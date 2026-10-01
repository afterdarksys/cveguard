//! First-match rule engine. Shadow is the ceiling. Imports cannot enforce.
//!
//! Threats: an enforce decision on imported intel, on a toolchain descendant,
//! or after a seal mismatch would act on untrusted or self-referential input.
//! The budget fails closed. Isolate output is a plan string.

use cveguard_proto::isolate::{self, IsolateSpec};
use cveguard_proto::model::{
    Action, ActionBudget, Decision, GuardEvent, Kind, Mode, Origin, Outcome, Reason, Rule,
    SCHEMA_VERSION, basename, is_toolchain_basename, predicate_matches, subject_of, validate_event,
};
use cveguard_proto::seal::SealStatus;

use crate::container::ContainerIndex;
use crate::lineage::Lineage;

const STORED_ANCESTORS: usize = 8;

pub struct Engine {
    lineage: Lineage,
    containers: ContainerIndex,
    rules: Vec<Rule>,
    mode: Mode,
    isolate: IsolateSpec,
    budget: ActionBudget,
    seal: SealStatus,
    seal_alerted: bool,
    halted: bool,
}

impl Engine {
    #[must_use]
    pub fn new(
        rules: Vec<Rule>,
        mode: Mode,
        isolate: IsolateSpec,
        budget: ActionBudget,
        seal: SealStatus,
    ) -> Self {
        Self {
            lineage: Lineage::new(),
            containers: ContainerIndex::new(),
            rules,
            mode,
            isolate,
            budget,
            seal,
            seal_alerted: false,
            halted: false,
        }
    }

    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    #[must_use]
    pub fn seal_status(&self) -> SealStatus {
        self.seal
    }

    #[must_use]
    pub fn halted(&self) -> bool {
        self.halted
    }

    #[must_use]
    pub fn isolate_plan_ok(&self) -> bool {
        isolate::plan(&self.isolate).is_ok()
    }

    /// One noted alert for a mismatched seal, then evaluation stops.
    pub fn take_seal_alert(&mut self) -> Option<Decision> {
        if self.seal != SealStatus::Mismatch || self.seal_alerted {
            return None;
        }
        self.seal_alerted = true;
        self.halted = true;
        Some(Decision {
            schema_version: SCHEMA_VERSION,
            observed_at_ms: 0,
            action: Action::Alert,
            outcome: Outcome::Noted,
            reason: Reason::SealMismatch,
            origin: Origin::Ring,
            plan: None,
            pid: None,
            rule_id: None,
            cve: None,
            subject: Some("afterseal".to_owned()),
            ancestors: Vec::new(),
        })
    }

    pub fn evaluate(&mut self, event: &GuardEvent) -> Option<Decision> {
        if self.halted {
            return None;
        }
        let mut ev = event.clone();
        self.containers.apply(&mut ev);
        if validate_event(&ev).is_err() {
            return Some(schema_decision(&ev));
        }
        self.observe(&ev);
        let full = match ev.pid {
            Some(pid) => self.lineage.ancestors(pid),
            None => Vec::new(),
        };
        let rule = self
            .rules
            .iter()
            .find(|rule| {
                rule.enabled
                    && rule
                        .when
                        .iter()
                        .all(|pred| predicate_matches(pred, &ev, &full))
            })?
            .clone();
        let stored: Vec<String> = full.iter().take(STORED_ANCESTORS).cloned().collect();
        Some(self.decide(&ev, &rule, &full, &stored))
    }

    fn observe(&mut self, ev: &GuardEvent) {
        match ev.kind {
            Kind::Exec => {
                if let Some(pid) = ev.pid {
                    let exe = ev
                        .exe
                        .clone()
                        .unwrap_or_else(|| ev.comm.clone().unwrap_or_default());
                    self.lineage.observe_start(pid, ev.ppid.unwrap_or(0), &exe);
                }
            }
            Kind::Exit => {
                if let Some(pid) = ev.pid {
                    self.lineage.observe_exit(pid);
                }
            }
            Kind::Connect | Kind::Listen | Kind::Package | Kind::Container | Kind::Finding => {}
        }
    }

    fn decide(
        &mut self,
        ev: &GuardEvent,
        rule: &Rule,
        full: &[String],
        stored: &[String],
    ) -> Decision {
        if rule.action == Action::Isolate {
            self.decide_isolate(ev, rule, full, stored)
        } else {
            self.decide_note(ev, rule, full, stored)
        }
    }

    fn decide_isolate(
        &mut self,
        ev: &GuardEvent,
        rule: &Rule,
        full: &[String],
        stored: &[String],
    ) -> Decision {
        let plan = match isolate::plan(&self.isolate) {
            Ok(plan) => plan,
            Err(_) => {
                return decided(
                    ev,
                    rule,
                    Action::Isolate,
                    Outcome::Rejected,
                    Reason::PlanInvalid,
                    None,
                    stored,
                );
            }
        };
        if is_protected(ev, full) {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Suppressed,
                Reason::Protected,
                None,
                stored,
            );
        }
        if self.mode != Mode::Enforce {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Shadow,
                Reason::PolicyShadow,
                Some(plan),
                stored,
            );
        }
        if rule.mode != Mode::Enforce {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Shadow,
                Reason::RuleShadow,
                Some(plan),
                stored,
            );
        }
        if ev.origin != Origin::Ring {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Shadow,
                Reason::ImportedIntel,
                Some(plan),
                stored,
            );
        }
        if self.seal == SealStatus::Missing {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Suppressed,
                Reason::SealMissing,
                None,
                stored,
            );
        }
        if self.seal == SealStatus::Mismatch {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Suppressed,
                Reason::SealMismatch,
                None,
                stored,
            );
        }
        if !self.budget.allow(ev.observed_at_ms) {
            return decided(
                ev,
                rule,
                Action::Isolate,
                Outcome::Suppressed,
                Reason::Budget,
                Some(plan),
                stored,
            );
        }
        decided(
            ev,
            rule,
            Action::Isolate,
            Outcome::Planned,
            Reason::Matched,
            Some(plan),
            stored,
        )
    }

    fn decide_note(
        &mut self,
        ev: &GuardEvent,
        rule: &Rule,
        full: &[String],
        stored: &[String],
    ) -> Decision {
        let action = rule.action;
        if is_protected(ev, full) {
            return decided(
                ev,
                rule,
                action,
                Outcome::Suppressed,
                Reason::Protected,
                None,
                stored,
            );
        }
        let enforceable = self.mode == Mode::Enforce
            && rule.mode == Mode::Enforce
            && ev.origin == Origin::Ring
            && self.seal == SealStatus::Valid;
        if !enforceable {
            let reason = if ev.origin != Origin::Ring {
                Reason::ImportedIntel
            } else if self.seal == SealStatus::Mismatch {
                Reason::SealMismatch
            } else if self.seal == SealStatus::Missing {
                Reason::SealMissing
            } else if self.mode != Mode::Enforce {
                Reason::PolicyShadow
            } else {
                Reason::RuleShadow
            };
            return decided(ev, rule, action, Outcome::Shadow, reason, None, stored);
        }
        if !self.budget.allow(ev.observed_at_ms) {
            return decided(
                ev,
                rule,
                action,
                Outcome::Suppressed,
                Reason::Budget,
                None,
                stored,
            );
        }
        decided(
            ev,
            rule,
            action,
            Outcome::Noted,
            Reason::Matched,
            None,
            stored,
        )
    }
}

fn is_protected(ev: &GuardEvent, ancestors: &[String]) -> bool {
    if ev
        .exe
        .as_deref()
        .is_some_and(|exe| is_toolchain_basename(basename(exe)))
    {
        return true;
    }
    if ev.comm.as_deref().is_some_and(is_toolchain_basename) {
        return true;
    }
    ancestors
        .iter()
        .any(|exe| is_toolchain_basename(basename(exe)))
}

fn schema_decision(ev: &GuardEvent) -> Decision {
    Decision {
        schema_version: SCHEMA_VERSION,
        observed_at_ms: ev.observed_at_ms,
        action: Action::Record,
        outcome: Outcome::Rejected,
        reason: Reason::Schema,
        origin: ev.origin,
        plan: None,
        pid: ev.pid,
        rule_id: None,
        cve: None,
        subject: subject_of(ev),
        ancestors: Vec::new(),
    }
}

fn decided(
    ev: &GuardEvent,
    rule: &Rule,
    action: Action,
    outcome: Outcome,
    reason: Reason,
    plan: Option<String>,
    ancestors: &[String],
) -> Decision {
    Decision {
        schema_version: SCHEMA_VERSION,
        observed_at_ms: ev.observed_at_ms,
        action,
        outcome,
        reason,
        origin: ev.origin,
        plan,
        pid: ev.pid,
        rule_id: Some(rule.id.clone()),
        cve: rule.cve.clone(),
        subject: subject_of(ev),
        ancestors: ancestors.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::Predicate;

    fn isolate_spec() -> IsolateSpec {
        IsolateSpec {
            local_cidrs: vec!["10.1.2.0/24".to_owned()],
            whitelist: vec!["192.0.2.20/32".to_owned()],
            management_ips: vec!["192.0.2.10".to_owned()],
            store_ips: vec!["198.51.100.8".to_owned()],
            keep_store: true,
            deadman_secs: 120,
        }
    }

    fn rule(id: &str, enabled: bool, action: Action, mode: Mode, pred: Predicate) -> Rule {
        Rule {
            id: id.to_owned(),
            enabled,
            action,
            mode,
            cve: None,
            when: vec![pred],
        }
    }

    fn exec(exe: &str, origin: Origin) -> GuardEvent {
        GuardEvent {
            schema_version: SCHEMA_VERSION,
            kind: Kind::Exec,
            origin,
            observed_at_ms: 5_000,
            pid: Some(40),
            ppid: Some(1),
            uid: Some(0),
            exe: Some(exe.to_owned()),
            comm: Some(basename(exe).to_owned()),
            args: Vec::new(),
            remote: None,
            package: None,
            version: None,
            container_id: None,
            privileged: None,
            runtime: None,
            severity: None,
            ancestors: Vec::new(),
        }
    }

    fn make(rules: Vec<Rule>, mode: Mode, seal: SealStatus, max_actions: u32) -> Engine {
        Engine::new(
            rules,
            mode,
            isolate_spec(),
            ActionBudget::new(60_000, max_actions).unwrap(),
            seal,
        )
    }

    #[test]
    fn shadow_keeps_enforce_rule_in_shadow() {
        let rules = vec![rule(
            "miner-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Shadow, SealStatus::Valid, 10);
        let decision = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(decision.outcome, Outcome::Shadow);
        assert_eq!(decision.reason, Reason::PolicyShadow);
        assert!(engine.budget.is_empty());
    }

    #[test]
    fn first_match_wins_and_disabled_rule_is_skipped() {
        let rules = vec![
            rule(
                "off",
                false,
                Action::Isolate,
                Mode::Enforce,
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
            rule(
                "miner-exe",
                true,
                Action::Alert,
                Mode::Enforce,
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
            rule(
                "isolate-miner",
                true,
                Action::Isolate,
                Mode::Enforce,
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
        ];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 10);
        let decision = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(decision.rule_id.as_deref(), Some("miner-exe"));
        assert_eq!(decision.action, Action::Alert);
        assert_eq!(decision.outcome, Outcome::Noted);
        assert!(engine.evaluate(&exec("/bin/true", Origin::Ring)).is_none());
    }

    #[test]
    fn imported_finding_cannot_enforce() {
        let rules = vec![rule(
            "finding-alert",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::KindEquals {
                equals: Kind::Finding,
            },
        )];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 10);
        let mut ev = exec("/tmp/xmrig", Origin::Aftercve);
        ev.kind = Kind::Finding;
        ev.exe = None;
        ev.comm = None;
        ev.pid = None;
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.outcome, Outcome::Shadow);
        assert_eq!(decision.reason, Reason::ImportedIntel);
        assert_ne!(decision.origin, Origin::Ring);
        assert!(engine.budget.is_empty());
    }

    #[test]
    fn package_version_is_exact_and_stores_cve() {
        let mut rule = rule(
            "example-miner-cve",
            true,
            Action::Alert,
            Mode::Shadow,
            Predicate::PackageExact {
                name: "example-miner".to_owned(),
                version: "1.2.3".to_owned(),
            },
        );
        rule.cve = Some("CVE-2099-0001".to_owned());
        let mut engine = make(vec![rule], Mode::Shadow, SealStatus::Missing, 10);
        let mut hit = exec("/usr/bin/dpkg", Origin::Nocved);
        hit.kind = Kind::Package;
        hit.package = Some("example-miner".to_owned());
        hit.version = Some("1.2.3".to_owned());
        let decision = engine.evaluate(&hit).unwrap();
        assert_eq!(decision.cve.as_deref(), Some("CVE-2099-0001"));
        hit.version = Some("1.2.3-1".to_owned());
        assert!(engine.evaluate(&hit).is_none());
    }

    #[test]
    fn secret_arg_is_schema_and_not_stored() {
        let rules = vec![rule(
            "miner-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 10);
        let mut ev = exec("/tmp/xmrig", Origin::Ring);
        ev.args = vec!["--password=x".to_owned()];
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.outcome, Outcome::Rejected);
        assert_eq!(decision.reason, Reason::Schema);
        assert!(decision.rule_id.is_none());
        let text = serde_json::to_string(&decision).unwrap();
        assert!(!text.contains("password"));
    }

    #[test]
    fn protected_toolchain_and_deep_descendant_are_suppressed() {
        let rules = vec![rule(
            "any-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "nocved".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 10);
        let decision = engine
            .evaluate(&exec("/usr/sbin/nocved", Origin::Ring))
            .unwrap();
        assert_eq!(decision.outcome, Outcome::Suppressed);
        assert_eq!(decision.reason, Reason::Protected);
        assert!(decision.plan.is_none());

        let rules = vec![rule(
            "miner-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 10);
        engine.lineage.observe_start(1, 0, "/usr/sbin/nocved");
        for pid in 2..10 {
            engine
                .lineage
                .observe_start(pid, pid - 1, &format!("/bin/p{pid}"));
        }
        let mut ev = exec("/tmp/xmrig", Origin::Ring);
        ev.pid = Some(10);
        ev.ppid = Some(9);
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.outcome, Outcome::Suppressed);
        assert_eq!(decision.reason, Reason::Protected);
        assert_eq!(decision.ancestors.len(), STORED_ANCESTORS);
        assert!(
            decision
                .ancestors
                .iter()
                .all(|exe| !exe.ends_with("nocved"))
        );
    }

    #[test]
    fn budget_trips_and_shadow_does_not_consume_it() {
        let rules = vec![rule(
            "miner-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Enforce, SealStatus::Valid, 1);
        let first = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(first.outcome, Outcome::Noted);
        let second = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(second.outcome, Outcome::Suppressed);
        assert_eq!(second.reason, Reason::Budget);
        assert_eq!(engine.budget.len(), 1);
    }

    #[test]
    fn empty_management_is_plan_invalid() {
        let rules = vec![rule(
            "isolate-miner",
            true,
            Action::Isolate,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut spec = isolate_spec();
        spec.management_ips.clear();
        let mut engine = Engine::new(
            rules,
            Mode::Shadow,
            spec,
            ActionBudget::new(60_000, 10).unwrap(),
            SealStatus::Missing,
        );
        let decision = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(decision.outcome, Outcome::Rejected);
        assert_eq!(decision.reason, Reason::PlanInvalid);
        assert!(decision.plan.is_none());
    }
}
