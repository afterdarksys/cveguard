//! First-match rule engine. Shadow is the ceiling. Imports cannot enforce.
//!
//! Threats: an enforce decision on imported intel, on a toolchain descendant,
//! or after a seal mismatch would act on untrusted or self-referential input.
//! The budget fails closed. Isolate output is a plan string.
//!
//! Protection is by verified identity only: the event's `exe`, or an
//! ancestor's recorded exe, must be exactly a canonical path whose digest the
//! seal verified, with the same dev/ino now. `comm` and basenames never
//! protect, so `/tmp/.x/afterseal` or `comm=nocved` cannot exempt itself.
//! With no valid seal nothing is protected.

use cveguard_proto::isolate::{self, IsolateSpec};
use cveguard_proto::model::{
    Action, ActionBudget, DECISION_SCHEMA_VERSION, Decision, GuardEvent, Kind, Mode, Origin,
    Outcome, Reason, Rule, Severity, predicate_matches, subject_of, valid_time, validate_event,
};
use cveguard_proto::seal::{SealCheck, SealStatus, Sealed};

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
    sealed: Sealed,
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
        seal: SealCheck,
    ) -> Self {
        Self {
            lineage: Lineage::new(),
            containers: ContainerIndex::new(),
            rules,
            mode,
            isolate,
            budget,
            seal: seal.status,
            sealed: seal.sealed,
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

    /// Replaces the seal result after a periodic re-verification. A new
    /// mismatch makes `take_seal_alert` fire once and halts evaluation.
    pub fn update_seal(&mut self, check: SealCheck) {
        self.seal = check.status;
        self.sealed = if check.status == SealStatus::Valid {
            check.sealed
        } else {
            Sealed::default()
        };
    }

    /// A `rejected` / `schema` row for an input line that did not parse.
    #[must_use]
    pub fn reject_line(&self, observed_at_ms: i64) -> Option<Decision> {
        if self.halted {
            return None;
        }
        Some(bare(
            observed_at_ms,
            Action::Record,
            Outcome::Rejected,
            Reason::Schema,
            Severity::Low,
        ))
    }

    /// A `record` / `rejected` / `feed_gap` row: the tail lost an unread
    /// stretch of the feed. High, because a hidden process start is exactly
    /// what a lost stretch can contain.
    #[must_use]
    pub fn feed_gap(&self, observed_at_ms: i64) -> Option<Decision> {
        if self.halted {
            return None;
        }
        Some(bare(
            observed_at_ms,
            Action::Record,
            Outcome::Rejected,
            Reason::FeedGap,
            Severity::High,
        ))
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
        let mut alert = bare(
            0,
            Action::Alert,
            Outcome::Noted,
            Reason::SealMismatch,
            Severity::Critical,
        );
        alert.origin = Origin::Ring;
        alert.subject = Some("afterseal".to_owned());
        Some(alert)
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
        if is_protected(ev, full, &self.sealed) {
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
        if is_protected(ev, full, &self.sealed) {
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

/// Sealed identity only. `comm` is ignored; a basename is never enough.
fn is_protected(ev: &GuardEvent, ancestors: &[String], sealed: &Sealed) -> bool {
    ev.exe.as_deref().is_some_and(|exe| sealed.protects(exe))
        || ancestors.iter().any(|exe| sealed.protects(exe))
}

/// A row with no rule and no event. `epoch`, `seq`, and `prev` are set by
/// the ledger writer.
fn bare(
    observed_at_ms: i64,
    action: Action,
    outcome: Outcome,
    reason: Reason,
    severity: Severity,
) -> Decision {
    Decision {
        schema_version: DECISION_SCHEMA_VERSION,
        epoch: None,
        seq: 0,
        prev: String::new(),
        observed_at_ms,
        action,
        outcome,
        reason,
        origin: Origin::Nocved,
        severity,
        plan: None,
        pid: None,
        rule_id: None,
        source_rule_id: None,
        cve: None,
        subject: None,
        comm_invalid: false,
        args_truncated: false,
        ancestors: Vec::new(),
    }
}

fn schema_decision(ev: &GuardEvent) -> Decision {
    // A stamp darksignal would refuse is written as 0 (unset), so the
    // rejection itself still ships.
    let observed_at_ms = if valid_time(ev.observed_at_ms) {
        ev.observed_at_ms
    } else {
        0
    };
    let mut row = bare(
        observed_at_ms,
        Action::Record,
        Outcome::Rejected,
        Reason::Schema,
        Severity::Low,
    );
    row.origin = ev.origin;
    row.pid = ev.pid;
    row.subject = subject_of(ev);
    row.comm_invalid = ev.comm_invalid;
    row
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
        schema_version: DECISION_SCHEMA_VERSION,
        epoch: None,
        seq: 0,
        prev: String::new(),
        observed_at_ms: ev.observed_at_ms,
        action,
        outcome,
        reason,
        origin: ev.origin,
        severity: rule.severity.unwrap_or_default(),
        plan,
        pid: ev.pid,
        rule_id: Some(rule.id.clone()),
        source_rule_id: ev.source_rule_id.clone(),
        cve: rule.cve.clone(),
        subject: subject_of(ev),
        comm_invalid: ev.comm_invalid,
        args_truncated: ev.args_truncated,
        ancestors: ancestors.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::{Predicate, SCHEMA_VERSION, basename};
    use cveguard_proto::seal::{self, CENSUS};
    use std::os::unix::fs::PermissionsExt;

    /// Six real files, pinned and verified. Returns the canonical paths.
    fn sealed_toolchain() -> (tempfile::TempDir, SealCheck, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let mut paths = Vec::new();
        for name in CENSUS {
            let path = root.join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            paths.push(path);
        }
        let manifest = seal::pin(&paths).unwrap();
        let seal_path = root.join("seal.json");
        seal::write_manifest(&seal_path, &manifest).unwrap();
        let check = seal::check(&seal_path);
        assert_eq!(check.status, SealStatus::Valid);
        let text = paths
            .iter()
            .map(|p| p.to_str().unwrap().to_owned())
            .collect();
        (dir, check, text)
    }

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
            severity: None,
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
            comm_invalid: false,
            args: Vec::new(),
            args_truncated: false,
            remote: None,
            local: None,
            package: None,
            version: None,
            container_id: None,
            privileged: None,
            runtime: None,
            severity: None,
            ancestors: Vec::new(),
            source_rule_id: None,
        }
    }

    fn make(rules: Vec<Rule>, mode: Mode, seal: SealStatus, max_actions: u32) -> Engine {
        Engine::new(
            rules,
            mode,
            isolate_spec(),
            ActionBudget::new(60_000, max_actions).unwrap(),
            SealCheck::of(seal),
        )
    }

    #[test]
    fn out_of_range_stamp_is_a_schema_row_with_an_unset_time() {
        let mut engine = make(Vec::new(), Mode::Shadow, SealStatus::Valid, 10);
        for ms in [-1, cveguard_proto::model::MAX_TIME_MS + 1] {
            let mut ev = exec("/tmp/xmrig", Origin::Ring);
            ev.observed_at_ms = ms;
            let row = engine.evaluate(&ev).unwrap();
            assert_eq!(
                (row.outcome, row.reason),
                (Outcome::Rejected, Reason::Schema)
            );
            assert_eq!(row.observed_at_ms, 0, "{ms}");
        }
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

    fn sealed_engine(rules: Vec<Rule>, check: SealCheck) -> Engine {
        Engine::new(
            rules,
            Mode::Enforce,
            isolate_spec(),
            ActionBudget::new(60_000, 10).unwrap(),
            check,
        )
    }

    fn alert(id: &str, pred: Predicate) -> Vec<Rule> {
        vec![rule(id, true, Action::Alert, Mode::Enforce, pred)]
    }

    #[test]
    fn sealed_path_and_sealed_ancestor_are_suppressed() {
        let (_dir, check, paths) = sealed_toolchain();
        let nocved = paths[0].clone();
        let mut engine = sealed_engine(
            alert(
                "any-exe",
                Predicate::ExeBasename {
                    equals: "nocved".to_owned(),
                },
            ),
            check.clone(),
        );
        let decision = engine.evaluate(&exec(&nocved, Origin::Ring)).unwrap();
        assert_eq!(decision.outcome, Outcome::Suppressed);
        assert_eq!(decision.reason, Reason::Protected);
        assert!(decision.plan.is_none());

        let mut engine = sealed_engine(
            alert(
                "miner-exe",
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
            check,
        );
        engine.lineage.observe_start(1, 0, &nocved);
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
        assert!(decision.ancestors.iter().all(|exe| *exe != nocved));
    }

    #[test]
    fn probe_comm_named_like_toolchain_is_not_protected() {
        // exe=/tmp/xmrig name=nocved
        let (_dir, check, _paths) = sealed_toolchain();
        let mut engine = sealed_engine(
            alert(
                "miner-exe",
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
            check,
        );
        let mut ev = exec("/tmp/xmrig", Origin::Ring);
        ev.comm = Some("nocved".to_owned());
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.outcome, Outcome::Noted);
        assert_eq!(decision.reason, Reason::Matched);
    }

    #[test]
    fn probe_unsealed_ancestor_named_like_toolchain_is_not_protected() {
        // ancestor at /dev/shm/aftercve
        let (_dir, check, _paths) = sealed_toolchain();
        let mut engine = sealed_engine(
            alert(
                "miner-exe",
                Predicate::ExeBasename {
                    equals: "xmrig".to_owned(),
                },
            ),
            check,
        );
        engine.lineage.observe_start(30, 1, "/dev/shm/aftercve");
        let mut ev = exec("/tmp/xmrig", Origin::Ring);
        ev.pid = Some(31);
        ev.ppid = Some(30);
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.ancestors, vec!["/dev/shm/aftercve".to_owned()]);
        assert_eq!(decision.outcome, Outcome::Noted);
        assert_eq!(decision.reason, Reason::Matched);
    }

    #[test]
    fn probe_unsealed_exe_named_like_toolchain_is_not_protected() {
        // /tmp/.x/afterseal connecting to a miner port
        let (_dir, check, _paths) = sealed_toolchain();
        let mut engine = sealed_engine(
            vec![rule(
                "miner-port",
                true,
                Action::Isolate,
                Mode::Enforce,
                Predicate::RemoteEquals {
                    equals: "192.0.2.99:3333".to_owned(),
                },
            )],
            check,
        );
        let mut ev = exec("/tmp/.x/afterseal", Origin::Ring);
        ev.kind = Kind::Connect;
        ev.remote = Some("192.0.2.99:3333".to_owned());
        let decision = engine.evaluate(&ev).unwrap();
        assert_eq!(decision.outcome, Outcome::Planned);
        assert_eq!(decision.reason, Reason::Matched);
        assert!(decision.plan.is_some());
    }

    #[test]
    fn nothing_is_protected_without_a_valid_seal() {
        let (_dir, _check, paths) = sealed_toolchain();
        let mut engine = make(
            alert(
                "any-exe",
                Predicate::ExeBasename {
                    equals: "nocved".to_owned(),
                },
            ),
            Mode::Shadow,
            SealStatus::Missing,
            10,
        );
        let decision = engine.evaluate(&exec(&paths[0], Origin::Ring)).unwrap();
        assert_ne!(decision.reason, Reason::Protected);
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
            SealCheck::of(SealStatus::Missing),
        );
        let decision = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(decision.outcome, Outcome::Rejected);
        assert_eq!(decision.reason, Reason::PlanInvalid);
        assert!(decision.plan.is_none());
    }

    /// The e2e rule pack (rules.json from the live run) with a severity on
    /// the masquerade rule.
    const E2E_RULES: &[u8] = br#"[
      {"id":"masq-kcompactd","enabled":true,"action":"alert","mode":"enforce","severity":"high","when":[{"op":"exe_basename","equals":"kcompactd0"}]},
      {"id":"sleep-comm","enabled":true,"action":"alert","mode":"shadow","when":[{"op":"comm_equals","equals":"sleep"}]}
    ]"#;

    #[test]
    fn e2e_padded_miner_is_decided_with_severity_and_source_rule() {
        let rules = cveguard_proto::model::parse_rules(E2E_RULES).unwrap();
        let mut engine = make(rules, Mode::Shadow, SealStatus::Missing, 10);
        let burst = include_str!("../../cveguard-proto/testdata/e2e_miner_burst.jsonl");
        let decisions: Vec<Decision> = burst
            .lines()
            .filter_map(|line| cveguard_proto::intel::ingest_line(line).unwrap())
            .filter_map(|ev| engine.evaluate(&ev))
            .collect();
        // seq 534 (2 args) and seq 535 (70 args, masked to 65) both decided.
        assert_eq!(decisions.len(), 2);
        for d in &decisions {
            assert_eq!(d.rule_id.as_deref(), Some("masq-kcompactd"));
            assert_eq!(d.severity, Severity::High);
            assert_eq!(d.source_rule_id.as_deref(), Some("proc.masquerade"));
            assert_eq!(d.reason, Reason::ImportedIntel);
            assert_eq!(d.subject.as_deref(), Some("kcompactd0"));
        }
        assert_eq!(decisions[0].pid, Some(8126));
        assert!(!decisions[0].args_truncated);
        assert_eq!(decisions[1].pid, Some(8128));
        assert!(decisions[1].args_truncated);
        let row = serde_json::to_string(&decisions[1]).unwrap();
        assert!(row.contains(r#""args_truncated":true"#));
        assert!(!row.contains("\"10\""));
    }

    #[test]
    fn rule_without_severity_is_medium_and_bad_severity_is_refused() {
        let rules = vec![rule(
            "miner-exe",
            true,
            Action::Alert,
            Mode::Enforce,
            Predicate::ExeBasename {
                equals: "xmrig".to_owned(),
            },
        )];
        let mut engine = make(rules, Mode::Shadow, SealStatus::Missing, 10);
        let d = engine.evaluate(&exec("/tmp/xmrig", Origin::Ring)).unwrap();
        assert_eq!(d.severity, Severity::Medium);
        assert_eq!(d.source_rule_id, None);
        let bad = br#"[{"id":"a","enabled":true,"action":"alert","mode":"shadow","severity":"urgent","when":[{"op":"comm_equals","equals":"x"}]}]"#;
        assert!(cveguard_proto::model::parse_rules(bad).is_err());
        assert_eq!(engine.feed_gap(1).unwrap().severity, Severity::High);
        assert_eq!(engine.reject_line(1).unwrap().severity, Severity::Low);
    }
}
