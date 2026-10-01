//! Decision schema, rule pack, and action budget.
//!
//! Threats: an empty predicate would match every event. A rule cannot cite a
//! malformed CVE. Imported events are marked so the engine can refuse to
//! enforce them. Secret-looking arguments are dropped before anything is
//! stored. The budget fails closed when the clock jumps backwards.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, invalid, schema};
use crate::fs::{self, FilePolicy};

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_INTEL_BYTES: usize = 256 * 1024;
pub const MAX_RULES: usize = 256;
pub const MAX_EVENTS_PER_PASS: usize = 1000;
pub const MAX_STRING: usize = 512;
pub const MAX_ARGS: usize = 64;
pub const MAX_LEDGER_BYTES: usize = 1024 * 1024;
pub const MAX_SEAL_ENTRIES: usize = 64;
pub const MAX_SEAL_FILE: usize = 32 * 1024 * 1024;
pub const MAX_LINE: usize = 8192;
pub const MAX_RING_PAYLOAD: usize = 1024;
pub const RULES_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Record,
    Alert,
    Isolate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Shadow,
    Noted,
    Planned,
    Suppressed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Ring,
    Nocved,
    Aftercve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Matched,
    PolicyShadow,
    RuleShadow,
    ImportedIntel,
    SealMissing,
    SealMismatch,
    Budget,
    Protected,
    PlanInvalid,
    Schema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Exec,
    Exit,
    Connect,
    Listen,
    Package,
    Container,
    Finding,
}

fn default_origin() -> Origin {
    Origin::Nocved
}

fn default_schema() -> u16 {
    SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvent {
    #[serde(default = "default_schema")]
    pub schema_version: u16,
    pub kind: Kind,
    #[serde(default = "default_origin")]
    pub origin: Origin,
    #[serde(default)]
    pub observed_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub schema_version: u16,
    pub observed_at_ms: i64,
    pub action: Action,
    pub outcome: Outcome,
    pub reason: Reason,
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    ExeBasename { equals: String },
    CommEquals { equals: String },
    PackageExact { name: String, version: String },
    RemoteEquals { equals: String },
    KindEquals { equals: Kind },
    Privileged { equals: bool },
    UidEquals { equals: u32 },
    AncestorExe { equals: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub action: Action,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    pub when: Vec<Predicate>,
}

#[derive(Debug, Clone)]
pub struct ActionBudget {
    window_ms: u64,
    max_actions: usize,
    hits: Vec<i64>,
}

impl ActionBudget {
    pub fn new(window_ms: u64, max_actions: u32) -> Result<Self, Error> {
        if !(1..=86_400_000).contains(&window_ms) || !(1..=1000).contains(&max_actions) {
            return Err(invalid("budget rejected"));
        }
        Ok(Self {
            window_ms,
            max_actions: usize::try_from(max_actions).map_err(|_| invalid("budget rejected"))?,
            hits: Vec::new(),
        })
    }

    /// Records a hit only when the window is under the cap.
    /// A backwards clock keeps existing hits, so the cap stays closed.
    pub fn allow(&mut self, now_ms: i64) -> bool {
        let window = i64::try_from(self.window_ms).unwrap_or(i64::MAX);
        let cutoff = now_ms.saturating_sub(window);
        self.hits.retain(|t| *t > cutoff);
        if self.hits.len() >= self.max_actions {
            return false;
        }
        self.hits.push(now_ms);
        true
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

#[must_use]
pub fn is_toolchain_basename(name: &str) -> bool {
    matches!(
        name,
        "nocved" | "nocve-store" | "aftercve" | "afterguard" | "afteralert" | "afterseal"
    )
}

#[must_use]
pub fn valid_subject(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[must_use]
pub fn valid_cve(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, num)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=7).contains(&num.len())
        && num.bytes().all(|b| b.is_ascii_digit())
}

#[must_use]
pub fn secret_arg(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token=")
        || lower.starts_with("--token")
}

pub fn filter_args(args: Vec<String>) -> Result<Vec<String>, Error> {
    let kept: Vec<String> = args.into_iter().filter(|a| !secret_arg(a)).collect();
    if kept.len() > MAX_ARGS {
        return Err(schema("too many args"));
    }
    for arg in &kept {
        if arg.len() > MAX_STRING || arg.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
            return Err(schema("arg too long"));
        }
    }
    Ok(kept)
}

pub fn check_text(s: &str) -> Result<(), Error> {
    if s.len() > MAX_STRING || s.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return Err(schema("string rejected"));
    }
    Ok(())
}

pub fn validate_event(ev: &GuardEvent) -> Result<(), Error> {
    if ev.schema_version != SCHEMA_VERSION {
        return Err(schema("schema rejected"));
    }
    if let Some(s) = &ev.exe {
        check_text(s)?;
    }
    if let Some(s) = &ev.comm {
        check_text(s)?;
        if !valid_subject(s) {
            return Err(schema("subject rejected"));
        }
    }
    for s in [
        &ev.remote,
        &ev.package,
        &ev.version,
        &ev.container_id,
        &ev.runtime,
        &ev.severity,
    ]
    .into_iter()
    .flatten()
    {
        check_text(s)?;
    }
    if ev.args.len() > MAX_ARGS {
        return Err(schema("too many args"));
    }
    for arg in &ev.args {
        if secret_arg(arg) {
            return Err(schema("secret arg"));
        }
        check_text(arg)?;
    }
    if ev.kind == Kind::Connect {
        match &ev.remote {
            Some(remote) => check_remote(remote)?,
            None => return Err(schema("remote rejected")),
        }
    }
    Ok(())
}

pub fn check_remote(remote: &str) -> Result<(), Error> {
    let (ip, port) = match remote.rsplit_once(':') {
        Some((ip, port)) => {
            if port.is_empty()
                || (port.len() > 1 && port.starts_with('0'))
                || !port.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(schema("remote rejected"));
            }
            let value: u32 = port.parse().map_err(|_| schema("remote rejected"))?;
            if value == 0 || value > 65535 {
                return Err(schema("remote rejected"));
            }
            (ip, Some(value))
        }
        None => (remote, None),
    };
    if ip.contains(':') {
        return Err(schema("remote rejected"));
    }
    crate::cidr::parse_ipv4(ip).map_err(|_| schema("remote rejected"))?;
    let _ = port;
    Ok(())
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>, Error> {
    let bytes = fs::read_trusted(path, RULES_MAX_BYTES, FilePolicy::Config)?;
    parse_rules(&bytes)
}

pub fn parse_rules(bytes: &[u8]) -> Result<Vec<Rule>, Error> {
    if bytes.len() > RULES_MAX_BYTES {
        return Err(invalid("rules too large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| schema("utf-8 rejected"))?;
    let rules: Vec<Rule> = serde_json::from_str(text).map_err(|_| schema("json rejected"))?;
    if rules.len() > MAX_RULES {
        return Err(invalid("too many rules"));
    }
    let mut seen = HashSet::new();
    for rule in &rules {
        validate_rule(rule)?;
        if !seen.insert(rule.id.clone()) {
            return Err(invalid("duplicate rule id"));
        }
    }
    Ok(rules)
}

fn validate_rule(rule: &Rule) -> Result<(), Error> {
    if !valid_subject(&rule.id) {
        return Err(invalid("rule id rejected"));
    }
    if rule.when.is_empty() {
        return Err(invalid("empty predicate"));
    }
    if let Some(cve) = &rule.cve
        && !valid_cve(cve)
    {
        return Err(invalid("cve rejected"));
    }
    for pred in &rule.when {
        match pred {
            Predicate::ExeBasename { equals }
            | Predicate::CommEquals { equals }
            | Predicate::RemoteEquals { equals }
            | Predicate::AncestorExe { equals } => {
                if equals.is_empty() || equals.len() > MAX_STRING {
                    return Err(invalid("predicate rejected"));
                }
            }
            Predicate::PackageExact { name, version } => {
                if name.is_empty()
                    || version.is_empty()
                    || name.len() > MAX_STRING
                    || version.len() > MAX_STRING
                {
                    return Err(invalid("predicate rejected"));
                }
            }
            Predicate::KindEquals { .. }
            | Predicate::Privileged { .. }
            | Predicate::UidEquals { .. } => {}
        }
    }
    Ok(())
}

pub fn predicate_matches(pred: &Predicate, ev: &GuardEvent, ancestors: &[String]) -> bool {
    match pred {
        Predicate::ExeBasename { equals } => match &ev.exe {
            Some(exe) => basename(exe) == equals,
            None => ev.comm.as_deref() == Some(equals.as_str()),
        },
        Predicate::CommEquals { equals } => ev.comm.as_deref() == Some(equals.as_str()),
        Predicate::PackageExact { name, version } => {
            ev.package.as_deref() == Some(name.as_str())
                && ev.version.as_deref() == Some(version.as_str())
        }
        Predicate::RemoteEquals { equals } => ev.remote.as_deref() == Some(equals.as_str()),
        Predicate::KindEquals { equals } => ev.kind == *equals,
        Predicate::Privileged { equals } => ev.privileged == Some(*equals),
        Predicate::UidEquals { equals } => ev.uid == Some(*equals),
        Predicate::AncestorExe { equals } => ancestors
            .iter()
            .any(|exe| basename(exe) == equals || exe == equals),
    }
}

#[must_use]
pub fn subject_of(ev: &GuardEvent) -> Option<String> {
    if let Some(exe) = &ev.exe {
        let base = basename(exe);
        if valid_subject(base) {
            return Some(base.to_owned());
        }
    }
    if let Some(comm) = &ev.comm
        && valid_subject(comm)
    {
        return Some(comm.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_keeps_hits_when_clock_goes_backwards() {
        let mut budget = ActionBudget::new(60_000, 1).unwrap();
        assert!(budget.is_empty());
        assert!(budget.allow(1_000));
        assert!(!budget.is_empty());
        assert!(!budget.allow(1_000));
        assert!(!budget.allow(500));
        assert_eq!(budget.len(), 1);
        assert!(budget.allow(1_000 + 60_000));
    }

    #[test]
    fn rules_reject_duplicates_empty_predicates_bad_cve_and_count() {
        let dup = br#"[{"id":"a","enabled":true,"action":"alert","mode":"shadow","when":[{"op":"comm_equals","equals":"x"}]},{"id":"a","enabled":true,"action":"alert","mode":"shadow","when":[{"op":"comm_equals","equals":"y"}]}]"#;
        assert!(
            parse_rules(dup)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        let empty = br#"[{"id":"a","enabled":true,"action":"alert","mode":"shadow","when":[]}]"#;
        assert!(
            parse_rules(empty)
                .unwrap_err()
                .to_string()
                .contains("empty")
        );
        let cve = br#"[{"id":"a","enabled":true,"action":"alert","mode":"enforce","cve":"cve-2099-0001","when":[{"op":"comm_equals","equals":"x"}]}]"#;
        assert!(parse_rules(cve).unwrap_err().to_string().contains("cve"));
        let short = br#"[{"id":"a","enabled":true,"action":"alert","mode":"enforce","cve":"CVE-2099-001","when":[{"op":"comm_equals","equals":"x"}]}]"#;
        assert!(parse_rules(short).is_err());
        assert!(valid_cve("CVE-2099-0001"));
        let mut rules = Vec::new();
        for i in 0..257 {
            rules.push(format!(
                r#"{{"id":"r{i}","enabled":true,"action":"record","mode":"shadow","when":[{{"op":"comm_equals","equals":"z"}}]}}"#
            ));
        }
        let blob = format!("[{}]", rules.join(","));
        assert!(
            parse_rules(blob.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("too many")
        );
        let huge = vec![b' '; RULES_MAX_BYTES + 1];
        assert!(parse_rules(&huge).is_err());
    }

    #[test]
    fn strips_secret_args_and_matches_basename_only_when_exe_present() {
        let kept = filter_args(vec![
            "--password=x".into(),
            "--donate-level=1".into(),
            "token=abc".into(),
            "--token".into(),
        ])
        .unwrap();
        assert_eq!(kept, vec!["--donate-level=1".to_owned()]);
        let ev = GuardEvent {
            schema_version: 1,
            kind: Kind::Exec,
            origin: Origin::Ring,
            observed_at_ms: 1,
            pid: None,
            ppid: None,
            uid: None,
            exe: Some("/usr/bin/other".into()),
            comm: Some("xmrig".into()),
            args: Vec::new(),
            remote: None,
            package: None,
            version: None,
            container_id: None,
            privileged: None,
            runtime: None,
            severity: None,
            ancestors: Vec::new(),
        };
        let pred = Predicate::ExeBasename {
            equals: "xmrig".into(),
        };
        assert!(!predicate_matches(&pred, &ev, &[]));
        let pred = Predicate::PackageExact {
            name: "example-miner".into(),
            version: "1.2.3".into(),
        };
        let mut pkg = ev.clone();
        pkg.package = Some("example-miner".into());
        pkg.version = Some("1.2.3-1".into());
        assert!(!predicate_matches(&pred, &pkg, &[]));
        pkg.version = Some("1.2.3".into());
        assert!(predicate_matches(&pred, &pkg, &[]));
    }
}
