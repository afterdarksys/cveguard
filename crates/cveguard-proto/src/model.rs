//! Decision schema, rule pack, and action budget.
//!
//! Threats: an empty predicate would match every event. A rule cannot cite a
//! malformed CVE. Imported events are marked so the engine can refuse to
//! enforce them. Secret-looking arguments are dropped before anything is
//! stored. The budget fails closed when the clock jumps backwards. Argv shape
//! never rejects an event: an attacker who pads argv past the cap, makes one
//! argument huge, or embeds a newline would otherwise skip evaluation, so
//! argv is cut to `MAX_ARGS` entries of `MAX_STRING` bytes, control
//! characters are escaped, and `args_truncated` records the cut.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, invalid, schema};
use crate::fs::{self, FilePolicy};

/// Event, finding, and seal manifest schema.
pub const SCHEMA_VERSION: u16 = 1;
/// Ledger row schema. Version 2 adds the `seq` / `prev` hash chain. Version 3
/// adds `epoch`, `severity`, `source_rule_id`, and `args_truncated`.
pub const DECISION_SCHEMA_VERSION: u16 = 3;
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
    /// The tail lost an unread stretch of the feed (a rotation it could not
    /// follow, or a shrink).
    FeedGap,
}

/// Decision severity, in the nocved vocabulary darksignal reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
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
    /// The source carried a comm that failed `valid_subject`; it was dropped.
    #[serde(default, skip_serializing_if = "is_false")]
    pub comm_invalid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// argv was cut to `MAX_ARGS` entries or an entry to `MAX_STRING` bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub args_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Local `ip:port` of a socket (`[v6]:port` for IPv6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
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
    /// The producer's own rule that raised this event: the highest-severity
    /// nocved signal rule, or the aftercve finding `rule_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rule_id: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One ledger row. `epoch`, `seq` and `prev` are filled by the ledger writer
/// under its lock: `seq` starts at 1 and `prev` is the SHA-256 hex of the
/// previous row's bytes (without the newline), or `chain::GENESIS` for the
/// first row. `epoch` names the chain and stays the same across rotation.
/// The JSON shape is the darksignal contract in DESIGN.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub schema_version: u16,
    /// Absent on schema 2 rows; never invented when an old row is re-read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev: String,
    pub observed_at_ms: i64,
    pub action: Action,
    pub outcome: Outcome,
    pub reason: Reason,
    pub origin: Origin,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub comm_invalid: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub args_truncated: bool,
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
    /// Severity copied to the decision. Absent means medium.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
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

/// The one comm normalizer for every source (nocved, aftercve, ring, guard
/// JSON). Absent, null, or empty is no comm. A comm that is not a string or
/// is not a `valid_subject` is dropped and reported as invalid; the caller
/// keeps evaluating the event on `exe`. Comm text is never trusted for
/// identity, so dropping it cannot widen what is protected.
#[must_use]
pub fn normalize_comm(raw: Option<&serde_json::Value>) -> (Option<String>, bool) {
    match raw {
        None | Some(serde_json::Value::Null) => (None, false),
        Some(serde_json::Value::String(s)) if s.is_empty() => (None, false),
        Some(serde_json::Value::String(s)) if valid_subject(s) => (Some(s.clone()), false),
        Some(_) => (None, true),
    }
}

/// Applies `normalize_comm` to an event that was deserialized directly.
pub fn normalize_event_comm(ev: &mut GuardEvent) {
    if ev
        .comm
        .as_deref()
        .is_some_and(|c| !c.is_empty() && !valid_subject(c))
    {
        ev.comm = None;
        ev.comm_invalid = true;
    } else if ev.comm.as_deref() == Some("") {
        ev.comm = None;
    }
}

/// darksignal's `frame::MAX_TIME_MS` (2100-01-01T00:00:00Z).
pub const MAX_TIME_MS: i64 = 4_102_444_800_000;

/// darksignal's time range (`frame::valid_time`): 0 (unset) to
/// `MAX_TIME_MS`. darksignal refuses a row whose `observed_at_ms` is outside
/// it, so an event with such a stamp is rejected at ingest instead.
#[must_use]
pub fn valid_time(ms: i64) -> bool {
    (0..=MAX_TIME_MS).contains(&ms)
}

/// A producer rule id: 1..=128 bytes of `[A-Za-z0-9._-]` (darksignal's
/// rule grammar).
#[must_use]
pub fn valid_rule_token(s: &str) -> bool {
    (1..=128).contains(&s.len())
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

/// Drops secret-looking args, keeps the first `MAX_ARGS`, cuts each to
/// `MAX_STRING` bytes at a char boundary, and escapes control characters.
/// Never fails: argv shape must not let an event skip evaluation. The flag is
/// true when an entry or a tail of entries was cut.
#[must_use]
pub fn filter_args(args: Vec<String>) -> (Vec<String>, bool) {
    let mut truncated = false;
    let mut kept = Vec::new();
    for arg in args.into_iter().filter(|a| !secret_arg(a)) {
        if kept.len() == MAX_ARGS {
            truncated = true;
            break;
        }
        let (clean, cut) = clean_arg(&arg);
        truncated |= cut;
        kept.push(clean);
    }
    (kept, truncated)
}

/// Escapes `\n`, `\r`, `\t` and other control characters (as `\u{..}`) and
/// stops before `MAX_STRING` bytes, never splitting an escape or a char.
fn clean_arg(arg: &str) -> (String, bool) {
    let mut out = String::with_capacity(arg.len().min(MAX_STRING));
    let mut buf = [0u8; 4];
    for ch in arg.chars() {
        let escaped;
        let piece: &str = match ch {
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            c if c.is_control() => {
                escaped = format!("\\u{{{:x}}}", u32::from(c));
                &escaped
            }
            c => c.encode_utf8(&mut buf),
        };
        if out.len().saturating_add(piece.len()) > MAX_STRING {
            return (out, true);
        }
        out.push_str(piece);
    }
    (out, false)
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
    if !valid_time(ev.observed_at_ms) {
        return Err(schema("time rejected"));
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
    } else if let Some(remote) = &ev.remote {
        parse_endpoint(remote)?;
    }
    if let Some(local) = &ev.local {
        parse_endpoint(local)?;
    }
    if let Some(rule) = &ev.source_rule_id
        && !valid_rule_token(rule)
    {
        return Err(schema("source rule rejected"));
    }
    Ok(())
}

/// A connect peer: `ip`, `ip:port`, `[v6]`, or `[v6]:port`, port 1..=65535.
pub fn check_remote(remote: &str) -> Result<(), Error> {
    match parse_endpoint(remote)? {
        (_, Some(0)) => Err(schema("remote rejected")),
        _ => Ok(()),
    }
}

/// Parses `ip`, `ip:port`, `[v6]`, `[v6]:port`, or a bare IPv6 address.
/// IPv4 uses the strict dotted quad (no leading zeros); IPv6 uses `std::net`.
/// A port is decimal with no leading zero, 0..=65535.
pub fn parse_endpoint(s: &str) -> Result<(IpAddr, Option<u16>), Error> {
    let bad = || schema("remote rejected");
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, tail) = rest.split_once(']').ok_or_else(bad)?;
        let ip: Ipv6Addr = ip.parse().map_err(|_| bad())?;
        let port = match tail {
            "" => None,
            _ => Some(parse_port(tail.strip_prefix(':').ok_or_else(bad)?)?),
        };
        return Ok((IpAddr::V6(ip), port));
    }
    if let Ok(ip) = s.parse::<Ipv6Addr>() {
        return Ok((IpAddr::V6(ip), None));
    }
    let (ip, port) = match s.rsplit_once(':') {
        Some((ip, port)) => (ip, Some(parse_port(port)?)),
        None => (s, None),
    };
    let octets = crate::cidr::parse_ipv4(ip).map_err(|_| bad())?;
    Ok((IpAddr::V4(Ipv4Addr::from(octets)), port))
}

pub fn parse_port(port: &str) -> Result<u16, Error> {
    if port.is_empty()
        || (port.len() > 1 && port.starts_with('0'))
        || !port.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(schema("remote rejected"));
    }
    port.parse().map_err(|_| schema("remote rejected"))
}

/// Canonical text for an endpoint: `a.b.c.d[:port]` or `[v6][:port]`.
#[must_use]
pub fn format_endpoint(ip: IpAddr, port: Option<u16>) -> String {
    match (ip, port) {
        (IpAddr::V4(v4), Some(port)) => format!("{v4}:{port}"),
        (IpAddr::V4(v4), None) => v4.to_string(),
        (IpAddr::V6(v6), Some(port)) => format!("[{v6}]:{port}"),
        (IpAddr::V6(v6), None) => format!("[{v6}]"),
    }
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
        let (kept, truncated) = filter_args(vec![
            "--password=x".into(),
            "--donate-level=1".into(),
            "token=abc".into(),
            "--token".into(),
        ]);
        assert_eq!(kept, vec!["--donate-level=1".to_owned()]);
        assert!(!truncated);
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

    #[test]
    fn argv_shape_never_rejects_and_marks_truncation() {
        let many: Vec<String> = (0..70).map(|i| format!("a{i}")).collect();
        let (kept, truncated) = filter_args(many);
        assert_eq!(kept.len(), MAX_ARGS);
        assert_eq!(kept[63], "a63");
        assert!(truncated);

        // 'é' is two bytes; the cut must land on a char boundary.
        let long = format!("x{}", "é".repeat(400));
        let (kept, truncated) = filter_args(vec![long]);
        assert!(truncated);
        assert!(kept[0].len() <= MAX_STRING);
        assert!(kept[0].len() >= MAX_STRING - 1);
        assert!(check_text(&kept[0]).is_ok());

        let (kept, truncated) =
            filter_args(vec!["echo a\nrm -rf /\r\tdone\u{0}\u{1b}[31m".to_owned()]);
        assert!(!truncated);
        assert_eq!(kept[0], "echo a\\nrm -rf /\\r\\tdone\\u{0}\\u{1b}[31m");
        assert!(check_text(&kept[0]).is_ok());

        // An escape that would cross the cap is dropped whole, not split.
        let edge = format!("{}\n", "b".repeat(MAX_STRING - 1));
        let (kept, truncated) = filter_args(vec![edge]);
        assert!(truncated);
        assert_eq!(kept[0], "b".repeat(MAX_STRING - 1));
    }

    #[test]
    fn endpoints_accept_ipv6_and_reject_junk() {
        assert!(check_remote("203.0.113.9:443").is_ok());
        assert!(check_remote("[2001:db8::1]:443").is_ok());
        assert!(check_remote("2001:db8::1").is_ok());
        assert!(check_remote("203.0.113.9:0").is_err());
        assert!(check_remote("[2001:db8::1]:0").is_err());
        assert!(check_remote("203.0.113.9:08").is_err());
        assert!(check_remote("203.0.113.9:65536").is_err());
        assert!(check_remote("[2001:db8::1]443").is_err());
        assert!(check_remote("010.0.0.1:80").is_err());
        assert!(check_remote("example.com:80").is_err());
        assert_eq!(
            parse_endpoint("[::1]:9998").unwrap(),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), Some(9998))
        );
    }
}
