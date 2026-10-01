//! One-way adapters from nocved events and aftercve findings.
//!
//! Threats: finding titles, explanations, and recommendations can carry
//! secrets, so they are not copied. Import never produces a ring origin, so
//! a file cannot promote itself into an enforce decision. Unknown nocved
//! kinds are skipped. A known kind with bad fields fails closed. A comm that
//! is not a valid subject is dropped and flagged (`comm_invalid`); the event
//! is still evaluated on `exe`, and comm is never used for identity. argv
//! shape (count, length, newlines) never rejects a line: `filter_args` cuts
//! and escapes it and flags `args_truncated`, so padding argv cannot hide a
//! process start. A listener's unspecified remote with port 0 is no remote;
//! IPv6 is parsed with `std::net`. Only the producer's rule token is kept
//! (`source_rule_id`); signal summaries are not read.
//!
//! nocved spool envelopes (`v`, `host`, `epoch`, `seq`, `prev`, `payload`,
//! `mac`) are unwrapped and the string `payload` is parsed as the event.
//! Not covered: the envelope MAC and the nocved hash chain are NOT verified
//! here (cveguard holds no nocved key). An envelope is only shape-checked, so
//! a local writer of the feed can forge events. Imports stay shadow.

use serde_json::Value;

use crate::error::{Error, schema};
use std::net::IpAddr;

use crate::model::{
    GuardEvent, Kind, MAX_LINE, Origin, SCHEMA_VERSION, Severity, check_remote, check_text,
    filter_args, format_endpoint, normalize_comm, normalize_event_comm, parse_endpoint, parse_port,
    valid_rule_token,
};

/// What one line produced. `envelope` is the nocved `(epoch, seq)` when the
/// line was a spool envelope, so a tail can skip a replayed envelope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ingested {
    pub event: Option<GuardEvent>,
    pub envelope: Option<(String, u64)>,
}

pub fn ingest_line(line: &str) -> Result<Option<GuardEvent>, Error> {
    ingest_line_meta(line).map(|ingested| ingested.event)
}

pub fn ingest_line_meta(line: &str) -> Result<Ingested, Error> {
    if line.len() > MAX_LINE {
        return Err(schema("line too long"));
    }
    if line.trim().is_empty() {
        return Ok(Ingested::default());
    }
    let outer: Value = serde_json::from_str(line).map_err(|_| schema("json rejected"))?;
    let (value, envelope) = match unwrap_envelope(&outer)? {
        Unwrapped::Event(inner, pos) => (inner, Some(pos)),
        Unwrapped::Skip => return Ok(Ingested::default()),
        Unwrapped::Plain => (outer, None),
    };
    let Some(mut event) = ingest_value(&value)? else {
        return Ok(Ingested {
            event: None,
            envelope,
        });
    };
    if event.origin == Origin::Ring {
        event.origin = Origin::Nocved;
    }
    crate::model::validate_event(&event)?;
    Ok(Ingested {
        event: Some(event),
        envelope,
    })
}

enum Unwrapped {
    Plain,
    Skip,
    Event(Value, (String, u64)),
}

const ENVELOPE_KEYS: [&str; 7] = ["v", "host", "epoch", "seq", "prev", "payload", "mac"];
const HEARTBEAT_KEYS: [&str; 4] = ["v", "host", "payload", "mac"];

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn unwrap_envelope(v: &Value) -> Result<Unwrapped, Error> {
    let Value::Object(map) = v else {
        return Ok(Unwrapped::Plain);
    };
    if !map.contains_key("payload") || map.contains_key("kind") {
        return Ok(Unwrapped::Plain);
    }
    let has = |keys: &[&str]| map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k));
    if has(&HEARTBEAT_KEYS) {
        return Ok(Unwrapped::Skip);
    }
    if !has(&ENVELOPE_KEYS) {
        return Err(schema("envelope rejected"));
    }
    let str_of = |key: &str| map.get(key).and_then(Value::as_str);
    let version_ok = map.get("v").and_then(Value::as_u64) == Some(1);
    let host_ok = str_of("host").is_some_and(|h| (1..=253).contains(&h.len()));
    let epoch = str_of("epoch").filter(|e| lower_hex(e, 32));
    let prev_ok = str_of("prev").is_some_and(|p| lower_hex(p, 64));
    let mac_ok = str_of("mac").is_some_and(|m| lower_hex(m, 64));
    let seq = map.get("seq").and_then(Value::as_u64);
    let (Some(epoch), Some(seq), true, true, true, true) =
        (epoch, seq, version_ok, host_ok, prev_ok, mac_ok)
    else {
        return Err(schema("envelope rejected"));
    };
    let payload = str_of("payload").ok_or_else(|| schema("envelope rejected"))?;
    if payload.len() > MAX_LINE {
        return Err(schema("line too long"));
    }
    let inner: Value = serde_json::from_str(payload).map_err(|_| schema("json rejected"))?;
    match &inner {
        Value::Object(inner_map) if !inner_map.contains_key("payload") => {}
        _ => return Err(schema("envelope rejected")),
    }
    Ok(Unwrapped::Event(inner, (epoch.to_owned(), seq)))
}

fn ingest_value(v: &Value) -> Result<Option<GuardEvent>, Error> {
    if is_finding(v) {
        return Ok(Some(finding_from(v)?));
    }
    let kind = match v.get("kind") {
        None => return Err(schema("kind missing")),
        Some(Value::String(s)) if s.is_empty() => return Err(schema("kind missing")),
        Some(Value::String(s)) => s.as_str(),
        _ => return Err(schema("kind rejected")),
    };
    if is_nocved_kind(kind) {
        return from_nocved(v);
    }
    if is_guard_kind(kind) {
        let mut event: GuardEvent =
            serde_json::from_value(v.clone()).map_err(|_| schema("json rejected"))?;
        normalize_event_comm(&mut event);
        let (args, cut) = filter_args(std::mem::take(&mut event.args));
        event.args = args;
        event.args_truncated |= cut;
        return Ok(Some(event));
    }
    Ok(None)
}

fn is_finding(v: &Value) -> bool {
    if v.get("correlation_key").is_some() {
        return true;
    }
    let kind_empty = match v.get("kind") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) if s.is_empty() => true,
        _ => false,
    };
    kind_empty && v.get("schema_version").is_some() && v.get("rule_id").is_some()
}

fn is_nocved_kind(kind: &str) -> bool {
    matches!(
        kind,
        "process.start"
            | "audit.exec"
            | "package.change"
            | "container.start"
            | "net.connect"
            | "net.listen"
    )
}

fn is_guard_kind(kind: &str) -> bool {
    matches!(
        kind,
        "exec" | "exit" | "connect" | "listen" | "package" | "container" | "finding"
    )
}

fn opt_u32(v: &Value, key: &str) -> Result<Option<u32>, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let raw = n.as_u64().ok_or_else(|| schema("field rejected"))?;
            u32::try_from(raw)
                .map(Some)
                .map_err(|_| schema("field rejected"))
        }
        _ => Err(schema("field rejected")),
    }
}

fn opt_i64(v: &Value, key: &str) -> Result<i64, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| schema("field rejected")),
        _ => Err(schema("field rejected")),
    }
}

fn opt_string(v: &Value, key: &str) -> Result<Option<String>, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => {
            check_text(s)?;
            Ok(Some(s.clone()))
        }
        _ => Err(schema("field rejected")),
    }
}

/// argv as a list (or one string). A non-string entry is a bad field; argv
/// shape (count, length, newlines) never is.
fn string_list(v: &Value, key: &str) -> Result<(Vec<String>, bool), Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok((Vec::new(), false)),
        Some(Value::String(s)) => Ok(filter_args(vec![s.clone()])),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => return Err(schema("field rejected")),
                }
            }
            Ok(filter_args(out))
        }
        _ => Err(schema("field rejected")),
    }
}

/// Rule of the highest-severity nocved signal (first wins a tie). Signals
/// that are malformed or carry an invalid rule token are ignored; the
/// summary is never read.
fn signal_rule(v: &Value) -> Option<String> {
    let Some(Value::Array(items)) = v.get("signals") else {
        return None;
    };
    let mut best: Option<(Severity, &str)> = None;
    for item in items {
        let Some(rule) = item.get("rule").and_then(Value::as_str) else {
            continue;
        };
        if !valid_rule_token(rule) {
            continue;
        }
        let severity = match item.get("severity").and_then(Value::as_str) {
            Some("critical") => Severity::Critical,
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            Some("low") => Severity::Low,
            _ => Severity::Info,
        };
        if best.is_none_or(|(have, _)| severity > have) {
            best = Some((severity, rule));
        }
    }
    best.map(|(_, rule)| rule.to_owned())
}

fn base_event(kind: Kind, origin: Origin, observed_at_ms: i64) -> GuardEvent {
    GuardEvent {
        schema_version: SCHEMA_VERSION,
        kind,
        origin,
        observed_at_ms,
        pid: None,
        ppid: None,
        uid: None,
        exe: None,
        comm: None,
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

fn from_nocved(v: &Value) -> Result<Option<GuardEvent>, Error> {
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| schema("kind rejected"))?;
    let observed = opt_i64(v, "observed_at_ms")?;
    let event = match kind {
        "process.start" => Some(from_process(v, observed)?),
        "audit.exec" => Some(from_audit(v, observed)?),
        "package.change" => from_package(v, observed)?,
        "container.start" => Some(from_container(v, observed)?),
        "net.connect" => Some(from_net(v, observed, Kind::Connect)?),
        "net.listen" => Some(from_net(v, observed, Kind::Listen)?),
        _ => None,
    };
    Ok(event.map(|mut ev| {
        ev.source_rule_id = signal_rule(v);
        ev
    }))
}

fn from_process(v: &Value, observed: i64) -> Result<GuardEvent, Error> {
    let mut ev = base_event(Kind::Exec, Origin::Nocved, observed);
    ev.pid = opt_u32(v, "pid")?;
    ev.ppid = opt_u32(v, "ppid")?;
    ev.uid = opt_u32(v, "uid")?;
    ev.exe = opt_string(v, "exe")?;
    (ev.comm, ev.comm_invalid) = normalize_comm(v.get("name"));
    (ev.args, ev.args_truncated) = string_list(v, "cmdline")?;
    ev.container_id = normalize_container_id(opt_string(v, "container_id")?)?;
    Ok(ev)
}

fn from_audit(v: &Value, observed: i64) -> Result<GuardEvent, Error> {
    let mut ev = base_event(Kind::Exec, Origin::Nocved, observed);
    ev.pid = opt_u32(v, "pid")?;
    ev.ppid = opt_u32(v, "ppid")?;
    ev.uid = opt_u32(v, "uid")?;
    ev.exe = opt_string(v, "exe")?;
    (ev.comm, ev.comm_invalid) = normalize_comm(v.get("comm"));
    (ev.args, ev.args_truncated) = string_list(v, "argv")?;
    let _ = v.get("success");
    Ok(ev)
}

fn from_package(v: &Value, observed: i64) -> Result<Option<GuardEvent>, Error> {
    if matches!(v.get("version_new"), Some(Value::Null)) {
        return Ok(None);
    }
    let version = opt_string(v, "version_new")?.ok_or_else(|| schema("field rejected"))?;
    let package = opt_string(v, "package")?.ok_or_else(|| schema("field rejected"))?;
    let mut ev = base_event(Kind::Package, Origin::Nocved, observed);
    ev.package = Some(package);
    ev.version = Some(version);
    Ok(Some(ev))
}

fn from_container(v: &Value, observed: i64) -> Result<GuardEvent, Error> {
    let mut ev = base_event(Kind::Container, Origin::Nocved, observed);
    ev.container_id = normalize_container_id(opt_string(v, "id")?)?;
    ev.privileged = match v.get("privileged") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        _ => return Err(schema("field rejected")),
    };
    Ok(ev)
}

fn from_net(v: &Value, observed: i64, kind: Kind) -> Result<GuardEvent, Error> {
    let mut ev = base_event(kind, Origin::Nocved, observed);
    ev.pid = opt_u32(v, "pid")?;
    ev.exe = opt_string(v, "exe")?;
    ev.remote = remote_from(v, kind)?;
    ev.local = local_from(v)?;
    if kind == Kind::Connect
        && let Some(remote) = &ev.remote
    {
        check_remote(remote)?;
    }
    Ok(ev)
}

/// A bare address (no port) in `remote_ip`: IPv4 dotted quad or IPv6.
fn bare_ip(text: &str) -> Result<IpAddr, Error> {
    match parse_endpoint(text)? {
        (ip, None) if !text.starts_with('[') => Ok(ip),
        _ => Err(schema("remote rejected")),
    }
}

/// A listener has no peer: nocved sends the unspecified address (`0.0.0.0`
/// or `::`) with port 0, which is no remote. A connect needs port 1..=65535.
fn remote_from(v: &Value, kind: Kind) -> Result<Option<String>, Error> {
    let Some(text) = opt_string(v, "remote_ip")? else {
        return Ok(None);
    };
    let ip = bare_ip(&text)?;
    let port = match opt_u32(v, "remote_port")? {
        None => None,
        Some(port) => Some(u16::try_from(port).map_err(|_| schema("remote rejected"))?),
    };
    if kind == Kind::Listen && ip.is_unspecified() && matches!(port, None | Some(0)) {
        return Ok(None);
    }
    if kind == Kind::Connect && port == Some(0) {
        return Err(schema("remote rejected"));
    }
    Ok(Some(format_endpoint(ip, port)))
}

/// Local endpoint. nocved (2026-10+) sends `local_ip` and `local_port`;
/// those win. Older sensors send only `local` as `{ip}:{port}`, with IPv6
/// unbracketed (`::1:9998`) before 2026-10 and bracketed (`[::1]:9998`)
/// after, so the fallback splits the port off the last colon and strips
/// brackets.
fn local_from(v: &Value) -> Result<Option<String>, Error> {
    if let Some(ip) = opt_string(v, "local_ip")? {
        let port = opt_u32(v, "local_port")?
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| schema("local rejected"))?;
        return Ok(Some(format_endpoint(bare_ip(&ip)?, Some(port))));
    }
    let Some(text) = opt_string(v, "local")? else {
        return Ok(None);
    };
    let (ip, port) = text
        .rsplit_once(':')
        .ok_or_else(|| schema("local rejected"))?;
    let ip = match ip.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .ok_or_else(|| schema("local rejected"))?,
        None => ip,
    };
    Ok(Some(format_endpoint(bare_ip(ip)?, Some(parse_port(port)?))))
}

fn normalize_container_id(id: Option<String>) -> Result<Option<String>, Error> {
    let Some(id) = id else {
        return Ok(None);
    };
    let bytes = id.as_bytes();
    if bytes.len() >= 12 && bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Some(id[..12].to_ascii_lowercase()));
    }
    check_text(&id)?;
    Ok(Some(id))
}

fn finding_from(v: &Value) -> Result<GuardEvent, Error> {
    let version = match v.get("schema_version") {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| schema("schema rejected"))?,
        Some(_) => return Err(schema("schema rejected")),
        None => return Err(schema("schema rejected")),
    };
    if version != u64::from(SCHEMA_VERSION) {
        return Err(schema("schema rejected"));
    }
    let mut ev = base_event(Kind::Finding, Origin::Aftercve, 0);
    (ev.comm, ev.comm_invalid) = normalize_comm(v.get("rule_id"));
    ev.source_rule_id = v
        .get("rule_id")
        .and_then(Value::as_str)
        .filter(|rule| valid_rule_token(rule))
        .map(str::to_owned);
    ev.severity = match v.get("severity").and_then(Value::as_str) {
        Some("informational") | Some("info") => Some("info".to_owned()),
        Some("low" | "medium" | "high" | "critical") => Some(
            v.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_owned(),
        ),
        Some(_) => return Err(schema("field rejected")),
        None => None,
    };
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MAX_ARGS;

    #[test]
    fn import_never_ring_and_drops_finding_prose() {
        let native =
            ingest_line(r#"{"kind":"exec","origin":"ring","exe":"/usr/bin/xmrig","comm":"xmrig"}"#)
                .unwrap()
                .unwrap();
        assert_ne!(native.origin, Origin::Ring);
        let finding = r#"{
            "schema_version": 1,
            "rule_id": "miner-rule",
            "correlation_key": "k",
            "severity": "informational",
            "title": "TITLE-SECRET-XYZ",
            "explanation": "EXPL-SECRET-XYZ",
            "inference": "INFER-SECRET-XYZ",
            "recommendations": [{"action_id": "kill", "text": "RECOMMEND-SECRET-XYZ"}]
        }"#;
        let ev = ingest_line(finding).unwrap().unwrap();
        assert_eq!(ev.origin, Origin::Aftercve);
        assert_eq!(ev.severity.as_deref(), Some("info"));
        let encoded = serde_json::to_string(&ev).unwrap();
        assert!(!encoded.contains("TITLE-SECRET-XYZ"));
        assert!(!encoded.contains("RECOMMEND-SECRET-XYZ"));
        assert!(!encoded.contains("EXPL-SECRET-XYZ"));
        assert!(!encoded.contains("INFER-SECRET-XYZ"));
    }

    #[test]
    fn nocved_shapes_skip_unknown_and_null_versions() {
        assert!(ingest_line(r#"{"kind":"auth.fail"}"#).unwrap().is_none());
        assert!(ingest_line(r#"{"kind":""}"#).is_err());
        assert!(ingest_line("{}").is_err());
        assert!(
            ingest_line(
                r#"{"kind":"package.change","package":"example-miner","version_new":null}"#
            )
            .unwrap()
            .is_none()
        );
        let pkg = ingest_line(
            r#"{"kind":"package.change","package":"example-miner","version_new":"1.2.3-1"}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(pkg.version.as_deref(), Some("1.2.3-1"));
        assert_eq!(pkg.origin, Origin::Nocved);
        let exec = ingest_line(
            r#"{"kind":"audit.exec","pid":3,"exe":"/bin/x","comm":"x","argv":["x","--password=x"],"success":false,"signals":[{"summary":"SECRET-SIGNAL"}]}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(exec.args, vec!["x".to_owned()]);
        let encoded = serde_json::to_string(&exec).unwrap();
        assert!(!encoded.contains("SECRET-SIGNAL"));
        assert!(!encoded.contains("password"));
        let ctr = ingest_line(
            r#"{"kind":"container.start","id":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","name":"privileged-miner","privileged":null}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ctr.container_id.as_deref(), Some("abcdefabcdef"));
        assert_eq!(ctr.privileged, None);
        let encoded = serde_json::to_string(&ctr).unwrap();
        assert!(!encoded.contains("privileged-miner"));
        assert!(!encoded.contains("\"privileged\":true"));
    }

    #[test]
    fn guard_event_drops_password_field() {
        let ev = ingest_line(
            r#"{"kind":"exec","exe":"/tmp/xmrig","comm":"xmrig","password":"super-secret-value"}"#,
        )
        .unwrap()
        .unwrap();
        let encoded = serde_json::to_string(&ev).unwrap();
        assert!(!encoded.contains("super-secret-value"));
    }

    #[test]
    fn firefox_web_content_comm_is_dropped_and_exe_kept() {
        for line in [
            r#"{"kind":"process.start","pid":9,"ppid":1,"uid":1000,"name":"Web Content","exe":"/usr/lib/firefox/firefox"}"#,
            r#"{"kind":"audit.exec","pid":9,"ppid":1,"uid":1000,"comm":"Web Content","exe":"/usr/lib/firefox/firefox","argv":["firefox"]}"#,
            r#"{"kind":"exec","pid":9,"comm":"Web Content","exe":"/usr/lib/firefox/firefox"}"#,
        ] {
            let ev = ingest_line(line).unwrap().unwrap();
            assert_eq!(ev.comm, None, "{line}");
            assert!(ev.comm_invalid, "{line}");
            assert_eq!(ev.exe.as_deref(), Some("/usr/lib/firefox/firefox"));
        }
        let ok = ingest_line(r#"{"kind":"audit.exec","pid":3,"comm":"bash","exe":"/bin/bash"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(ok.comm.as_deref(), Some("bash"));
        assert!(!ok.comm_invalid);
    }

    #[test]
    fn hostile_comm_is_dropped_not_line_rejected() {
        let long = "a".repeat(600);
        for comm in [
            "nocved\n".to_owned(),
            "../../afterguard".to_owned(),
            "xmrig;rm -rf".to_owned(),
            long,
        ] {
            let line = serde_json::json!({
                "kind": "audit.exec", "pid": 7, "comm": comm, "exe": "/tmp/xmrig"
            })
            .to_string();
            let ev = ingest_line(&line).unwrap().unwrap();
            assert!(ev.comm.is_none());
            assert!(ev.comm_invalid);
            assert_eq!(ev.exe.as_deref(), Some("/tmp/xmrig"));
        }
        let numeric =
            ingest_line(r#"{"kind":"process.start","pid":7,"name":42,"exe":"/tmp/xmrig"}"#)
                .unwrap()
                .unwrap();
        assert!(numeric.comm_invalid);
        let finding = ingest_line(
            r#"{"schema_version":1,"rule_id":"bad rule id","correlation_key":"k","severity":"high"}"#,
        )
        .unwrap()
        .unwrap();
        assert!(finding.comm.is_none());
        assert!(finding.comm_invalid);
    }

    fn envelope(seq: u64, payload: &serde_json::Value) -> String {
        serde_json::json!({
            "v": 1,
            "host": "web-1",
            "epoch": "0123456789abcdef0123456789abcdef",
            "seq": seq,
            "prev": "ab".repeat(32),
            "payload": payload.to_string(),
            "mac": "cd".repeat(32),
        })
        .to_string()
    }

    fn nocved_process_start() -> serde_json::Value {
        // Shape of nocve_proto::Event { observed_at_ms, source, kind (flattened
        // ProcessInfo), signals } as nocved serialises it into the spool.
        serde_json::json!({
            "observed_at_ms": 1_727_000_000_000_i64,
            "source": "proc",
            "kind": "process.start",
            "pid": 4242,
            "ppid": 1,
            "uid": 0,
            "name": "xmrig",
            "exe": "/tmp/xmrig",
            "exe_deleted": false,
            "cmdline": ["/tmp/xmrig", "--donate-level=1", "--pass=SECRET-PASSWORD"],
            "cwd": "/tmp",
            "start_ticks": 123_456,
            "started_at_ms": 1_726_999_999_000_i64,
            "container_id": null,
            "signals": [{"rule": "miner", "severity": "high", "summary": "SIGNAL-SUMMARY"}]
        })
    }

    #[test]
    fn nocved_spool_envelope_is_unwrapped() {
        let line = envelope(17, &nocved_process_start());
        let got = ingest_line_meta(&line).unwrap();
        assert_eq!(
            got.envelope,
            Some(("0123456789abcdef0123456789abcdef".to_owned(), 17))
        );
        let ev = got.event.unwrap();
        assert_eq!(ev.kind, Kind::Exec);
        assert_eq!(ev.origin, Origin::Nocved);
        assert_eq!(ev.exe.as_deref(), Some("/tmp/xmrig"));
        assert_eq!(ev.pid, Some(4242));
        let stored = serde_json::to_string(&ev).unwrap();
        assert!(!stored.contains("SIGNAL-SUMMARY"));
        assert!(!stored.contains("SECRET-PASSWORD"));

        // Unknown inner kind is skipped but the position is still reported.
        let exit = envelope(
            18,
            &serde_json::json!({"observed_at_ms": 1, "source": "proc", "kind": "process.exit", "pid": 1, "name": "x", "exe": null, "start_ticks": 1, "lifetime_ms": null}),
        );
        let skipped = ingest_line_meta(&exit).unwrap();
        assert!(skipped.event.is_none());
        assert_eq!(skipped.envelope.map(|(_, s)| s), Some(18));
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let inner = nocved_process_start();
        let mut bad_epoch: serde_json::Value = serde_json::from_str(&envelope(1, &inner)).unwrap();
        bad_epoch["epoch"] = "XYZ".into();
        assert!(ingest_line(&bad_epoch.to_string()).is_err());
        let mut extra: serde_json::Value = serde_json::from_str(&envelope(1, &inner)).unwrap();
        extra["extra"] = 1.into();
        assert!(ingest_line(&extra.to_string()).is_err());
        let nested = envelope(2, &serde_json::from_str(&envelope(1, &inner)).unwrap());
        assert!(ingest_line(&nested).is_err());
        let not_json = envelope(3, &serde_json::Value::String("{".into()));
        assert!(ingest_line(&not_json).is_err());
        let ring_claim = envelope(
            4,
            &serde_json::json!({"kind": "exec", "origin": "ring", "exe": "/tmp/xmrig"}),
        );
        assert_eq!(
            ingest_line(&ring_claim).unwrap().unwrap().origin,
            Origin::Nocved
        );
        let heartbeat = serde_json::json!({"v":1,"host":"h","payload":"{}","mac":"cd".repeat(32)});
        assert!(ingest_line(&heartbeat.to_string()).unwrap().is_none());
    }

    const MINER_BURST: &str = include_str!("../testdata/e2e_miner_burst.jsonl");
    const BASH_C: &str = include_str!("../testdata/e2e_bash_c.jsonl");
    const FEED_REJECTED: &str = include_str!("../testdata/e2e_feed_rejected.jsonl");
    const NET_CONNECT: &str = include_str!("../testdata/e2e_net_connect_payload.json");

    /// Re-wraps a real feed envelope with an edited payload.
    fn with_payload(line: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut outer: serde_json::Value = serde_json::from_str(line).unwrap();
        let mut inner: serde_json::Value =
            serde_json::from_str(outer["payload"].as_str().unwrap()).unwrap();
        edit(&mut inner);
        outer["payload"] = inner.to_string().into();
        outer.to_string()
    }

    #[test]
    fn e2e_miner_with_padded_argv_is_ingested_not_rejected() {
        // seq 533-535 from the live run: the bash launcher, the 2-arg miner,
        // and the miner run with 70 args (nocved masked it to 64 + "…").
        let lines: Vec<&str> = MINER_BURST.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(ingest_line(line).unwrap().is_some(), "{line}");
        }
        let got = ingest_line_meta(lines[2]).unwrap();
        assert_eq!(got.envelope.as_ref().map(|(_, s)| *s), Some(535));
        let ev = got.event.unwrap();
        assert_eq!(ev.exe.as_deref(), Some("/tmp/.cache/kcompactd0"));
        assert_eq!(ev.comm.as_deref(), Some("kcompactd0"));
        assert_eq!(ev.args.len(), MAX_ARGS);
        assert!(ev.args_truncated);
        // proc.masquerade (high) beats proc.exe_hidden_dir (medium).
        assert_eq!(ev.source_rule_id.as_deref(), Some("proc.masquerade"));
        let stored = serde_json::to_string(&ev).unwrap();
        assert!(!stored.contains("looks like kernel thread"));

        let short = ingest_line(lines[1]).unwrap().unwrap();
        assert!(!short.args_truncated);

        // The unmasked shape the attacker ran: exe plus 70 args.
        let seventy = with_payload(lines[2], |p| {
            let mut argv = vec![serde_json::Value::from("/tmp/.cache/kcompactd0")];
            argv.extend((0..70).map(|_| serde_json::Value::from("10")));
            p["cmdline"] = argv.into();
        });
        let ev = ingest_line(&seventy).unwrap().unwrap();
        assert_eq!(ev.args.len(), MAX_ARGS);
        assert!(ev.args_truncated);
        assert_eq!(ev.exe.as_deref(), Some("/tmp/.cache/kcompactd0"));
    }

    #[test]
    fn e2e_bash_c_script_and_long_args_are_ingested() {
        let real = ingest_line(BASH_C.trim_end()).unwrap().unwrap();
        assert_eq!(real.exe.as_deref(), Some("/usr/bin/bash"));
        assert!(!real.args_truncated);

        // The same `bash -c` launcher with its script lines intact.
        let script = "mkdir -p /tmp/.cache && cp /bin/sleep /tmp/.cache/kcompactd0\n\
                      (nohup /tmp/.cache/kcompactd0 600 >/dev/null 2>&1 &)\r\n\
                      ln -sf /dev/null /root/.bash_history\x1b[0m";
        let multi = with_payload(BASH_C.trim_end(), |p| {
            p["cmdline"] = serde_json::json!(["bash", "-c", script]);
        });
        let ev = ingest_line(&multi).unwrap().unwrap();
        assert_eq!(ev.args.len(), 3);
        assert!(!ev.args[2].contains('\n'));
        assert!(!ev.args[2].contains('\r'));
        assert!(ev.args[2].contains("kcompactd0\\n(nohup"));
        assert!(ev.args[2].contains("\\u{1b}[0m"));
        assert!(!ev.args_truncated);

        // Real feed lines afterguard dropped live: an arg over 512 bytes, and
        // 65 args.
        for line in FEED_REJECTED.lines() {
            let ev = ingest_line(line).unwrap().unwrap();
            assert!(ev.args_truncated, "{line}");
            assert!(ev.args.len() <= MAX_ARGS);
            assert!(ev.args.iter().all(|a| a.len() <= crate::model::MAX_STRING));
        }
    }

    /// `net.listen` as nocved serialises `NetConnInfo`
    /// (nocved/src/sources/net.rs, listen branch).
    fn nocved_listen(local: &str, remote_ip: &str) -> serde_json::Value {
        serde_json::json!({
            "observed_at_ms": 1_790_869_200_000_i64,
            "source": "net",
            "kind": "net.listen",
            "proto": "tcp",
            "local": local,
            "remote_ip": remote_ip,
            "remote_port": 0,
            "state": "listen",
            "pid": 812,
            "exe": "/tmp/.cache/kcompactd0",
            "netns": "net:[4026531840]",
            "inode": 1_234_567,
            "signals": [{"rule": "net.listen", "severity": "medium", "summary": "tcp listening"}]
        })
    }

    #[test]
    fn nocved_listen_and_ipv6_net_lines_are_accepted() {
        for (local, remote, want) in [
            ("0.0.0.0:22", "0.0.0.0", "0.0.0.0:22"),
            (":::22", "::", "[::]:22"),
            ("::1:9998", "::", "[::1]:9998"),
            ("[::1]:9998", "::", "[::1]:9998"),
            ("127.0.0.1:9998", "0.0.0.0", "127.0.0.1:9998"),
        ] {
            let line = envelope(40, &nocved_listen(local, remote));
            let ev = ingest_line(&line).unwrap().unwrap();
            assert_eq!(ev.kind, Kind::Listen);
            assert_eq!(ev.remote, None, "{local}");
            assert_eq!(ev.local.as_deref(), Some(want));
            assert_eq!(ev.source_rule_id.as_deref(), Some("net.listen"));
            assert!(crate::model::validate_event(&ev).is_ok());
        }
        // Stored net.connect payload from the live run, then the same over IPv6.
        let connect: serde_json::Value = serde_json::from_str(NET_CONNECT).unwrap();
        let ev = ingest_line(&envelope(41, &connect)).unwrap().unwrap();
        assert_eq!(ev.remote.as_deref(), Some("151.101.34.137:443"));
        assert_eq!(ev.local.as_deref(), Some("172.17.0.4:38980"));
        let mut v6 = connect.clone();
        v6["remote_ip"] = "2a04:4e42:8::649".into();
        v6["local"] = "2001:db8::4:38980".into();
        let ev = ingest_line(&envelope(42, &v6)).unwrap().unwrap();
        assert_eq!(ev.remote.as_deref(), Some("[2a04:4e42:8::649]:443"));
        assert_eq!(ev.local.as_deref(), Some("[2001:db8::4]:38980"));

        // Still fail closed on junk.
        let mut zero = connect.clone();
        zero["remote_port"] = 0.into();
        assert!(ingest_line(&envelope(43, &zero)).is_err());
        let mut name = connect.clone();
        name["remote_ip"] = "evil.example".into();
        assert!(ingest_line(&envelope(44, &name)).is_err());
        let mut bracketed = connect.clone();
        bracketed["remote_ip"] = "[::1]".into();
        assert!(ingest_line(&envelope(45, &bracketed)).is_err());
        let mut bad_local = nocved_listen("0.0.0.0", "0.0.0.0");
        bad_local["local"] = "0.0.0.0".into();
        assert!(ingest_line(&envelope(46, &bad_local)).is_err());

        // nocved 2026-10: separate `local_ip` / `local_port` win over `local`.
        let mut split = nocved_listen("[::1]:9998", "::");
        split["local_ip"] = "::1".into();
        split["local_port"] = 9998.into();
        let ev = ingest_line(&envelope(47, &split)).unwrap().unwrap();
        assert_eq!(ev.local.as_deref(), Some("[::1]:9998"));
        assert_eq!(ev.remote, None);
        split["local_ip"] = "0.0.0.0".into();
        split["local_port"] = 4444.into();
        let ev = ingest_line(&envelope(48, &split)).unwrap().unwrap();
        assert_eq!(ev.local.as_deref(), Some("0.0.0.0:4444"));
        let mut no_port = split.clone();
        no_port["local_port"] = serde_json::Value::Null;
        assert!(ingest_line(&envelope(49, &no_port)).is_err());
        let mut bracketed_ip = split.clone();
        bracketed_ip["local_ip"] = "[::1]".into();
        assert!(ingest_line(&envelope(50, &bracketed_ip)).is_err());
    }

    #[test]
    fn finding_rule_id_is_the_source_rule() {
        let ev = ingest_line(
            r#"{"schema_version":1,"rule_id":"builtin.cryptominer_process","correlation_key":"k","severity":"high"}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            ev.source_rule_id.as_deref(),
            Some("builtin.cryptominer_process")
        );
        let bad = ingest_line(
            r#"{"schema_version":1,"rule_id":"bad rule id","correlation_key":"k","severity":"high"}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bad.source_rule_id, None);
    }
}
