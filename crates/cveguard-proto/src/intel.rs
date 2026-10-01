//! One-way adapters from nocved events and aftercve findings.
//!
//! Threats: finding titles, explanations, and recommendations can carry
//! secrets, so they are not copied. Import never produces a ring origin, so
//! a file cannot promote itself into an enforce decision. Unknown nocved
//! kinds are skipped. A known kind with bad fields fails closed.

use serde_json::Value;

use crate::error::{Error, schema};
use crate::model::{
    GuardEvent, Kind, MAX_LINE, Origin, SCHEMA_VERSION, check_remote, check_text, filter_args,
    valid_subject,
};

pub fn ingest_line(line: &str) -> Result<Option<GuardEvent>, Error> {
    if line.len() > MAX_LINE {
        return Err(schema("line too long"));
    }
    if line.trim().is_empty() {
        return Ok(None);
    }
    if line.len() > crate::model::MAX_INTEL_BYTES {
        return Err(schema("line too long"));
    }
    let value: Value = serde_json::from_str(line).map_err(|_| schema("json rejected"))?;
    let mut event = match ingest_value(&value)? {
        Some(event) => event,
        None => return Ok(None),
    };
    if event.origin == Origin::Ring {
        event.origin = Origin::Nocved;
    }
    crate::model::validate_event(&event)?;
    Ok(Some(event))
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
        let event: GuardEvent =
            serde_json::from_value(v.clone()).map_err(|_| schema("json rejected"))?;
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

fn string_list(v: &Value, key: &str) -> Result<Vec<String>, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => filter_args(vec![s.clone()]),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => return Err(schema("field rejected")),
                }
            }
            filter_args(out)
        }
        _ => Err(schema("field rejected")),
    }
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

fn from_nocved(v: &Value) -> Result<Option<GuardEvent>, Error> {
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| schema("kind rejected"))?;
    let observed = opt_i64(v, "observed_at_ms")?;
    match kind {
        "process.start" => Ok(Some(from_process(v, observed)?)),
        "audit.exec" => Ok(Some(from_audit(v, observed)?)),
        "package.change" => from_package(v, observed),
        "container.start" => Ok(Some(from_container(v, observed)?)),
        "net.connect" => Ok(Some(from_net(v, observed, Kind::Connect)?)),
        "net.listen" => Ok(Some(from_net(v, observed, Kind::Listen)?)),
        _ => Ok(None),
    }
}

fn from_process(v: &Value, observed: i64) -> Result<GuardEvent, Error> {
    let mut ev = base_event(Kind::Exec, Origin::Nocved, observed);
    ev.pid = opt_u32(v, "pid")?;
    ev.ppid = opt_u32(v, "ppid")?;
    ev.uid = opt_u32(v, "uid")?;
    ev.exe = opt_string(v, "exe")?;
    ev.comm = opt_string(v, "name")?;
    if ev.comm.as_ref().is_some_and(|comm| !valid_subject(comm)) {
        ev.comm = None;
    }
    ev.args = string_list(v, "cmdline")?;
    ev.container_id = normalize_container_id(opt_string(v, "container_id")?)?;
    Ok(ev)
}

fn from_audit(v: &Value, observed: i64) -> Result<GuardEvent, Error> {
    let mut ev = base_event(Kind::Exec, Origin::Nocved, observed);
    ev.pid = opt_u32(v, "pid")?;
    ev.ppid = opt_u32(v, "ppid")?;
    ev.uid = opt_u32(v, "uid")?;
    ev.exe = opt_string(v, "exe")?;
    ev.comm = opt_string(v, "comm")?;
    if ev.comm.as_ref().is_some_and(|comm| !valid_subject(comm)) {
        return Err(schema("subject rejected"));
    }
    ev.args = string_list(v, "argv")?;
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
    ev.remote = remote_from(v)?;
    if kind == Kind::Connect
        && let Some(remote) = &ev.remote
    {
        check_remote(remote)?;
    }
    Ok(ev)
}

fn remote_from(v: &Value) -> Result<Option<String>, Error> {
    let Some(ip) = opt_string(v, "remote_ip")? else {
        return Ok(None);
    };
    crate::cidr::parse_ipv4(&ip).map_err(|_| schema("remote rejected"))?;
    match opt_u32(v, "remote_port")? {
        Some(0) | Some(65536..) => Err(schema("remote rejected")),
        Some(port) => Ok(Some(format!("{ip}:{port}"))),
        None => Ok(Some(ip)),
    }
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
    if let Some(rule) = opt_string(v, "rule_id")?
        && valid_subject(&rule)
    {
        ev.comm = Some(rule);
    }
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
}
