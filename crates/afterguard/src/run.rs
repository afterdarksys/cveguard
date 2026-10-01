//! One pass over the ring and the optional JSONL tail.
//!
//! Threats: enforce mode with a missing seal or a plan that cannot be rendered
//! must not record ordinary decisions. A seal mismatch writes one alert and
//! stops the pass. Imported lines stay non-ring because ingest forces that.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cveguard_proto::Error;
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::intel::ingest_line;
use cveguard_proto::model::{GuardEvent, MAX_EVENTS_PER_PASS, MAX_LINE, Mode, Outcome};
use cveguard_proto::ring::{self, Record, SharedRing};
use cveguard_proto::seal::SealStatus;
use serde::Serialize;

use crate::config::Loaded;
use crate::engine::Engine;
use crate::ledger;
use crate::tail::Tail;

pub struct Runtime {
    engine: Engine,
    ring: SharedRing,
    tail: Tail,
    ledger: std::path::PathBuf,
    ledger_max: usize,
    events: Option<std::path::PathBuf>,
    status: Option<std::path::PathBuf>,
    bad_lines: u64,
    rules_loaded: u64,
}

#[derive(Serialize)]
struct StatusFile {
    rules_loaded: u64,
    enforce_enabled: u64,
    ring_lost: u64,
    tamper_mismatch: u64,
    bad_lines: u64,
}

impl Runtime {
    pub fn new(loaded: Loaded) -> Result<Self, Error> {
        if !loaded.enabled {
            return Err(Error::Invalid("daemon disabled".to_owned()));
        }
        let rules_loaded = u64::try_from(loaded.rules.len()).unwrap_or(u64::MAX);
        let seal = loaded.seal_status();
        let mut ring = SharedRing::new(loaded.ring_cap)?;
        ring.attach()?;
        let engine = Engine::new(
            loaded.rules,
            loaded.mode,
            loaded.isolate,
            loaded.budget,
            seal,
        );
        Ok(Self {
            engine,
            ring,
            tail: Tail::new(),
            ledger: loaded.ledger,
            ledger_max: loaded.ledger_max,
            events: loaded.events,
            status: loaded.status,
            bad_lines: 0,
            rules_loaded,
        })
    }

    pub fn push_ring(&mut self, rec: Record) -> Result<(), Error> {
        self.ring.push(rec)
    }

    pub fn run_passes(&mut self, passes: u32) -> Result<i32, Error> {
        if passes == 0 {
            return Err(Error::Invalid("passes rejected".to_owned()));
        }
        let mut code = 0;
        for _ in 0..passes {
            let now = now_ms()?;
            let pass = self.run_at(now)?;
            if pass == 3 {
                return Ok(3);
            }
            if pass > code {
                code = pass;
            }
        }
        Ok(code)
    }

    pub fn run_at(&mut self, now_ms: i64) -> Result<i32, Error> {
        if let Some(code) = self.gate()? {
            return Ok(code);
        }
        let mut rejected = false;
        if let Some(path) = self.events.clone() {
            let batch = self.tail.poll(&path, now_ms, MAX_EVENTS_PER_PASS)?;
            self.bad_lines = self.bad_lines.saturating_add(batch.bad_lines);
            for event in batch.events {
                if self.note(event)? {
                    rejected = true;
                }
            }
        }
        while let Some(rec) = self.ring.pop() {
            match ring::record_to_event(&rec, now_ms) {
                Ok(event) => {
                    if self.note(event)? {
                        rejected = true;
                    }
                }
                Err(_) => self.bad_lines = self.bad_lines.saturating_add(1),
            }
        }
        self.write_status()?;
        if rejected { Ok(2) } else { Ok(0) }
    }

    fn gate(&mut self) -> Result<Option<i32>, Error> {
        if let Some(alert) = self.engine.take_seal_alert() {
            ledger::append_decision(&self.ledger, &alert, self.ledger_max)?;
            self.write_status()?;
            return Ok(Some(3));
        }
        let blocked = self.engine.mode() == Mode::Enforce
            && (self.engine.seal_status() != SealStatus::Valid || !self.engine.isolate_plan_ok());
        if blocked {
            self.write_status()?;
            return Ok(Some(3));
        }
        Ok(None)
    }

    fn note(&mut self, event: GuardEvent) -> Result<bool, Error> {
        let Some(decision) = self.engine.evaluate(&event) else {
            return Ok(false);
        };
        let rejected = decision.outcome == Outcome::Rejected;
        ledger::append_decision(&self.ledger, &decision, self.ledger_max)?;
        Ok(rejected)
    }

    fn write_status(&self) -> Result<(), Error> {
        let Some(path) = &self.status else {
            return Ok(());
        };
        let body = StatusFile {
            rules_loaded: self.rules_loaded,
            enforce_enabled: u64::from(self.engine.mode() == Mode::Enforce),
            ring_lost: self.ring.lost(),
            tamper_mismatch: u64::from(self.engine.seal_status() == SealStatus::Mismatch),
            bad_lines: self.bad_lines,
        };
        let bytes =
            serde_json::to_vec(&body).map_err(|_| Error::Schema("json rejected".to_owned()))?;
        fs::write_atomic_0600(path, &bytes)
    }
}

pub fn check(loaded: &Loaded) -> Result<i32, Error> {
    let seal = loaded.seal_status();
    let plan = cveguard_proto::isolate::plan(&loaded.isolate);
    println!("mode={}", mode_word(loaded.mode));
    println!("enabled={}", if loaded.enabled { "yes" } else { "no" });
    println!("rules={}", loaded.rules.len());
    println!("seal={}", seal_word(seal));
    println!(
        "caps={}",
        crate::caps::format_plan(&crate::caps::debut_plan())
    );
    match &plan {
        Ok(text) => println!("{text}"),
        Err(err) => eprintln!("isolate: {err}"),
    }
    let bad_seal = seal == SealStatus::Mismatch;
    let enforce_blocked =
        loaded.mode == Mode::Enforce && (seal != SealStatus::Valid || plan.is_err());
    if bad_seal || enforce_blocked {
        Ok(3)
    } else {
        Ok(0)
    }
}

fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Shadow => "shadow",
        Mode::Enforce => "enforce",
    }
}

fn seal_word(seal: SealStatus) -> &'static str {
    match seal {
        SealStatus::Missing => "missing",
        SealStatus::Valid => "valid",
        SealStatus::Mismatch => "mismatch",
    }
}

pub fn once(loaded: Loaded, input: &Path) -> Result<i32, Error> {
    let mut runtime = Runtime::new(loaded)?;
    if let Some(code) = runtime.gate()? {
        return Ok(code);
    }
    let events = parse_once(input)?;
    let now = now_ms()?;
    let mut rejected = false;
    for mut event in events {
        if event.observed_at_ms == 0 {
            event.observed_at_ms = now;
        }
        if runtime.note(event)? {
            rejected = true;
        }
    }
    runtime.write_status()?;
    if rejected { Ok(2) } else { Ok(0) }
}

fn parse_once(path: &Path) -> Result<Vec<GuardEvent>, Error> {
    let bytes = fs::read_trusted(path, 1024 * 1024, FilePolicy::Config)?;
    let mut events = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        push_line(&mut events, &bytes[start..index])?;
        start = index + 1;
    }
    if start < bytes.len() {
        push_line(&mut events, &bytes[start..])?;
    }
    if events.len() > MAX_EVENTS_PER_PASS {
        return Err(Error::Invalid("too many events".to_owned()));
    }
    Ok(events)
}

fn push_line(events: &mut Vec<GuardEvent>, line: &[u8]) -> Result<(), Error> {
    if line.len() > MAX_LINE {
        return Err(Error::Invalid("line too long".to_owned()));
    }
    let text = std::str::from_utf8(line).map_err(|_| Error::Schema("json rejected".to_owned()))?;
    match ingest_line(text) {
        Ok(Some(event)) => {
            events.push(event);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(Error::Schema(_)) => Err(Error::Schema("json rejected".to_owned())),
        Err(err) => Err(err),
    }
}

pub fn now_ms() -> Result<i64, Error> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid("clock rejected".to_owned()))?;
    i64::try_from(dur.as_millis()).map_err(|_| Error::Invalid("clock rejected".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Loaded;
    use cveguard_proto::ring::{KIND_EXEC, Record};
    use std::os::unix::fs::PermissionsExt;

    const RULES: &str = r#"[{"id":"miner-exe","enabled":true,"action":"alert","mode":"enforce","when":[{"op":"exe_basename","equals":"xmrig"}]}]"#;

    fn shadow_loaded(dir: &Path, extra: serde_json::Value) -> Loaded {
        std::fs::write(dir.join("rules.json"), RULES).unwrap();
        let mut cfg = serde_json::json!({
            "mode": "shadow",
            "enabled": true,
            "rules": "rules.json",
            "ledger": "decisions.jsonl",
            "isolate": {
                "local_cidrs": ["10.1.2.0/24"],
                "management_ips": ["192.0.2.10"],
                "store_ips": ["198.51.100.8"],
                "keep_store": true,
                "deadman_secs": 120
            }
        });
        if let serde_json::Value::Object(map) = extra {
            for (key, value) in map {
                cfg[key] = value;
            }
        }
        let path = dir.join("config.json");
        std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
        Loaded::load(&path).unwrap()
    }

    #[test]
    fn ring_push_records_a_shadow_decision() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = shadow_loaded(dir.path(), serde_json::json!({}));
        let mut runtime = Runtime::new(loaded).unwrap();
        runtime
            .push_ring(Record {
                kind: KIND_EXEC,
                observed_at_ms: 1,
                payload: br#"{"pid":4,"exe":"/tmp/xmrig","comm":"xmrig"}"#.to_vec(),
            })
            .unwrap();
        assert_eq!(runtime.run_at(50).unwrap(), 0);
        let body = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
        assert!(body.contains("\"outcome\":\"shadow\""));
        assert!(body.contains("\"origin\":\"ring\""));
        assert!(body.contains("xmrig"));
        assert_eq!(runtime.ring.lost(), 0);
    }

    #[test]
    fn run_at_tails_events_and_counts_a_bad_line() {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("events.jsonl");
        std::fs::write(
            &events,
            b"{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/tmp/xmrig\",\"comm\":\"xmrig\"}\n{\n",
        )
        .unwrap();
        let loaded = shadow_loaded(
            dir.path(),
            serde_json::json!({"events": "events.jsonl", "status": "status.json"}),
        );
        let mut runtime = Runtime::new(loaded).unwrap();
        assert_eq!(runtime.run_at(9).unwrap(), 0);
        let body = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
        assert!(body.contains("xmrig"));
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("status.json")).unwrap())
                .unwrap();
        assert_eq!(status["bad_lines"], 1);
        assert_eq!(status["rules_loaded"], 1);
        assert_eq!(status["enforce_enabled"], 0);
        let mode = std::fs::metadata(dir.path().join("status.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn zero_passes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = shadow_loaded(dir.path(), serde_json::json!({}));
        let mut runtime = Runtime::new(loaded).unwrap();
        assert!(runtime.run_passes(0).is_err());
    }
}
