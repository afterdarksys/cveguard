//! One pass over the ring and the optional JSONL tail.
//!
//! Threats: enforce mode with a missing seal or a plan that cannot be rendered
//! must not record ordinary decisions. A seal mismatch writes one alert and
//! stops the pass. Imported lines stay non-ring because ingest forces that.
//! The seal is re-verified every `seal_recheck_passes` passes (default 60),
//! so a binary replaced after startup is caught. A full ledger rotates and
//! never stops the daemon. A feed gap (a shrink, or a rotation the tail
//! could not follow) is a `record` / `rejected` / `feed_gap` row and the
//! `events_gap` counter in `status.json`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cveguard_proto::Error;
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::intel::ingest_line;
use cveguard_proto::model::{Decision, GuardEvent, MAX_EVENTS_PER_PASS, MAX_LINE, Mode, Outcome};
use cveguard_proto::ring::{self, Record, SharedRing};
use cveguard_proto::seal::SealStatus;
use serde::Serialize;

use crate::config::{Loaded, seal_check_at};
use crate::engine::Engine;
use crate::ledger::Ledger;
use crate::tail::Tail;

pub struct Runtime {
    engine: Engine,
    ring: SharedRing,
    tail: Tail,
    ledger: Ledger,
    events: Option<std::path::PathBuf>,
    status: Option<std::path::PathBuf>,
    seal: Option<std::path::PathBuf>,
    seal_recheck_passes: u32,
    passes: u64,
    bad_lines: u64,
    rules_loaded: u64,
    stop: Option<&'static str>,
    written: u64,
    rejected_rows: u64,
}

#[derive(Serialize)]
struct StatusFile<'a> {
    rules_loaded: u64,
    enforce_enabled: u64,
    ring_lost: u64,
    tamper_mismatch: u64,
    bad_lines: u64,
    ledger_seq: u64,
    ledger_head: &'a str,
    ledger_drops: u64,
    ledger_rotations: u64,
    ledger_epoch: u64,
    events_replaced: u64,
    events_gap: u64,
}

impl Runtime {
    pub fn new(loaded: Loaded) -> Result<Self, Error> {
        if !loaded.enabled {
            return Err(Error::Invalid("daemon disabled".to_owned()));
        }
        let rules_loaded = u64::try_from(loaded.rules.len()).unwrap_or(u64::MAX);
        let seal = loaded.seal_check();
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
            ledger: Ledger::new(loaded.ledger, loaded.ledger_max)?,
            events: loaded.events,
            status: loaded.status,
            seal: loaded.seal,
            seal_recheck_passes: loaded.seal_recheck_passes,
            passes: 0,
            bad_lines: 0,
            rules_loaded,
            stop: None,
            written: 0,
            rejected_rows: 0,
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
        self.passes = self.passes.saturating_add(1);
        if self
            .passes
            .is_multiple_of(u64::from(self.seal_recheck_passes))
        {
            self.engine.update_seal(seal_check_at(self.seal.as_deref()));
        }
        if let Some(code) = self.gate()? {
            return Ok(code);
        }
        let mut rejected = false;
        if let Some(path) = self.events.clone() {
            let batch = self.tail.poll(&path, now_ms, MAX_EVENTS_PER_PASS)?;
            self.bad_lines = self.bad_lines.saturating_add(batch.bad_lines);
            for _ in 0..batch.gaps {
                if let Some(row) = self.engine.feed_gap(now_ms) {
                    rejected |= self.record(&row)?;
                }
            }
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

    /// Why the last pass returned 3: `seal_mismatch`, `halted`,
    /// `enforce_seal_not_valid`, or `enforce_plan_invalid`.
    #[must_use]
    pub fn stop_reason(&self) -> Option<&'static str> {
        self.stop
    }

    fn gate(&mut self) -> Result<Option<i32>, Error> {
        if let Some(alert) = self.engine.take_seal_alert() {
            self.ledger.append(&alert)?;
            self.written = self.written.saturating_add(1);
            self.stop = Some("seal_mismatch");
            self.write_status()?;
            return Ok(Some(3));
        }
        let reason = if self.engine.halted() {
            Some("halted")
        } else if self.engine.mode() == Mode::Enforce
            && self.engine.seal_status() != SealStatus::Valid
        {
            Some("enforce_seal_not_valid")
        } else if self.engine.mode() == Mode::Enforce && !self.engine.isolate_plan_ok() {
            Some("enforce_plan_invalid")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.stop = Some(reason);
            self.write_status()?;
            return Ok(Some(3));
        }
        Ok(None)
    }

    fn note(&mut self, event: GuardEvent) -> Result<bool, Error> {
        let Some(decision) = self.engine.evaluate(&event) else {
            return Ok(false);
        };
        self.record(&decision)
    }

    fn record(&mut self, decision: &Decision) -> Result<bool, Error> {
        self.ledger.append(decision)?;
        self.written = self.written.saturating_add(1);
        let rejected = decision.outcome == Outcome::Rejected;
        if rejected {
            self.rejected_rows = self.rejected_rows.saturating_add(1);
        }
        Ok(rejected)
    }

    fn write_status(&self) -> Result<(), Error> {
        let Some(path) = &self.status else {
            return Ok(());
        };
        let stats = self.ledger.stats();
        let body = StatusFile {
            rules_loaded: self.rules_loaded,
            enforce_enabled: u64::from(self.engine.mode() == Mode::Enforce),
            ring_lost: self.ring.lost(),
            tamper_mismatch: u64::from(self.engine.seal_status() == SealStatus::Mismatch),
            bad_lines: self.bad_lines,
            ledger_seq: stats.head.seq,
            ledger_head: &stats.head.head,
            ledger_drops: stats.drops,
            ledger_rotations: stats.rotations,
            ledger_epoch: stats.head.epoch,
            events_replaced: self.tail.replaced(),
            events_gap: self.tail.gaps(),
        };
        let mut payload =
            serde_json::to_value(&body).map_err(|_| Error::Schema("json rejected".to_owned()))?;
        payload["daemon"] = serde_json::Value::from("run");
        if let Some(stop) = self.stop {
            payload["stop_reason"] = serde_json::Value::from(stop);
        }
        crate::status::write(path, payload, now_ms()?)
    }
}

/// What `once` did. `stopped` is the gate reason when it exited 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnceSummary {
    #[serde(skip)]
    pub code: i32,
    pub lines_evaluated: u64,
    pub decisions_written: u64,
    pub rejected: u64,
    pub ledger_seq: u64,
    pub ledger_epoch: u64,
    pub stopped: Option<&'static str>,
}

/// `check` result. Text mode prints the old `key=value` lines and the plan.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    #[serde(skip)]
    pub code: i32,
    pub mode: &'static str,
    pub enabled: bool,
    pub rules: usize,
    pub seal: &'static str,
    pub caps: String,
    pub plan: Option<String>,
    pub plan_error: Option<String>,
    pub enforce_blocked: bool,
}

pub fn check(loaded: &Loaded) -> CheckReport {
    let seal = loaded.seal_status();
    let plan = cveguard_proto::isolate::plan(&loaded.isolate);
    let bad_seal = seal == SealStatus::Mismatch;
    let enforce_blocked =
        loaded.mode == Mode::Enforce && (seal != SealStatus::Valid || plan.is_err());
    let (plan, plan_error) = match plan {
        Ok(text) => (Some(text), None),
        Err(err) => (None, Some(err.to_string())),
    };
    CheckReport {
        code: if bad_seal || enforce_blocked { 3 } else { 0 },
        mode: mode_word(loaded.mode),
        enabled: loaded.enabled,
        rules: loaded.rules.len(),
        seal: seal_word(seal),
        caps: crate::caps::format_plan(&crate::caps::debut_plan()),
        plan,
        plan_error,
        enforce_blocked,
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

/// Bad lines become `rejected` / `schema` rows; the rest of the batch is
/// still evaluated. Exit 2 when any row was rejected.
pub fn once(loaded: Loaded, input: &Path) -> Result<OnceSummary, Error> {
    let mut runtime = Runtime::new(loaded)?;
    if let Some(code) = runtime.gate()? {
        return Ok(runtime.summary(code, 0));
    }
    let lines = parse_once(input)?;
    let lines_evaluated = u64::try_from(lines.len()).unwrap_or(u64::MAX);
    let now = now_ms()?;
    let mut rejected = false;
    for line in lines {
        let hit = match line {
            Some(mut event) => {
                if event.observed_at_ms == 0 {
                    event.observed_at_ms = now;
                }
                runtime.note(event)?
            }
            None => match runtime.engine.reject_line(now) {
                Some(decision) => runtime.record(&decision)?,
                None => false,
            },
        };
        rejected |= hit;
    }
    runtime.write_status()?;
    Ok(runtime.summary(if rejected { 2 } else { 0 }, lines_evaluated))
}

impl Runtime {
    fn summary(&self, code: i32, lines_evaluated: u64) -> OnceSummary {
        let stats = self.ledger.stats();
        OnceSummary {
            code,
            lines_evaluated,
            decisions_written: self.written,
            rejected: self.rejected_rows,
            ledger_seq: stats.head.seq,
            ledger_epoch: stats.head.epoch,
            stopped: if code == 3 { self.stop } else { None },
        }
    }
}

/// One entry per non-empty line: `Some(event)`, or `None` for a line that
/// failed to parse. Skipped kinds produce nothing.
fn parse_once(path: &Path) -> Result<Vec<Option<GuardEvent>>, Error> {
    let bytes = fs::read_trusted(path, 1024 * 1024, FilePolicy::Config)?;
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        out.push(parse_line(line));
        if out.len() > MAX_EVENTS_PER_PASS {
            return Err(Error::Invalid("too many events".to_owned()));
        }
    }
    Ok(out.into_iter().flatten().collect())
}

fn parse_line(line: &[u8]) -> Option<Option<GuardEvent>> {
    if line.len() > MAX_LINE {
        return Some(None);
    }
    let Ok(text) = std::str::from_utf8(line) else {
        return Some(None);
    };
    match ingest_line(text) {
        Ok(Some(event)) => Some(Some(event)),
        Ok(None) => None,
        Err(_) => Some(None),
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
    fn double_rotation_writes_a_feed_gap_row_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("events.jsonl");
        let line = |pid: u32| {
            format!("{{\"schema_version\":1,\"kind\":\"exec\",\"pid\":{pid},\"exe\":\"/bin/w\"}}\n")
        };
        std::fs::write(&events, line(1)).unwrap();
        let loaded = shadow_loaded(
            dir.path(),
            serde_json::json!({"events": "events.jsonl", "status": "status.json"}),
        );
        let mut runtime = Runtime::new(loaded).unwrap();
        assert_eq!(runtime.run_at(9).unwrap(), 0);
        let rotated = dir.path().join("events.jsonl.1");
        for pid in [2, 3] {
            std::fs::rename(&events, &rotated).unwrap();
            let staged = dir.path().join("fresh");
            std::fs::write(&staged, line(pid)).unwrap();
            std::fs::rename(&staged, &events).unwrap();
        }
        assert_eq!(runtime.run_at(10).unwrap(), 2);
        let body = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
        let rows: Vec<serde_json::Value> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["action"], "record");
        assert_eq!(rows[0]["outcome"], "rejected");
        assert_eq!(rows[0]["reason"], "feed_gap");
        assert_eq!(rows[0]["severity"], "high");
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("status.json")).unwrap())
                .unwrap();
        assert_eq!(status["events_gap"], 1);
        assert_eq!(status["events_replaced"], 1);
        assert_eq!(status["ledger_epoch"], rows[0]["epoch"]);
    }

    #[test]
    fn zero_passes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = shadow_loaded(dir.path(), serde_json::json!({}));
        let mut runtime = Runtime::new(loaded).unwrap();
        assert!(runtime.run_passes(0).is_err());
    }

    fn exec_record(pid: u32) -> Record {
        Record {
            kind: KIND_EXEC,
            observed_at_ms: 1,
            payload: format!(r#"{{"pid":{pid},"exe":"/tmp/xmrig","comm":"xmrig"}}"#).into_bytes(),
        }
    }

    #[test]
    fn full_ledger_keeps_running_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = shadow_loaded(
            dir.path(),
            serde_json::json!({"ledger_max": 1024, "status": "status.json"}),
        );
        let mut runtime = Runtime::new(loaded).unwrap();
        for pass in 0..20u32 {
            runtime.push_ring(exec_record(pass + 2)).unwrap();
            assert_eq!(runtime.run_at(100 + i64::from(pass)).unwrap(), 0);
        }
        let ledger = dir.path().join("decisions.jsonl");
        let old = std::fs::read(dir.path().join("decisions.jsonl.1")).unwrap();
        let cur = std::fs::read(&ledger).unwrap();
        assert!(cur.len() <= 1024);
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("status.json")).unwrap())
                .unwrap();
        assert!(status["ledger_rotations"].as_u64().unwrap() >= 1);
        assert_eq!(status["ledger_seq"], 20);
        assert_eq!(status["ledger_drops"], 0);
        let head = cveguard_proto::chain::ChainHead {
            epoch: 0,
            seq: 20,
            head: status["ledger_head"].as_str().unwrap().to_owned(),
        };
        assert!(cveguard_proto::chain::verify(Some(&old), &cur, Some(&head)));
    }

    fn seal_dir(dir: &Path) -> Vec<std::path::PathBuf> {
        let root = std::fs::canonicalize(dir).unwrap();
        let tools = root.join("bin");
        std::fs::create_dir(&tools).unwrap();
        let mut paths = Vec::new();
        for name in cveguard_proto::seal::CENSUS {
            let path = tools.join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            paths.push(path);
        }
        let manifest = cveguard_proto::seal::pin(&paths).unwrap();
        cveguard_proto::seal::write_manifest(&root.join("seal.json"), &manifest).unwrap();
        paths
    }

    #[test]
    fn seal_is_rechecked_every_n_passes() {
        let dir = tempfile::tempdir().unwrap();
        let tools = seal_dir(dir.path());
        let loaded = shadow_loaded(
            dir.path(),
            serde_json::json!({"seal": "seal.json", "seal_recheck_passes": 3}),
        );
        let mut runtime = Runtime::new(loaded).unwrap();
        assert_eq!(runtime.engine.seal_status(), SealStatus::Valid);
        assert_eq!(runtime.run_at(1).unwrap(), 0);
        std::fs::write(&tools[3], b"replaced afterguard").unwrap();
        assert_eq!(runtime.run_at(2).unwrap(), 0);
        assert_eq!(runtime.run_at(3).unwrap(), 3);
        assert_eq!(runtime.engine.seal_status(), SealStatus::Mismatch);
        let body = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
        assert!(body.contains("seal_mismatch"));
        assert_eq!(runtime.run_at(4).unwrap(), 3);
    }

    #[test]
    fn seal_recheck_passes_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rules.json"), RULES).unwrap();
        let cfg = serde_json::json!({
            "mode": "shadow", "enabled": true, "rules": "rules.json",
            "seal_recheck_passes": 0,
            "isolate": {"management_ips": ["192.0.2.10"], "deadman_secs": 120}
        });
        let path = dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert!(
            Loaded::load(&path)
                .unwrap_err()
                .to_string()
                .contains("seal recheck")
        );
    }
}
