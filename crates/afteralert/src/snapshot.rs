//! Ledger counts and Prometheus text. Labels come from the decision enums.
//!
//! Threats: a plan string, an argument, or a password in the ledger must not
//! become a label or a sample. A ledger that is a symlink, the wrong mode, or
//! over the cap is refused whole. One bad line increments the parse counter
//! and is left out of the series. `cveguard_ledger_chain_ok` re-verifies the
//! `seq` / `prev` hash chain over `<ledger>.1` and the ledger, and the head
//! (`ledger_seq`, `ledger_head`) afterguard wrote to `status.json`; an
//! edited, deleted, or truncated row drops it to 0. Not covered: an attacker
//! who rewrites both the ledger and `status.json` (see `cveguard_proto::chain`).
//!
//! Feed health comes from `status.json`: `cveguard_feed_bad_lines` (lines the
//! tail could not parse), `cveguard_feed_events_replaced` (times the feed
//! path named a new inode), and `cveguard_feed_gaps` (stretches of the feed
//! the tail lost). Only the numbers are exported, never the lines.

use std::path::Path;

use cveguard_proto::Error;
use cveguard_proto::chain::{self, ChainHead};
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::model::{Action, MAX_LEDGER_BYTES, Outcome};
use serde::Deserialize;

const ACTIONS: [Action; 3] = [Action::Record, Action::Alert, Action::Isolate];
const OUTCOMES: [Outcome; 5] = [
    Outcome::Shadow,
    Outcome::Noted,
    Outcome::Planned,
    Outcome::Suppressed,
    Outcome::Rejected,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    decisions: [u64; 15],
    ring_lost: u64,
    tamper_mismatch: u64,
    rules_loaded: u64,
    enforce_enabled: u64,
    ledger_parse_errors: u64,
    ledger_chain_ok: u64,
    ledger_drops: u64,
    feed_bad_lines: u64,
    feed_events_replaced: u64,
    feed_gaps: u64,
}

#[derive(Debug, Deserialize)]
struct Counted {
    action: Action,
    outcome: Outcome,
}

#[derive(Debug, Default, Deserialize)]
struct Gauges {
    #[serde(default)]
    rules_loaded: u64,
    #[serde(default)]
    enforce_enabled: u64,
    #[serde(default)]
    ring_lost: u64,
    #[serde(default)]
    tamper_mismatch: u64,
    #[serde(default)]
    ledger_seq: u64,
    #[serde(default)]
    ledger_head: String,
    #[serde(default)]
    ledger_drops: u64,
    #[serde(default)]
    bad_lines: u64,
    #[serde(default)]
    events_replaced: u64,
    #[serde(default)]
    events_gap: u64,
}

pub fn load_snapshot(ledger: &Path, gauges: Option<&Path>) -> Result<Snapshot, Error> {
    let (decisions, ledger_parse_errors, current) = load_ledger(ledger)?;
    let gauge = match gauges {
        Some(path) => load_gauges(path)?,
        None => Gauges::default(),
    };
    let rotated = read_ledger_file(&rotated_path(ledger))?;
    let expect = ChainHead {
        epoch: 0,
        seq: gauge.ledger_seq,
        head: gauge.ledger_head.clone(),
    };
    let ledger_chain_ok = u64::from(chain::verify(
        rotated.as_deref(),
        current.as_deref().unwrap_or_default(),
        Some(&expect),
    ));
    Ok(Snapshot {
        decisions,
        ring_lost: gauge.ring_lost,
        tamper_mismatch: gauge.tamper_mismatch,
        rules_loaded: gauge.rules_loaded,
        enforce_enabled: gauge.enforce_enabled,
        ledger_parse_errors,
        ledger_chain_ok,
        ledger_drops: gauge.ledger_drops,
        feed_bad_lines: gauge.bad_lines,
        feed_events_replaced: gauge.events_replaced,
        feed_gaps: gauge.events_gap,
    })
}

fn load_gauges(path: &Path) -> Result<Gauges, Error> {
    match fs::read_trusted(path, 64 * 1024, FilePolicy::Config) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| Error::Schema("json rejected".to_owned()))
        }
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(Gauges::default()),
        Err(err) => Err(err),
    }
}

fn rotated_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    std::path::PathBuf::from(name)
}

/// Ledger bytes under the 0600 / size / nofollow policy; `None` if absent.
fn read_ledger_file(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match fs::read_trusted(path, MAX_LEDGER_BYTES, FilePolicy::Secret0600) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

type LedgerCounts = ([u64; 15], u64, Option<Vec<u8>>);

fn load_ledger(path: &Path) -> Result<LedgerCounts, Error> {
    let Some(bytes) = read_ledger_file(path)? else {
        return Ok(([0; 15], 0, None));
    };
    let mut decisions = [0u64; 15];
    let mut errors = 0u64;
    for_each_line(&bytes, |line| match count_line(line) {
        LineCount::Skip => {}
        LineCount::Hit(action, outcome) => {
            decisions[slot(action, outcome)] = decisions[slot(action, outcome)].saturating_add(1);
        }
        LineCount::Bad => errors = errors.saturating_add(1),
    });
    Ok((decisions, errors, Some(bytes)))
}

enum LineCount {
    Skip,
    Hit(Action, Outcome),
    Bad,
}

fn count_line(line: &[u8]) -> LineCount {
    let Ok(text) = std::str::from_utf8(line) else {
        return LineCount::Bad;
    };
    if text.trim().is_empty() {
        return LineCount::Skip;
    }
    match serde_json::from_str::<Counted>(text) {
        Ok(row) => LineCount::Hit(row.action, row.outcome),
        Err(_) => LineCount::Bad,
    }
}

fn for_each_line(bytes: &[u8], mut visit: impl FnMut(&[u8])) {
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        visit(trim_cr(&bytes[start..index]));
        start = index + 1;
    }
    if start < bytes.len() {
        visit(trim_cr(&bytes[start..]));
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', head)) => head,
        _ => line,
    }
}

fn slot(action: Action, outcome: Outcome) -> usize {
    let action_index = match action {
        Action::Record => 0,
        Action::Alert => 1,
        Action::Isolate => 2,
    };
    let outcome_index = match outcome {
        Outcome::Shadow => 0,
        Outcome::Noted => 1,
        Outcome::Planned => 2,
        Outcome::Suppressed => 3,
        Outcome::Rejected => 4,
    };
    action_index * 5 + outcome_index
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Record => "record",
        Action::Alert => "alert",
        Action::Isolate => "isolate",
    }
}

fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Shadow => "shadow",
        Outcome::Noted => "noted",
        Outcome::Planned => "planned",
        Outcome::Suppressed => "suppressed",
        Outcome::Rejected => "rejected",
    }
}

#[must_use]
pub fn render(snapshot: &Snapshot) -> String {
    let mut out = String::new();
    out.push_str("# TYPE cveguard_decisions_total counter\n");
    for action in ACTIONS {
        for outcome in OUTCOMES {
            let count = snapshot.decisions[slot(action, outcome)];
            out.push_str(&format!(
                "cveguard_decisions_total{{action=\"{action}\",outcome=\"{outcome}\"}} {count}\n",
                action = action_label(action),
                outcome = outcome_label(outcome),
            ));
        }
    }
    push_gauge(&mut out, "cveguard_ring_lost", snapshot.ring_lost);
    push_gauge(
        &mut out,
        "cveguard_tamper_mismatch",
        snapshot.tamper_mismatch,
    );
    push_gauge(&mut out, "cveguard_rules_loaded", snapshot.rules_loaded);
    push_gauge(
        &mut out,
        "cveguard_enforce_enabled",
        snapshot.enforce_enabled,
    );
    out.push_str("# TYPE cveguard_ledger_parse_errors counter\n");
    out.push_str(&format!(
        "cveguard_ledger_parse_errors {}\n",
        snapshot.ledger_parse_errors
    ));
    push_gauge(
        &mut out,
        "cveguard_ledger_chain_ok",
        snapshot.ledger_chain_ok,
    );
    push_gauge(&mut out, "cveguard_ledger_drops", snapshot.ledger_drops);
    push_counter(&mut out, "cveguard_feed_bad_lines", snapshot.feed_bad_lines);
    push_counter(
        &mut out,
        "cveguard_feed_events_replaced",
        snapshot.feed_events_replaced,
    );
    push_counter(&mut out, "cveguard_feed_gaps", snapshot.feed_gaps);
    out
}

fn push_counter(out: &mut String, name: &str, value: u64) {
    out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
}

fn push_gauge(out: &mut String, name: &str, value: u64) {
    out.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn write_0600(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn renders_every_series_without_plan_text() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("decisions.jsonl");
        let line = concat!(
            r#"{"schema_version":1,"observed_at_ms":1,"action":"alert","outcome":"shadow","#,
            r#""reason":"matched","origin":"ring","plan":"nft-secret-plan","password":"hunter2"}"#,
            "\n{\n\n"
        );
        write_0600(&ledger, line.as_bytes());
        let gauges = dir.path().join("status.json");
        std::fs::write(
            &gauges,
            br#"{"rules_loaded":3,"enforce_enabled":0,"ring_lost":2,"tamper_mismatch":1,"bad_lines":49,"events_replaced":23,"events_gap":4}"#,
        )
        .unwrap();
        let snapshot = load_snapshot(&ledger, Some(&gauges)).unwrap();
        let text = render(&snapshot);
        for action in ["record", "alert", "isolate"] {
            for outcome in ["shadow", "noted", "planned", "suppressed", "rejected"] {
                let needle = format!(
                    "cveguard_decisions_total{{action=\"{action}\",outcome=\"{outcome}\"}}"
                );
                assert!(text.contains(&needle), "{needle}");
            }
        }
        assert!(text.contains("cveguard_decisions_total{action=\"alert\",outcome=\"shadow\"} 1\n"));
        assert!(text.contains("cveguard_ring_lost 2\n"));
        assert!(text.contains("cveguard_tamper_mismatch 1\n"));
        assert!(text.contains("cveguard_rules_loaded 3\n"));
        assert!(text.contains("cveguard_enforce_enabled 0\n"));
        assert!(text.contains("cveguard_ledger_parse_errors 1\n"));
        assert!(!text.contains("nft-secret-plan"));
        assert!(!text.contains("hunter2"));
        // Feed health from status.json (the live e2e status had
        // bad_lines 49 and events_replaced 23, and no exported series).
        assert!(
            text.contains("# TYPE cveguard_feed_bad_lines counter\ncveguard_feed_bad_lines 49\n")
        );
        assert!(text.contains("cveguard_feed_events_replaced 23\n"));
        assert!(text.contains("cveguard_feed_gaps 4\n"));
    }

    #[test]
    fn feed_series_are_zero_without_status() {
        let dir = tempfile::tempdir().unwrap();
        let text = render(&load_snapshot(&dir.path().join("absent.jsonl"), None).unwrap());
        for name in [
            "cveguard_feed_bad_lines",
            "cveguard_feed_events_replaced",
            "cveguard_feed_gaps",
        ] {
            assert!(text.contains(&format!("\n{name} 0\n")), "{name}");
        }
    }

    #[test]
    fn ledger_over_cap_symlink_bad_line_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.jsonl");
        let empty = load_snapshot(&missing, None).unwrap();
        let rendered = render(&empty);
        assert!(rendered.contains("cveguard_ledger_parse_errors 0\n"));
        assert!(rendered.contains("cveguard_ring_lost 0\n"));

        let big = dir.path().join("big.jsonl");
        write_0600(&big, &vec![b'x'; MAX_LEDGER_BYTES + 1]);
        let err = load_snapshot(&big, None).unwrap_err();
        assert!(err.to_string().contains("file too large"));

        let real = dir.path().join("real.jsonl");
        write_0600(&real, b"{\"action\":\"record\",\"outcome\":\"noted\"}\n");
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            load_snapshot(&link, None)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );

        let gauge_link = dir.path().join("gauge-link");
        std::os::unix::fs::symlink(&real, &gauge_link).unwrap();
        assert!(
            load_snapshot(&real, Some(&gauge_link))
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    fn row(n: i64) -> cveguard_proto::Decision {
        cveguard_proto::Decision {
            schema_version: cveguard_proto::DECISION_SCHEMA_VERSION,
            epoch: Some(9),
            seq: 0,
            prev: String::new(),
            observed_at_ms: n,
            action: Action::Alert,
            outcome: Outcome::Shadow,
            reason: cveguard_proto::Reason::PolicyShadow,
            origin: cveguard_proto::Origin::Ring,
            severity: cveguard_proto::model::Severity::Medium,
            plan: None,
            pid: Some(7),
            rule_id: Some("miner-exe".to_owned()),
            source_rule_id: None,
            cve: None,
            subject: Some("xmrig".to_owned()),
            comm_invalid: false,
            args_truncated: false,
            ancestors: Vec::new(),
        }
    }

    /// Five chained rows plus the matching status.json head.
    fn chained(dir: &Path) -> (Vec<Vec<u8>>, std::path::PathBuf) {
        let mut head = ChainHead::genesis();
        let mut rows = Vec::new();
        for n in 0..5 {
            let line = chain::chain_line(&row(n), &head).unwrap();
            head = ChainHead {
                epoch: head.epoch,
                seq: head.seq + 1,
                head: chain::line_hash(&line),
            };
            rows.push(line);
        }
        let status = dir.join("status.json");
        std::fs::write(
            &status,
            serde_json::to_vec(&serde_json::json!({
                "ledger_seq": head.seq, "ledger_head": head.head, "ledger_drops": 2
            }))
            .unwrap(),
        )
        .unwrap();
        (rows, status)
    }

    fn chain_gauge(dir: &Path, rows: &[Vec<u8>], status: &Path) -> String {
        let ledger = dir.join("decisions.jsonl");
        let mut body = Vec::new();
        for r in rows {
            body.extend_from_slice(r);
            body.push(b'\n');
        }
        write_0600(&ledger, &body);
        let text = render(&load_snapshot(&ledger, Some(status)).unwrap());
        text.lines()
            .find(|l| l.starts_with("cveguard_ledger_chain_ok "))
            .unwrap()
            .to_owned()
    }

    #[test]
    fn chain_gauge_is_one_for_an_intact_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let (rows, status) = chained(dir.path());
        assert_eq!(
            chain_gauge(dir.path(), &rows, &status),
            "cveguard_ledger_chain_ok 1"
        );
        let text =
            render(&load_snapshot(&dir.path().join("decisions.jsonl"), Some(&status)).unwrap());
        assert!(text.contains("cveguard_ledger_drops 2\n"));
    }

    #[test]
    fn chain_gauge_drops_on_edited_row() {
        let dir = tempfile::tempdir().unwrap();
        let (mut rows, status) = chained(dir.path());
        rows[2] = String::from_utf8(rows[2].clone())
            .unwrap()
            .replace("\"pid\":7", "\"pid\":8")
            .into_bytes();
        assert_eq!(
            chain_gauge(dir.path(), &rows, &status),
            "cveguard_ledger_chain_ok 0"
        );
    }

    #[test]
    fn chain_gauge_drops_on_deleted_row() {
        let dir = tempfile::tempdir().unwrap();
        let (mut rows, status) = chained(dir.path());
        rows.remove(2);
        assert_eq!(
            chain_gauge(dir.path(), &rows, &status),
            "cveguard_ledger_chain_ok 0"
        );
    }

    #[test]
    fn chain_gauge_drops_on_truncated_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let (rows, status) = chained(dir.path());
        assert_eq!(
            chain_gauge(dir.path(), &rows[..3], &status),
            "cveguard_ledger_chain_ok 0"
        );
        assert_eq!(
            chain_gauge(dir.path(), &[], &status),
            "cveguard_ledger_chain_ok 0"
        );
    }
}
