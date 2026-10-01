//! Cross-check against darksignal's validators. The `golden_*` functions are
//! verbatim copies of darksignal's; if darksignal changes one, copy it again
//! and this test says whether cveguard still only emits what it accepts.
//! darksignal refuses (ack 0x00, row lost) a frame whose host, time, or cve
//! fails these, and ignores a rule string that fails `valid_rule`.

use afterguard::ship::valid_host;
use cveguard_proto::intel::ingest_line;
use cveguard_proto::model::{
    Action, MAX_TIME_MS, Origin, Outcome, Reason, Severity, valid_cve, valid_rule_token,
    valid_subject, valid_time,
};

// golden copy of darksignal src/frame.rs MAX_TIME_MS
const GOLDEN_MAX_TIME_MS: i64 = 4_102_444_800_000;

// golden copy of darksignal src/frame.rs valid_host
fn golden_valid_host(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        })
}

// golden copy of darksignal src/frame.rs valid_rule
fn golden_valid_rule(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

// golden copy of darksignal src/frame.rs valid_time
fn golden_valid_time(ms: i64) -> bool {
    (0..=GOLDEN_MAX_TIME_MS).contains(&ms)
}

// golden copy of darksignal src/classify.rs valid_cve (reject_bad_cve)
fn golden_valid_cve(s: &str) -> bool {
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

/// Every string of length 0..=3 over an alphabet that covers each class
/// the grammars treat differently, plus length and label boundaries.
fn corpus() -> Vec<String> {
    let alphabet = ["a", "Z", "0", ".", "_", "-", "/", " ", ":", "\u{e9}"];
    let mut out = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for s in &frontier {
            for c in alphabet {
                next.push(format!("{s}{c}"));
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    for n in [62, 63, 64, 65, 127, 128, 129, 252, 253, 254] {
        out.push("a".repeat(n));
        out.push(format!("{}.b", "a".repeat(n)));
    }
    let label63 = "a".repeat(63);
    for tail in [61, 62] {
        out.push(format!(
            "{label63}.{label63}.{label63}.{}",
            "d".repeat(tail)
        ));
    }
    out.extend(
        [
            "ns2",
            "ns2.example",
            "e2e-host1",
            "host_1.lan",
            ".ns2",
            "ns2.",
            "ns2..x",
            "-x",
            "CVE-2024-1234",
            "CVE-2024-1234567",
            "CVE-2024-12345678",
            "CVE-24-1234",
            "cve-2024-1234",
            "CVE-2024-12a4",
        ]
        .map(str::to_owned),
    );
    out
}

#[test]
fn hosts_cveguard_accepts_are_exactly_darksignals() {
    for s in corpus() {
        assert_eq!(valid_host(&s), golden_valid_host(&s), "{s:?}");
    }
}

#[test]
fn every_rule_string_cveguard_can_ship_is_a_darksignal_rule() {
    for s in corpus() {
        // `source_rule_id` (valid_rule_token) and `rule_id` (a rule pack id,
        // valid_subject).
        if valid_rule_token(&s) || valid_subject(&s) {
            assert!(golden_valid_rule(&s), "{s:?}");
        }
        assert_eq!(valid_rule_token(&s), golden_valid_rule(&s), "{s:?}");
    }
    for s in shipped_enum_strings() {
        assert!(golden_valid_rule(&s), "{s:?}");
    }
}

#[test]
fn every_time_cveguard_can_ship_is_in_darksignals_range() {
    assert_eq!(MAX_TIME_MS, GOLDEN_MAX_TIME_MS);
    let stamps = [
        i64::MIN,
        -1,
        0,
        1,
        1_790_869_200_000,
        MAX_TIME_MS - 1,
        MAX_TIME_MS,
        MAX_TIME_MS + 1,
        i64::MAX,
    ];
    for ms in stamps {
        assert_eq!(valid_time(ms), golden_valid_time(ms), "{ms}");
        let line = serde_json::json!({
            "observed_at_ms": ms, "source": "proc", "kind": "process.start",
            "pid": 7, "name": "xmrig", "exe": "/tmp/xmrig"
        })
        .to_string();
        // An event that imports carries a stamp darksignal accepts; one that
        // does not is rejected (a counted bad line), never shipped.
        match ingest_line(&line) {
            Ok(Some(ev)) => assert!(golden_valid_time(ev.observed_at_ms), "{ms}"),
            Ok(None) => panic!("{ms}: skipped"),
            Err(_) => assert!(!golden_valid_time(ms), "{ms}"),
        }
    }
}

#[test]
fn every_cve_cveguard_accepts_is_a_darksignal_cve() {
    for s in corpus() {
        assert_eq!(valid_cve(&s), golden_valid_cve(&s), "{s:?}");
    }
}

/// Every action, outcome, reason, origin, and severity a row can carry, as
/// serialized. The matches are exhaustive, so a new variant fails to compile
/// here until it is listed.
fn shipped_enum_strings() -> Vec<String> {
    let actions = [Action::Record, Action::Alert, Action::Isolate];
    for a in actions {
        match a {
            Action::Record | Action::Alert | Action::Isolate => {}
        }
    }
    let outcomes = [
        Outcome::Shadow,
        Outcome::Noted,
        Outcome::Planned,
        Outcome::Suppressed,
        Outcome::Rejected,
    ];
    for o in outcomes {
        match o {
            Outcome::Shadow
            | Outcome::Noted
            | Outcome::Planned
            | Outcome::Suppressed
            | Outcome::Rejected => {}
        }
    }
    let reasons = [
        Reason::Matched,
        Reason::PolicyShadow,
        Reason::RuleShadow,
        Reason::ImportedIntel,
        Reason::SealMissing,
        Reason::SealMismatch,
        Reason::Budget,
        Reason::Protected,
        Reason::PlanInvalid,
        Reason::Schema,
        Reason::FeedGap,
    ];
    for r in reasons {
        match r {
            Reason::Matched
            | Reason::PolicyShadow
            | Reason::RuleShadow
            | Reason::ImportedIntel
            | Reason::SealMissing
            | Reason::SealMismatch
            | Reason::Budget
            | Reason::Protected
            | Reason::PlanInvalid
            | Reason::Schema
            | Reason::FeedGap => {}
        }
    }
    let origins = [Origin::Ring, Origin::Nocved, Origin::Aftercve];
    for o in origins {
        match o {
            Origin::Ring | Origin::Nocved | Origin::Aftercve => {}
        }
    }
    let severities = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for s in severities {
        match s {
            Severity::Info
            | Severity::Low
            | Severity::Medium
            | Severity::High
            | Severity::Critical => {}
        }
    }
    // A variant that does not serialize to a string becomes "", which
    // fails `golden_valid_rule`.
    fn text<T: serde::Serialize>(v: T) -> String {
        serde_json::to_value(v)
            .ok()
            .and_then(|x| x.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
    let mut out = Vec::new();
    out.extend(actions.map(text));
    out.extend(outcomes.map(text));
    out.extend(reasons.map(text));
    out.extend(origins.map(text));
    out.extend(severities.map(text));
    out
}
