//! Daemon status files and `afterguard status`.
//!
//! `run` writes the config's `status` path every pass (about once a second)
//! and before it stops. `ship` writes `<cursor>.status.json` after every
//! pass and at least every `STATUS_INTERVAL_MS` while it backs off, and once
//! more before a fatal error. Both use the output-contract envelope with
//! `kind` `afterguard.status`, a `daemon` field (`run` or `ship`), and
//! `updated_at_ms`.
//!
//! Threats: `status` only reads. It never takes the ledger lock and never
//! writes. A status file that is a symlink, group or other writable, or over
//! 64 KiB is refused, so a planted file cannot pose as a fresh daemon. A
//! file without `updated_at_ms`, older than `STALE_AFTER_MS`, or dated more
//! than `STALE_AFTER_MS` in the future is stale (fail closed). Not covered:
//! the owner of the state directory can write a fresh-looking file.

use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::cli::{self, Category, CliError};
use cveguard_proto::fs::{self, FilePolicy};
use serde_json::Value;

use crate::config::Loaded;

pub const KIND: &str = "afterguard.status";
/// Longest gap between two status writes of a healthy daemon.
pub const STATUS_INTERVAL_MS: i64 = 10_000;
/// `stale` is reported past three write intervals.
pub const STALE_AFTER_MS: i64 = 3 * STATUS_INTERVAL_MS;
const STATUS_MAX: usize = 64 * 1024;

/// Adds the envelope and `updated_at_ms` to `payload` and writes it
/// atomically with mode 0600.
pub fn write(path: &Path, mut payload: Value, now_ms: i64) -> Result<(), Error> {
    payload["updated_at_ms"] = Value::from(now_ms);
    let line = cli::envelope("afterguard", env!("CARGO_PKG_VERSION"), KIND, &payload)
        .map_err(|_| Error::Schema("json rejected".to_owned()))?;
    fs::write_atomic_0600(path, line.as_bytes())
}

/// Where `ship` keeps its status: beside the cursor.
#[must_use]
pub fn ship_path(cursor: &Path) -> PathBuf {
    let mut name = cursor
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".status.json");
    cursor.with_file_name(name)
}

/// The `status` payload and whether every configured daemon is fresh.
pub fn report(loaded: &Loaded, now_ms: i64) -> Result<(Value, bool), CliError> {
    let run = entry(loaded.status.as_deref(), now_ms)?;
    let ship_file = loaded.ship.as_ref().map(|ship| ship_path(&ship.cursor));
    let ship = entry(ship_file.as_deref(), now_ms)?;
    let fresh = [&run, &ship]
        .iter()
        .all(|e| e["configured"] == false || e["stale"] == false);
    Ok((
        serde_json::json!({
            "stale_after_ms": STALE_AFTER_MS,
            "now_ms": now_ms,
            "run": run,
            "ship": ship,
        }),
        fresh,
    ))
}

fn entry(path: Option<&Path>, now_ms: i64) -> Result<Value, CliError> {
    let Some(path) = path else {
        return Ok(serde_json::json!({"configured": false, "stale": false}));
    };
    let shown = path.to_string_lossy();
    let bytes = match fs::read_trusted(path, STATUS_MAX, FilePolicy::Config) {
        Ok(bytes) => bytes,
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({
                "configured": true,
                "path": shown,
                "present": false,
                "stale": true,
            }));
        }
        Err(err) => {
            return Err(CliError::new(
                Category::Io,
                format!("status file {}: {err}", cli::clean(&shown)),
                1,
            ));
        }
    };
    let file: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CliError::new(
            Category::Integrity,
            format!("status file {} is not JSON", cli::clean(&shown)),
            1,
        )
    })?;
    if !file.is_object() {
        return Err(CliError::new(
            Category::Integrity,
            format!("status file {} is not an object", cli::clean(&shown)),
            1,
        ));
    }
    let updated = file.get("updated_at_ms").and_then(Value::as_i64);
    let age = updated.map(|at| now_ms.saturating_sub(at));
    Ok(serde_json::json!({
        "configured": true,
        "path": shown,
        "present": true,
        "stale": is_stale(updated, now_ms),
        "updated_at_ms": updated,
        "age_ms": age,
        "file": file,
    }))
}

#[must_use]
pub fn is_stale(updated_at_ms: Option<i64>, now_ms: i64) -> bool {
    match updated_at_ms {
        None => true,
        Some(at) => {
            let age = now_ms.saturating_sub(at);
            !(-STALE_AFTER_MS..=STALE_AFTER_MS).contains(&age)
        }
    }
}

/// One line per daemon: `run status=fresh age_ms=812 path=...`.
#[must_use]
pub fn render_text(payload: &Value) -> String {
    let mut out = Vec::new();
    for name in ["run", "ship"] {
        let e = &payload[name];
        let line = if e["configured"] == false {
            format!("{name} status=not_configured")
        } else if e["present"] == false {
            format!("{name} status=missing path={}", text_of(&e["path"]))
        } else {
            let word = if e["stale"] == true { "stale" } else { "fresh" };
            let age = e["age_ms"]
                .as_i64()
                .map_or_else(|| "unknown".to_owned(), |a| a.to_string());
            format!(
                "{name} status={word} age_ms={age} path={}",
                text_of(&e["path"])
            )
        };
        out.push(line);
    }
    out.join("\n")
}

fn text_of(value: &Value) -> String {
    cli::clean(value.as_str().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_window_is_three_intervals_both_ways() {
        let now = 1_000_000;
        assert!(!is_stale(Some(now), now));
        assert!(!is_stale(Some(now - STALE_AFTER_MS), now));
        assert!(is_stale(Some(now - STALE_AFTER_MS - 1), now));
        assert!(is_stale(Some(now + STALE_AFTER_MS + 1), now));
        assert!(is_stale(None, now));
    }

    #[test]
    fn ship_status_sits_beside_the_cursor() {
        assert_eq!(
            ship_path(Path::new("/var/lib/cveguard/ship.cursor")),
            PathBuf::from("/var/lib/cveguard/ship.cursor.status.json")
        );
    }

    #[test]
    fn written_status_has_the_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        write(&path, serde_json::json!({"daemon": "run", "sent": 1}), 42).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"schema_version\":1,\"kind\":\"afterguard.status\""));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["tool"], "afterguard");
        assert_eq!(v["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["updated_at_ms"], 42);
        assert_eq!(v["sent"], 1);
        assert!(!is_stale(v["updated_at_ms"].as_i64(), 42 + STALE_AFTER_MS));
    }
}
