//! Cumulative decision counts that survive ledger rotation.
//!
//! The ledger keeps two generations (`<ledger>.1` and `<ledger>`); a second
//! rotation discards the old `.1`. Before the writer renames the ledger over
//! `.1` it adds the outgoing `.1`'s rows, per action and outcome, to
//! `<ledger>.retired` and records the SHA-256 of that `.1` as `mark`. Both
//! happen under the writer's exclusive lock, so rotation is detected by the
//! writer that does it, not guessed from a size or inode change.
//!
//! A reader takes the shared lock and counts `retired + .1 + live`, leaving
//! `.1` out when its hash equals `mark` (the writer stopped between the
//! retire and the rename). The total never decreases and equals every row
//! written, across any number of rotations, `once` and `run` writers alike.
//!
//! Threats: the sidecar is 0600, symlinks are refused, and it is replaced
//! atomically. One that does not parse fails the read and the rotation
//! rather than restarting the counter at zero. Not covered: a local root
//! that edits both the sidecar and the ledger.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::chain;
use crate::error::Error;
use crate::fs::{self, FilePolicy};
use crate::model::{Action, MAX_LEDGER_BYTES, Outcome};

/// Rows per (action, outcome), indexed by `slot`.
pub type Counts = [u64; 15];

const RETIRED_MAX: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    /// SHA-256 hex of the last `.1` already added; empty before any.
    mark: String,
    counts: Counts,
}

/// Everything a reader needs, read under one shared lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cumulative {
    /// Rows ever written, per slot: retired plus both generations.
    pub decisions: Counts,
    /// Lines in the live ledger that are not a decision row.
    pub live_parse_errors: u64,
    pub rotated: Option<Vec<u8>>,
    pub current: Option<Vec<u8>>,
}

#[must_use]
pub fn slot(action: Action, outcome: Outcome) -> usize {
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

#[derive(Deserialize)]
struct Counted {
    action: Action,
    outcome: Outcome,
}

/// Per-slot rows in `bytes`, and the number of non-empty lines that are not
/// a decision row.
#[must_use]
pub fn count_rows(bytes: &[u8]) -> (Counts, u64) {
    let mut counts = [0u64; 15];
    let mut errors = 0u64;
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Counted>(line) {
            Ok(row) => {
                let i = slot(row.action, row.outcome);
                counts[i] = counts[i].saturating_add(1);
            }
            Err(_) => errors = errors.saturating_add(1),
        }
    }
    (counts, errors)
}

fn add(into: &mut Counts, from: &Counts) {
    for (a, b) in into.iter_mut().zip(from) {
        *a = a.saturating_add(*b);
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[must_use]
pub fn retired_path(ledger: &Path) -> PathBuf {
    with_suffix(ledger, ".retired")
}

fn read_optional(path: &Path, max: usize) -> Result<Option<Vec<u8>>, Error> {
    match fs::read_trusted(path, max, FilePolicy::Secret0600) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn load_retired(ledger: &Path) -> Result<Retired, Error> {
    match read_optional(&retired_path(ledger), RETIRED_MAX)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| Error::Schema("retired counts rejected".to_owned())),
        None => Ok(Retired::default()),
    }
}

/// Writer side. Call with the ledger's exclusive lock held, just before
/// renaming the ledger over `.1`: adds the outgoing `.1` to the sidecar
/// once.
pub fn retire_rotated(ledger: &Path) -> Result<(), Error> {
    let Some(old) = read_optional(&with_suffix(ledger, ".1"), MAX_LEDGER_BYTES)? else {
        return Ok(());
    };
    let mut retired = load_retired(ledger)?;
    let mark = chain::line_hash(&old);
    if chain::hash_eq(&retired.mark, &mark) {
        return Ok(());
    }
    add(&mut retired.counts, &count_rows(&old).0);
    retired.mark = mark;
    let bytes =
        serde_json::to_vec(&retired).map_err(|_| Error::Schema("json rejected".to_owned()))?;
    fs::write_atomic_0600(&retired_path(ledger), &bytes)
}

/// Shared lock on `<ledger>.lock`, opened read-only so a reader without
/// write access to the state directory can still take it. `None` when no
/// writer ever created it.
fn lock_shared(ledger: &Path) -> Result<Option<File>, Error> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(with_suffix(ledger, ".lock"));
    let file = match opened {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    fs::check_metadata(&file.metadata()?, FilePolicy::Secret0600)?;
    file.lock_shared()?;
    Ok(Some(file))
}

/// Reader side: the sidecar and both generations under one shared lock.
pub fn load(ledger: &Path) -> Result<Cumulative, Error> {
    let _lock = lock_shared(ledger)?;
    let retired = load_retired(ledger)?;
    let rotated = read_optional(&with_suffix(ledger, ".1"), MAX_LEDGER_BYTES)?;
    let current = read_optional(ledger, MAX_LEDGER_BYTES)?;
    let mut decisions = retired.counts;
    if let Some(old) = &rotated
        && !chain::hash_eq(&retired.mark, &chain::line_hash(old))
    {
        add(&mut decisions, &count_rows(old).0);
    }
    let mut live_parse_errors = 0;
    if let Some(cur) = &current {
        let (counts, errors) = count_rows(cur);
        add(&mut decisions, &counts);
        live_parse_errors = errors;
    }
    Ok(Cumulative {
        decisions,
        live_parse_errors,
        rotated,
        current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_0600(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    const ROW: &[u8] = b"{\"action\":\"alert\",\"outcome\":\"shadow\"}\n";

    #[test]
    fn a_repeated_retire_counts_the_rotated_generation_once() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("decisions.jsonl");
        write_0600(&with_suffix(&ledger, ".1"), &ROW.repeat(3));
        write_0600(&ledger, ROW);
        let total = |c: &Cumulative| c.decisions.iter().sum::<u64>();
        assert_eq!(total(&load(&ledger).unwrap()), 4);
        // The writer retires `.1`, then stops before the rename: the reader
        // must not count `.1` twice, and a second retire must not either.
        retire_rotated(&ledger).unwrap();
        assert_eq!(total(&load(&ledger).unwrap()), 4);
        retire_rotated(&ledger).unwrap();
        assert_eq!(total(&load(&ledger).unwrap()), 4);
        let got = load(&ledger).unwrap();
        assert_eq!(got.decisions[slot(Action::Alert, Outcome::Shadow)], 4);
    }

    #[test]
    fn hostile_sidecar_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("decisions.jsonl");
        let side = retired_path(&ledger);
        write_0600(&side, b"{not json");
        assert!(load(&ledger).is_err());
        write_0600(
            &side,
            br#"{"mark":"","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        );
        std::fs::set_permissions(&side, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&ledger).is_err());
        std::fs::remove_file(&side).unwrap();
        std::os::unix::fs::symlink(&ledger, &side).unwrap();
        assert!(load(&ledger).is_err());
    }
}
