//! Hash-chained decision ledger. Mode 0600. A full ledger rotates; it never
//! stops the daemon.
//!
//! Threats: a world-readable ledger leaks decisions. A short write left in
//! place would corrupt the next parse. Symlinks are refused. Existing files
//! with the wrong mode are not chmodded into compliance. Two writers (`once`
//! and `run`) are serialized by an exclusive `flock` on `<ledger>.lock`, and
//! each append re-reads the chain head from disk under that lock, so neither
//! can truncate or fork the other's rows. Each row carries `seq` and `prev`
//! (SHA-256 of the previous row), so an edit or deletion breaks the chain.
//!
//! Every row carries the chain `epoch`. The first row of a new ledger (and
//! the first row after a schema 2 row) draws a fresh epoch from the OS
//! CSPRNG; later rows copy it from the head, across rotation.
//!
//! When an append would pass `ledger_max`, the ledger is renamed to
//! `<ledger>.1` (replacing the previous `.1`) and the new file continues the
//! chain from the old head. A single row larger than `ledger_max` is dropped
//! and counted. Not covered: only one rotated generation is kept, so the
//! second rotation discards the oldest rows; collect `.1` before then.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::chain::{self, ChainHead};
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::model::{Decision, MAX_LEDGER_BYTES};

/// Largest tail read to recover the chain head. Rows are far smaller.
const TAIL_WINDOW: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LedgerStats {
    /// Head after this process's last append (`seq` 0 before any).
    pub head: ChainHead,
    /// Rows not written because a single row exceeded `ledger_max`.
    pub drops: u64,
    /// Times this process rotated the ledger to `.1`.
    pub rotations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    Written,
    Dropped,
}

#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    max: usize,
    stats: LedgerStats,
}

impl Ledger {
    pub fn new(path: PathBuf, max: usize) -> Result<Self, Error> {
        if max < 64 {
            return Err(Error::Invalid("ledger max rejected".to_owned()));
        }
        Ok(Self {
            path,
            max,
            stats: LedgerStats::default(),
        })
    }

    #[must_use]
    pub fn stats(&self) -> &LedgerStats {
        &self.stats
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, decision: &Decision) -> Result<Appended, Error> {
        reject_symlink(&self.path)?;
        let _lock = lock(&self.path)?;
        let mut head = read_head(&self.path)?;
        if head.epoch == 0 {
            head.epoch = chain::new_epoch()?;
        }
        let mut line = chain::chain_line(decision, &head)?;
        let hash = chain::line_hash(&line);
        line.push(b'\n');
        if line.len() > self.max {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return Ok(Appended::Dropped);
        }
        let current = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => return Err(err.into()),
        };
        let current = usize::try_from(current).unwrap_or(usize::MAX);
        if current.saturating_add(line.len()) > self.max {
            std::fs::rename(&self.path, rotated(&self.path))?;
            self.stats.rotations = self.stats.rotations.saturating_add(1);
        }
        write_row(&self.path, &line)?;
        self.stats.head = ChainHead {
            epoch: head.epoch,
            seq: head.seq.saturating_add(1),
            head: hash,
        };
        Ok(Appended::Written)
    }
}

/// `(<ledger>.1, <ledger>)` bytes; `None` for an absent file.
pub type Generations = (Option<Vec<u8>>, Option<Vec<u8>>);

/// `<ledger>.1` and `<ledger>` (either may be absent), read under a shared
/// lock so a writer cannot rotate between the two reads. Same 0600 /
/// nofollow / size policy as the writer.
pub fn read_generations(path: &Path) -> Result<Generations, Error> {
    let lock_file = open_lock(path)?;
    lock_file.lock_shared()?;
    let old = read_generation(&rotated(path))?;
    let cur = read_generation(path)?;
    Ok((old, cur))
}

fn read_generation(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match fs::read_trusted(path, MAX_LEDGER_BYTES, FilePolicy::Secret0600) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

#[must_use]
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn reject_symlink(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(Error::Invalid("symlink rejected".to_owned()))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Exclusive flock on `<ledger>.lock`, released when the file is dropped.
fn lock(path: &Path) -> Result<File, Error> {
    let file = open_lock(path)?;
    file.lock()?;
    Ok(file)
}

fn open_lock(path: &Path) -> Result<File, Error> {
    let lock_file = lock_path(path);
    reject_symlink(&lock_file)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_file)?;
    checked(&file)?;
    Ok(file)
}

/// Head of the current ledger, else of `.1`, else genesis.
fn read_head(path: &Path) -> Result<ChainHead, Error> {
    if let Some(head) = tail_head(path)? {
        return Ok(head);
    }
    if let Some(head) = tail_head(&rotated(path))? {
        return Ok(head);
    }
    Ok(ChainHead::genesis())
}

fn tail_head(path: &Path) -> Result<Option<ChainHead>, Error> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(Error::Invalid("symlink rejected".to_owned()));
    }
    let mut file = fs::open_nofollow(path)?;
    checked(&file)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let start = len.saturating_sub(TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.take(TAIL_WINDOW).read_to_end(&mut tail)?;
    if start > 0 {
        // The first line in the window may be cut; it must not be the last.
        let complete = tail.strip_suffix(b"\n").unwrap_or(&tail);
        if !complete.contains(&b'\n') {
            return Err(Error::Schema("ledger tail rejected".to_owned()));
        }
    }
    chain::head_of(&tail).map(Some)
}

fn write_row(path: &Path, line: &[u8]) -> Result<(), Error> {
    let existed = match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err.into()),
    };
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !existed {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    checked(&file)?;
    let prior = file.metadata()?.len();
    if let Err(err) = file.write_all(line).and_then(|()| file.sync_all()) {
        if let Err(rollback) = file.set_len(prior) {
            return Err(Error::Io(rollback));
        }
        return Err(Error::Io(err));
    }
    Ok(())
}

fn checked(file: &File) -> Result<(), Error> {
    let meta = file.metadata()?;
    fs::check_metadata(&meta, FilePolicy::Secret0600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::{Action, DECISION_SCHEMA_VERSION, Origin, Outcome, Reason};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::time::Duration;

    fn sample() -> Decision {
        Decision {
            schema_version: DECISION_SCHEMA_VERSION,
            epoch: None,
            seq: 0,
            prev: String::new(),
            observed_at_ms: 1,
            action: Action::Alert,
            outcome: Outcome::Shadow,
            reason: Reason::PolicyShadow,
            origin: Origin::Nocved,
            severity: cveguard_proto::model::Severity::Medium,
            plan: None,
            pid: None,
            rule_id: Some("miner-exe".to_owned()),
            source_rule_id: None,
            cve: None,
            subject: Some("xmrig".to_owned()),
            comm_invalid: false,
            args_truncated: false,
            ancestors: Vec::new(),
        }
    }

    fn read(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap_or_default()
    }

    #[test]
    fn append_is_0600_chained_and_symlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let mut ledger = Ledger::new(path.clone(), 1024 * 1024).unwrap();
        for _ in 0..3 {
            assert_eq!(ledger.append(&sample()).unwrap(), Appended::Written);
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let body = read(&path);
        assert!(chain::verify(None, &body, Some(&ledger.stats().head)));
        assert_eq!(ledger.stats().head.seq, 3);
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("\"schema_version\":3")
        );

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let err = Ledger::new(link, 1024 * 1024)
            .unwrap()
            .append(&sample())
            .unwrap_err();
        assert!(err.to_string().contains("symlink rejected"));
    }

    #[test]
    fn full_ledger_rotates_and_carries_the_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let row_len = chain::chain_line(&sample(), &ChainHead::genesis())
            .unwrap()
            .len()
            + 1;
        let mut ledger = Ledger::new(path.clone(), row_len * 3).unwrap();
        for _ in 0..7 {
            assert_eq!(ledger.append(&sample()).unwrap(), Appended::Written);
        }
        assert!(ledger.stats().rotations >= 2);
        assert_eq!(ledger.stats().drops, 0);
        let old = read(&rotated(&path));
        let cur = read(&path);
        assert!(!old.is_empty() && !cur.is_empty());
        assert!(chain::verify(Some(&old), &cur, Some(&ledger.stats().head)));
        assert_eq!(ledger.stats().head.seq, 7);
        // One epoch across the rotation.
        let epoch = ledger.stats().head.epoch;
        assert_ne!(epoch, 0);
        for body in [&old, &cur] {
            for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                let row: serde_json::Value = serde_json::from_slice(line).unwrap();
                assert_eq!(row["epoch"], epoch);
            }
        }
    }

    #[test]
    fn oversized_row_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let mut ledger = Ledger::new(path.clone(), 64).unwrap();
        assert_eq!(ledger.append(&sample()).unwrap(), Appended::Dropped);
        assert_eq!(ledger.stats().drops, 1);
        assert!(!path.exists());
    }

    #[test]
    fn existing_bad_mode_is_not_chmodded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Ledger::new(path.clone(), 4096)
            .unwrap()
            .append(&sample())
            .unwrap_err();
        assert!(err.to_string().contains("mode rejected"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn two_writers_share_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let mut run = Ledger::new(path.clone(), 1024 * 1024).unwrap();
        let mut once = Ledger::new(path.clone(), 1024 * 1024).unwrap();
        run.append(&sample()).unwrap();
        once.append(&sample()).unwrap();
        run.append(&sample()).unwrap();
        assert_eq!(run.stats().head.seq, 3);
        assert!(chain::verify(None, &read(&path), Some(&run.stats().head)));
    }

    #[test]
    fn append_waits_for_the_flock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let held = lock(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut ledger = Ledger::new(writer_path, 1024 * 1024).unwrap();
            let result = ledger.append(&sample()).map(|_| ());
            tx.send(()).unwrap();
            result
        });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        assert!(read(&path).is_empty());
        drop(held);
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        writer.join().unwrap().unwrap();
        assert!(!read(&path).is_empty());
    }

    #[test]
    fn epoch_is_kept_and_a_new_ledger_draws_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let mut ledger = Ledger::new(path.clone(), 1024 * 1024).unwrap();
        ledger.append(&sample()).unwrap();
        let first = ledger.stats().head.epoch;
        assert!((1..=chain::MAX_EPOCH).contains(&first));
        // A second writer reads the epoch from the head on disk.
        let mut other = Ledger::new(path.clone(), 1024 * 1024).unwrap();
        other.append(&sample()).unwrap();
        assert_eq!(other.stats().head.epoch, first);
        std::fs::remove_file(&path).unwrap();
        ledger.append(&sample()).unwrap();
        assert_eq!(ledger.stats().head.seq, 1);
        assert_ne!(ledger.stats().head.epoch, first);
    }
}
