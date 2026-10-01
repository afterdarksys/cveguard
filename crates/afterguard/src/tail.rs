//! JSONL tail. Offset is the first unconsumed byte. A shrink is a gap.
//!
//! Threats: replaying a truncated file would invent a second copy of old
//! intel. A line over the cap is skipped and the offset moves past it so a
//! hostile file cannot stall the daemon on the same bytes. The file is
//! opened with O_NOFOLLOW and must pass the config owner/mode policy (owner
//! root or the daemon uid, no group/other write).
//!
//! Rotation: nocved rotates the feed by renaming `events.jsonl` to
//! `events.jsonl.1` and creating a new inode. The tail keeps the fd of every
//! inode it follows, so when the path names a new `(dev, ino)` it first
//! drains the old inode to EOF through that fd, then reads the new file from
//! offset 0. Nothing written before the rename is lost. When `<path>.1` is
//! an inode the tail never opened (two rotations between polls), that
//! generation is queued and read whole too, and a gap is still raised,
//! because a third rotation would be invisible. A shrink is also a gap.
//! A jump in nocved envelope `seq` within one epoch (nocved skipped lines in
//! a burst, or dropped an oversized line) is a gap too. A missing live path
//! (nocved is between its two renames) is no new data, not an error.
//! Gaps are counted (`gaps`) and reported per batch so the daemon can write
//! a `feed_gap` row. nocved envelopes whose `(epoch, seq)` is not newer than
//! the last one seen are skipped, so compaction and overlap do not replay
//! events. A replaced non-envelope file is read from the start.
//!
//! Not covered: offsets live in memory. A daemon restart reads the current
//! file from offset 0 and does not look at `<path>.1`.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::fs::{FilePolicy, check_metadata, open_nofollow};
use cveguard_proto::intel::ingest_line_meta;
use cveguard_proto::model::{GuardEvent, MAX_LINE};

const READ_CHUNK: usize = 64 * 1024;
/// Finished inodes remembered so a stale `<path>.1` is not read twice.
const DONE_KEEP: usize = 4;

type Identity = (u64, u64);

#[derive(Debug)]
struct Source {
    file: File,
    id: Identity,
    offset: u64,
}

#[derive(Debug)]
pub struct Tail {
    cur: Option<Source>,
    next: VecDeque<Source>,
    done: VecDeque<Identity>,
    partial: Vec<u8>,
    gap: bool,
    gaps: u64,
    skipped: u64,
    discard_line: bool,
    replaced: u64,
    last_envelope: Option<(String, u64)>,
}

#[derive(Debug, Default)]
pub struct Batch {
    pub events: Vec<GuardEvent>,
    pub bad_lines: u64,
    /// Gaps raised by this poll (each one is a `feed_gap` row).
    pub gaps: u64,
}

impl Tail {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cur: None,
            next: VecDeque::new(),
            done: VecDeque::new(),
            partial: Vec::new(),
            gap: false,
            gaps: 0,
            skipped: 0,
            discard_line: false,
            replaced: 0,
            last_envelope: None,
        }
    }

    #[must_use]
    pub fn gap(&self) -> bool {
        self.gap
    }

    /// Gaps raised so far: shrinks, and rotations the tail could not follow.
    #[must_use]
    pub fn gaps(&self) -> u64 {
        self.gaps
    }

    #[must_use]
    pub fn offset(&self) -> u64 {
        self.cur.as_ref().map_or(0, |src| src.offset)
    }

    #[must_use]
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// Times the followed path pointed at a new inode.
    #[must_use]
    pub fn replaced(&self) -> u64 {
        self.replaced
    }

    #[must_use]
    pub fn partial_len(&self) -> usize {
        self.partial.len()
    }

    pub fn poll(&mut self, path: &Path, now_ms: i64, max_events: usize) -> Result<Batch, Error> {
        let mut batch = Batch::default();
        self.follow(path, &mut batch)?;
        while let Some(cur) = self.cur.as_mut() {
            let len = cur.file.metadata()?.len();
            let buffered = u64::try_from(self.partial.len())
                .map_err(|_| Error::Invalid("tail rejected".to_owned()))?;
            if len < cur.offset.saturating_add(buffered) {
                cur.offset = len;
                self.raise_gap(&mut batch);
                self.partial.clear();
                self.discard_line = false;
                break;
            }
            let start = cur.offset.saturating_add(buffered);
            let read = read_from(&mut cur.file, start, &mut self.partial)?;
            self.consume(now_ms, max_events, &mut batch);
            if batch.events.len() >= max_events {
                break;
            }
            let drained = start.saturating_add(read) >= len;
            if !drained || self.next.is_empty() {
                break;
            }
            // The old inode is final once the path names a newer one.
            if !self.partial.is_empty() && !self.discard_line {
                batch.bad_lines = batch.bad_lines.saturating_add(1);
            }
            self.partial.clear();
            self.discard_line = false;
            self.finish();
        }
        Ok(batch)
    }

    /// Opens the path on first use, and queues a new inode (plus an unseen
    /// `<path>.1`) when the path was rotated. The old fd stays open.
    fn follow(&mut self, path: &Path, batch: &mut Batch) -> Result<(), Error> {
        let Some((file, id)) = open_checked(path)? else {
            return Ok(());
        };
        let newest = self.next.back().or(self.cur.as_ref()).map(|src| src.id);
        match newest {
            None => {
                self.cur = Some(Source {
                    file,
                    id,
                    offset: 0,
                });
            }
            Some(known) if known == id => {}
            Some(known) => {
                self.replaced = self.replaced.saturating_add(1);
                if let Some((old, old_id)) = open_checked(&rotated(path))?
                    && old_id != known
                    && old_id != id
                    && !self.done.contains(&old_id)
                    && self.cur.as_ref().is_none_or(|src| src.id != old_id)
                    && !self.next.iter().any(|src| src.id == old_id)
                {
                    // `.1` is a generation this tail never opened: the file
                    // rotated at least twice since the last poll.
                    self.raise_gap(batch);
                    self.next.push_back(Source {
                        file: old,
                        id: old_id,
                        offset: 0,
                    });
                }
                self.next.push_back(Source {
                    file,
                    id,
                    offset: 0,
                });
            }
        }
        Ok(())
    }

    fn finish(&mut self) {
        if let Some(old) = self.cur.take() {
            if self.done.len() == DONE_KEEP {
                self.done.pop_front();
            }
            self.done.push_back(old.id);
        }
        self.cur = self.next.pop_front();
    }

    fn raise_gap(&mut self, batch: &mut Batch) {
        self.gap = true;
        self.gaps = self.gaps.saturating_add(1);
        batch.gaps = batch.gaps.saturating_add(1);
    }

    /// True when `pos` is not newer than the last envelope in the same epoch.
    /// A seq that skips ahead in the same epoch raises a gap.
    fn replayed(&mut self, pos: (String, u64), batch: &mut Batch) -> bool {
        if let Some((epoch, seq)) = &self.last_envelope
            && *epoch == pos.0
        {
            if pos.1 <= *seq {
                return true;
            }
            if pos.1 > seq.saturating_add(1) {
                self.raise_gap(batch);
            }
        }
        self.last_envelope = Some(pos);
        false
    }

    fn consume(&mut self, now_ms: i64, max_events: usize, batch: &mut Batch) {
        let mut consumed = 0usize;
        loop {
            if batch.events.len() >= max_events {
                break;
            }
            let rest = &self.partial[consumed..];
            if self.discard_line {
                match rest.iter().position(|byte| *byte == b'\n') {
                    Some(nl) => {
                        consumed += nl + 1;
                        self.discard_line = false;
                    }
                    None => {
                        consumed = self.partial.len();
                        break;
                    }
                }
                continue;
            }
            match rest.iter().position(|byte| *byte == b'\n') {
                None => {
                    if rest.len() > MAX_LINE {
                        self.skipped = self.skipped.saturating_add(1);
                        self.discard_line = true;
                        consumed = self.partial.len();
                    }
                    break;
                }
                Some(nl) => {
                    let line = &rest[..nl];
                    let advance = nl + 1;
                    if line.len() > MAX_LINE {
                        self.skipped = self.skipped.saturating_add(1);
                        consumed += advance;
                        continue;
                    }
                    consumed += advance;
                    let ingested = std::str::from_utf8(line)
                        .map_err(|_| ())
                        .and_then(|text| ingest_line_meta(text).map_err(|_| ()));
                    match ingested {
                        Ok(got) => {
                            if let Some(pos) = got.envelope
                                && self.replayed(pos, batch)
                            {
                                continue;
                            }
                            if let Some(mut event) = got.event {
                                if event.observed_at_ms == 0 {
                                    event.observed_at_ms = now_ms;
                                }
                                batch.events.push(event);
                            }
                        }
                        Err(()) => batch.bad_lines = batch.bad_lines.saturating_add(1),
                    }
                }
            }
        }
        self.partial.drain(..consumed);
        if let Some(cur) = self.cur.as_mut() {
            cur.offset = cur
                .offset
                .saturating_add(u64::try_from(consumed).unwrap_or(0));
        }
    }
}

impl Default for Tail {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// Opens `path` under the feed policy. `None` when it does not exist.
fn open_checked(path: &Path) -> Result<Option<(File, Identity)>, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::Invalid("symlink rejected".to_owned()));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let file = match open_nofollow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let meta = file.metadata()?;
    check_metadata(&meta, FilePolicy::Config)?;
    Ok(Some((file, (meta.dev(), meta.ino()))))
}

/// Appends up to one chunk from `start`; returns the bytes read.
fn read_from(file: &mut File, start: u64, into: &mut Vec<u8>) -> Result<u64, Error> {
    file.seek(SeekFrom::Start(start))?;
    let mut buf = [0u8; READ_CHUNK];
    let n = file.read(&mut buf)?;
    into.extend_from_slice(&buf[..n]);
    u64::try_from(n).map_err(|_| Error::Invalid("tail rejected".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::Kind;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    /// Replace the file with a new inode, as nocved compaction does.
    fn replace(path: &Path, bytes: &[u8]) {
        let staged = path.with_extension("new");
        std::fs::write(&staged, bytes).unwrap();
        std::fs::rename(&staged, path).unwrap();
    }

    fn envelope(seq: u64, exe: &str) -> String {
        let payload = serde_json::json!({
            "observed_at_ms": 1_727_000_000_000_i64,
            "source": "proc",
            "kind": "process.start",
            "pid": 100 + seq,
            "ppid": 1,
            "uid": 0,
            "name": "worker",
            "exe": exe,
            "exe_deleted": false,
            "cmdline": [exe],
            "cwd": "/",
            "start_ticks": 5,
            "started_at_ms": null,
            "container_id": null
        });
        let mut line = serde_json::json!({
            "v": 1,
            "host": "web-1",
            "epoch": "0123456789abcdef0123456789abcdef",
            "seq": seq,
            "prev": "ab".repeat(32),
            "payload": payload.to_string(),
            "mac": "cd".repeat(32),
        })
        .to_string();
        line.push('\n');
        line
    }

    #[test]
    fn does_not_double_read_and_shrink_sets_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let line =
            b"{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/tmp/xmrig\",\"comm\":\"xmrig\"}\n";
        write(&path, line);
        let mut tail = Tail::new();
        let first = tail.poll(&path, 10, 10).unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].kind, Kind::Exec);
        assert_ne!(first.events[0].origin, cveguard_proto::Origin::Ring);
        let second = tail.poll(&path, 10, 10).unwrap();
        assert!(second.events.is_empty());
        assert_eq!(tail.offset(), u64::try_from(line.len()).unwrap());

        let new_line =
            b"{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/bin/new\",\"comm\":\"new\"}\n";
        write(&path, new_line);
        let shrunk = tail.poll(&path, 11, 10).unwrap();
        assert!(shrunk.events.is_empty());
        assert!(tail.gap());
        assert_eq!(tail.offset(), u64::try_from(new_line.len()).unwrap());
        let after = tail.poll(&path, 12, 10).unwrap();
        assert!(after.events.is_empty());
        assert!(tail.gap());

        let mut appended = new_line.to_vec();
        appended.extend_from_slice(
            b"{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/bin/later\",\"comm\":\"later\"}\n",
        );
        write(&path, &appended);
        let later = tail.poll(&path, 13, 10).unwrap();
        assert_eq!(later.events.len(), 1);
        assert_eq!(later.events[0].comm.as_deref(), Some("later"));
        assert!(tail.gap());
    }

    #[test]
    fn oversized_line_advances_and_partial_is_not_double_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut bytes = vec![b'a'; MAX_LINE + 2];
        bytes.push(b'\n');
        bytes.extend_from_slice(
            b"{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/bin/ok\",\"comm\":\"ok\"}",
        );
        write(&path, &bytes);
        let mut tail = Tail::new();
        let batch = tail.poll(&path, 3, 10).unwrap();
        assert!(batch.events.is_empty());
        assert_eq!(tail.skipped(), 1);
        assert!(tail.partial_len() > 0);
        let held = tail.offset();
        let again = tail.poll(&path, 3, 10).unwrap();
        assert!(again.events.is_empty());
        assert_eq!(tail.offset(), held);

        let mut finished = bytes.clone();
        finished.push(b'\n');
        write(&path, &finished);
        let done = tail.poll(&path, 4, 10).unwrap();
        assert_eq!(done.events.len(), 1);
        assert_eq!(done.events[0].comm.as_deref(), Some("ok"));
        let idle = tail.poll(&path, 4, 10).unwrap();
        assert!(idle.events.is_empty());
    }

    #[test]
    fn inode_replacement_restarts_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        write(
            &path,
            b"{\"kind\":\"exec\",\"exe\":\"/bin/a\",\"comm\":\"a\"}\n{\"kind\":\"exec\",\"exe\":\"/bin/b\",\"comm\":\"b\"}\n",
        );
        let mut tail = Tail::new();
        assert_eq!(tail.poll(&path, 1, 10).unwrap().events.len(), 2);
        // New file, longer than the old offset: without (dev, ino) tracking the
        // tail would resume mid-file and miss or garble these lines.
        replace(
            &path,
            b"{\"kind\":\"exec\",\"exe\":\"/bin/cccccccc\",\"comm\":\"c\"}\n{\"kind\":\"exec\",\"exe\":\"/bin/dddddddd\",\"comm\":\"d\"}\n{\"kind\":\"exec\",\"exe\":\"/bin/e\",\"comm\":\"e\"}\n",
        );
        let batch = tail.poll(&path, 2, 10).unwrap();
        let comms: Vec<_> = batch
            .events
            .iter()
            .map(|e| e.comm.clone().unwrap_or_default())
            .collect();
        assert_eq!(comms, vec!["c", "d", "e"]);
        assert_eq!(batch.bad_lines, 0);
        assert_eq!(tail.replaced(), 1);
    }

    #[test]
    fn nocved_compaction_does_not_replay_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let first = format!("{}{}", envelope(1, "/bin/one"), envelope(2, "/bin/two"));
        write(&path, first.as_bytes());
        let mut tail = Tail::new();
        let got = tail.poll(&path, 1, 10).unwrap();
        assert_eq!(got.events.len(), 2);
        assert_eq!(got.events[0].exe.as_deref(), Some("/bin/one"));
        // Compaction: seq 1 acked, seq 2 still queued, seq 3 new; new inode.
        let compacted = format!("{}{}", envelope(2, "/bin/two"), envelope(3, "/tmp/xmrig"));
        replace(&path, compacted.as_bytes());
        let got = tail.poll(&path, 2, 10).unwrap();
        assert_eq!(got.events.len(), 1);
        assert_eq!(got.events[0].exe.as_deref(), Some("/tmp/xmrig"));
        assert_eq!(got.bad_lines, 0);
    }

    #[test]
    fn group_writable_or_foreign_events_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        write(&path, b"{\"kind\":\"exec\",\"exe\":\"/bin/a\"}\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let mut tail = Tail::new();
        let err = tail.poll(&path, 1, 10).unwrap_err();
        assert!(err.to_string().contains("mode rejected"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(tail.poll(&path, 1, 10).unwrap().events.len(), 1);
    }

    /// nocved's feed writer: append, and rotate by renaming the file to
    /// `.1` and renaming a fresh file into place (a new inode).
    struct Feed {
        path: std::path::PathBuf,
        file: File,
    }

    impl Feed {
        fn new(path: &Path) -> Self {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            Self {
                path: path.to_path_buf(),
                file,
            }
        }

        fn append(&mut self, line: &str) {
            use std::io::Write;
            self.file.write_all(line.as_bytes()).unwrap();
        }

        fn rotate(&mut self) {
            std::fs::rename(&self.path, rotated(&self.path)).unwrap();
            let staged = self.path.with_extension("fresh");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&staged)
                .unwrap();
            std::fs::rename(&staged, &self.path).unwrap();
            self.file = file;
        }
    }

    fn seqs(events: &[GuardEvent]) -> Vec<u64> {
        events
            .iter()
            .map(|e| {
                e.exe.as_deref().unwrap()["/bin/w".len()..]
                    .parse::<u64>()
                    .unwrap()
            })
            .collect()
    }

    fn drain(tail: &mut Tail, path: &Path, max: usize, seen: &mut Vec<u64>) -> u64 {
        let mut gaps = 0;
        loop {
            let batch = tail.poll(path, 1, max).unwrap();
            assert_eq!(batch.bad_lines, 0);
            gaps += batch.gaps;
            if batch.events.is_empty() {
                return gaps;
            }
            seen.extend(seqs(&batch.events));
        }
    }

    #[test]
    fn rotation_during_a_write_burst_loses_zero_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut feed = Feed::new(&path);
        let mut tail = Tail::new();
        let mut seen = Vec::new();
        let mut gaps = 0;
        let mut seq = 0u64;
        // The daemon is already following the (empty) feed.
        assert!(tail.poll(&path, 1, 4).unwrap().events.is_empty());
        for round in 0..40u64 {
            // A burst lands, the file rotates, and more lands in the new file,
            // all between two polls; small polls leave a backlog behind.
            for _ in 0..(3 + round % 5) {
                seq += 1;
                feed.append(&envelope(seq, &format!("/bin/w{seq}")));
            }
            feed.rotate();
            for _ in 0..(round % 3) {
                seq += 1;
                feed.append(&envelope(seq, &format!("/bin/w{seq}")));
            }
            let batch = tail.poll(&path, 1, 4).unwrap();
            assert_eq!(batch.bad_lines, 0);
            gaps += batch.gaps;
            seen.extend(seqs(&batch.events));
        }
        gaps += drain(&mut tail, &path, 4, &mut seen);
        assert_eq!(seen, (1..=seq).collect::<Vec<_>>());
        assert_eq!(gaps, 0);
        assert_eq!(tail.gaps(), 0);
        assert!(!tail.gap());
        assert_eq!(tail.replaced(), 40);
    }

    #[test]
    fn double_rotation_between_polls_is_reported_as_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut feed = Feed::new(&path);
        let mut tail = Tail::new();
        let mut seen = Vec::new();
        for seq in 1..=3 {
            feed.append(&envelope(seq, &format!("/bin/w{seq}")));
        }
        seen.extend(seqs(&tail.poll(&path, 1, 100).unwrap().events));
        for seq in 4..=5 {
            feed.append(&envelope(seq, &format!("/bin/w{seq}")));
        }
        feed.rotate();
        for seq in 6..=8 {
            feed.append(&envelope(seq, &format!("/bin/w{seq}")));
        }
        feed.rotate();
        for seq in 9..=10 {
            feed.append(&envelope(seq, &format!("/bin/w{seq}")));
        }
        let gaps = drain(&mut tail, &path, 100, &mut seen);
        assert_eq!(gaps, 1);
        assert_eq!(tail.gaps(), 1);
        assert!(tail.gap());
        // The held fd recovers 4-5 and `.1` recovers 6-8, but a third
        // rotation would be invisible, so the gap still stands.
        assert_eq!(seen, (1..=10).collect::<Vec<_>>());
    }

    #[test]
    fn real_feed_rotation_boundary_is_read_whole() {
        let old = include_str!("../../cveguard-proto/testdata/e2e_rotation_old.jsonl");
        let new = include_str!("../../cveguard-proto/testdata/e2e_rotation_new.jsonl");
        let want: usize = [old, new]
            .iter()
            .flat_map(|body| body.lines())
            .filter(|line| line.contains("process.start"))
            .count();
        assert!(want > 0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut feed = Feed::new(&path);
        let mut tail = Tail::new();
        let lines: Vec<&str> = old.lines().collect();
        let (head, rest) = lines.split_at(lines.len() / 2);
        for line in head {
            feed.append(&format!("{line}\n"));
        }
        let mut got = tail.poll(&path, 1, 1000).unwrap().events.len();
        for line in rest {
            feed.append(&format!("{line}\n"));
        }
        feed.rotate();
        feed.append(new);
        loop {
            let batch = tail.poll(&path, 2, 1000).unwrap();
            assert_eq!(batch.bad_lines, 0);
            assert_eq!(batch.gaps, 0);
            if batch.events.is_empty() {
                break;
            }
            got += batch.events.len();
        }
        assert_eq!(got, want);
    }

    #[test]
    fn seq_jump_is_a_gap_and_missing_live_path_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut feed = Feed::new(&path);
        let mut tail = Tail::new();
        feed.append(&envelope(1, "/bin/w1"));
        feed.append(&envelope(2, "/bin/w2"));
        // nocved skipped 3-5 in a burst.
        feed.append(&envelope(6, "/bin/w6"));
        let batch = tail.poll(&path, 1, 100).unwrap();
        assert_eq!(seqs(&batch.events), vec![1, 2, 6]);
        assert_eq!(batch.gaps, 1);
        feed.append(&envelope(7, "/bin/w7"));
        // Between nocved's two renames the live path is absent.
        std::fs::rename(&path, rotated(&path)).unwrap();
        let batch = tail.poll(&path, 1, 100).unwrap();
        assert_eq!(seqs(&batch.events), vec![7]);
        assert_eq!(batch.gaps, 0);
        assert_eq!(tail.gaps(), 1);
    }
}
