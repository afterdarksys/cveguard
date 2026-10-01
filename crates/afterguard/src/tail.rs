//! JSONL tail. Offset is the first unconsumed byte. A shrink is a gap.
//!
//! Threats: replaying a truncated file would invent a second copy of old
//! intel. A line over the cap is skipped and the offset moves past it so a
//! hostile file cannot stall the daemon on the same bytes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use cveguard_proto::Error;
use cveguard_proto::fs::open_nofollow;
use cveguard_proto::intel::ingest_line;
use cveguard_proto::model::{GuardEvent, MAX_LINE};

const READ_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub struct Tail {
    offset: u64,
    partial: Vec<u8>,
    gap: bool,
    skipped: u64,
    discard_line: bool,
}

#[derive(Debug)]
pub struct Batch {
    pub events: Vec<GuardEvent>,
    pub bad_lines: u64,
}

impl Tail {
    #[must_use]
    pub fn new() -> Self {
        Self {
            offset: 0,
            partial: Vec::new(),
            gap: false,
            skipped: 0,
            discard_line: false,
        }
    }

    #[must_use]
    pub fn gap(&self) -> bool {
        self.gap
    }

    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    #[must_use]
    pub fn partial_len(&self) -> usize {
        self.partial.len()
    }

    pub fn poll(&mut self, path: &Path, now_ms: i64, max_events: usize) -> Result<Batch, Error> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Batch {
                    events: Vec::new(),
                    bad_lines: 0,
                });
            }
            Err(err) => return Err(err.into()),
        };
        if meta.file_type().is_symlink() {
            return Err(Error::Invalid("symlink rejected".to_owned()));
        }
        let len = meta.len();
        let buffered = u64::try_from(self.partial.len())
            .map_err(|_| Error::Invalid("tail rejected".to_owned()))?;
        if len < self.offset.saturating_add(buffered) {
            self.gap = true;
            self.offset = len;
            self.partial.clear();
            self.discard_line = false;
            return Ok(Batch {
                events: Vec::new(),
                bad_lines: 0,
            });
        }
        let mut file = open_nofollow(path)?;
        let start = self.offset.saturating_add(buffered);
        self.read_from(&mut file, start)?;
        Ok(self.consume(now_ms, max_events))
    }

    fn read_from(&mut self, file: &mut File, start: u64) -> Result<(), Error> {
        file.seek(SeekFrom::Start(start))?;
        let mut buf = [0u8; READ_CHUNK];
        let n = file.read(&mut buf)?;
        self.partial.extend_from_slice(&buf[..n]);
        Ok(())
    }

    fn consume(&mut self, now_ms: i64, max_events: usize) -> Batch {
        let mut events = Vec::new();
        let mut bad_lines = 0u64;
        let mut consumed = 0usize;
        loop {
            if events.len() >= max_events {
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
                    match std::str::from_utf8(line) {
                        Ok(text) => match ingest_line(text) {
                            Ok(Some(mut event)) => {
                                if event.observed_at_ms == 0 {
                                    event.observed_at_ms = now_ms;
                                }
                                events.push(event);
                            }
                            Ok(None) => {}
                            Err(_) => bad_lines = bad_lines.saturating_add(1),
                        },
                        Err(_) => bad_lines = bad_lines.saturating_add(1),
                    }
                }
            }
        }
        self.partial.drain(..consumed);
        self.offset = self
            .offset
            .saturating_add(u64::try_from(consumed).unwrap_or(0));
        Batch { events, bad_lines }
    }
}

impl Default for Tail {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::Kind;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
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
}
