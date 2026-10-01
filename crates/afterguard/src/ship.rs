//! `afterguard ship`: sends ledger rows to the local darksignal socket.
//!
//! Each row of `<ledger>.1` then `<ledger>` that comes after the cursor is
//! sent as one frame on its own connection: a u32 little-endian length, then
//! `{"v":1,"tool":"cveguard","host","sent_at_ms","body":<row>}`, at most
//! 64 KiB. darksignal answers one byte:
//!
//! - `0x01` accepted (stored, duplicate, evicted-older, or dropped by the
//!   classifier): advance the cursor.
//! - `0x00` refused, permanent and the producer's fault (a malformed frame or
//!   a field that fails validation): advance the cursor, count `refused`, and
//!   log the row's `{epoch}:{seq}`. The row is lost by design.
//! - `0x02` retry (darksignal could not identify the peer, its queue was
//!   full, or its store failed), any other byte, no byte, a timeout, or an
//!   I/O error: keep the cursor, back off (1 s doubling to 60 s), and send
//!   the same row again. One accepted or refused row resets the backoff.
//!
//! The cursor is the `(epoch, seq)` of the last row handed over, kept in a
//! 0600 file written atomically after every row. The rows to send start after
//! the last row in file order whose epoch matches and whose seq is not past
//! the cursor; with no such row (a new ledger, or both generations newer than
//! the cursor) every row is sent, and a jump past `seq + 1` in the same epoch
//! is counted as `missed`. Delivery is at least once: a crash between the ack
//! and the cursor write, or a lost ack, resends a row. darksignal keys a
//! cveguard row's dedupe hash on the row's `{epoch}:{seq}`, so the resend is
//! acked `0x01` as a duplicate and stored once. Both generations are read under a shared lock on the
//! ledger's `.lock`, so a rotation cannot fall between the two reads.
//!
//! Threats: the cursor file is refused if it is a symlink or not 0600, and a
//! cursor that does not parse stops the shipper rather than resending or
//! skipping the ledger. Rows are copied as written; argv, env, and file
//! contents never enter the ledger. Not covered: this does not authenticate
//! the socket. darksignal authenticates this process by uid and exe, and the
//! socket directory (0750, group `darksignal-producers`) limits who can
//! listen there only as far as the host's root allows.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cveguard_proto::Error;
use cveguard_proto::fs::{self, FilePolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ledger;

/// darksignal `frame::MAX_FRAME`: the JSON after the length prefix.
pub const MAX_FRAME: usize = 64 * 1024;
pub const ACK_ACCEPTED: u8 = 0x01;
pub const ACK_REFUSED: u8 = 0x00;
pub const ACK_RETRY: u8 = 0x02;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(1);
const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(60);
const CURSOR_MAX: usize = 4096;

#[derive(Debug, Clone)]
pub struct ShipConfig {
    pub socket: PathBuf,
    pub host: String,
    pub cursor: PathBuf,
}

/// darksignal's host grammar (`frame::valid_host`): 1..=253 bytes of
/// dot-separated labels, each 1..=63 bytes of `[A-Za-z0-9_-]`, so no empty,
/// leading, or trailing label.
#[must_use]
pub fn valid_host(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub epoch: u64,
    pub seq: u64,
    #[serde(default)]
    pub sent: u64,
    #[serde(default)]
    pub refused: u64,
    #[serde(default)]
    pub missed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pass {
    pub sent: u64,
    pub refused: u64,
    /// The socket failed; the cursor stayed and the next pass waits.
    pub failed: bool,
}

pub struct Shipper {
    ledger: PathBuf,
    cfg: ShipConfig,
    cursor: Cursor,
    backoff: Duration,
    /// Passes that ended on a retry ack, unknown ack, or socket error, since
    /// this process started (not kept in the cursor file).
    retried: u64,
    last_error: Option<String>,
    last_error_at_ms: Option<i64>,
}

struct Row {
    epoch: u64,
    seq: u64,
    body: Value,
}

impl Shipper {
    pub fn new(ledger: PathBuf, cfg: ShipConfig) -> Result<Self, Error> {
        let cursor = load_cursor(&cfg.cursor)?;
        Ok(Self {
            ledger,
            cfg,
            cursor,
            backoff: Duration::ZERO,
            retried: 0,
            last_error: None,
            last_error_at_ms: None,
        })
    }

    /// Records a failure for the status file. `message` must not carry row
    /// contents.
    pub fn note_error(&mut self, message: String, now_ms: i64) {
        self.last_error = Some(message);
        self.last_error_at_ms = Some(now_ms);
    }

    /// The `ship` status payload (envelope added by `status::write`).
    #[must_use]
    pub fn status_payload(&self) -> Value {
        serde_json::json!({
            "daemon": "ship",
            "sent": self.cursor.sent,
            "refused": self.cursor.refused,
            "missed": self.cursor.missed,
            "retried": self.retried,
            "cursor": {"epoch": self.cursor.epoch, "seq": self.cursor.seq},
            "backoff_ms": u64::try_from(self.backoff.as_millis()).unwrap_or(u64::MAX),
            "last_error": self.last_error,
            "last_error_at_ms": self.last_error_at_ms,
        })
    }

    /// Writes `<cursor>.status.json`.
    pub fn write_status(&self, now_ms: i64) -> Result<(), Error> {
        crate::status::write(
            &crate::status::ship_path(&self.cfg.cursor),
            self.status_payload(),
            now_ms,
        )
    }

    #[must_use]
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// How long to wait before the next pass.
    #[must_use]
    pub fn wait(&self) -> Duration {
        if self.backoff.is_zero() {
            IDLE
        } else {
            self.backoff
        }
    }

    /// Sends every row after the cursor, stopping at the first socket error.
    pub fn pass(&mut self, now_ms: i64) -> Result<Pass, Error> {
        let rows = self.pending()?;
        let mut pass = Pass::default();
        for row in rows {
            let frame = frame(&self.cfg.host, now_ms, &row.body)?;
            let ack = match frame {
                Some(bytes) => match send(&self.cfg.socket, &bytes) {
                    Ok(ACK_ACCEPTED) => ACK_ACCEPTED,
                    Ok(ACK_REFUSED) => ACK_REFUSED,
                    // ACK_RETRY, an unknown byte, no byte, or an I/O error:
                    // the row was not taken; keep the cursor and resend it.
                    other => {
                        let why = match other {
                            Ok(ACK_RETRY) => "darksignal answered retry".to_owned(),
                            Ok(byte) => format!("darksignal sent unknown ack 0x{byte:02x}"),
                            Err(err) => format!("socket: {}", err.kind()),
                        };
                        self.note_error(why, now_ms);
                        self.retried = self.retried.saturating_add(1);
                        pass.failed = true;
                        self.backoff = next_backoff(self.backoff);
                        return Ok(pass);
                    }
                },
                // Over 64 KiB can never be accepted: count it as refused.
                None => ACK_REFUSED,
            };
            if ack == ACK_REFUSED {
                self.note_error(
                    format!("darksignal refused row {}:{}", row.epoch, row.seq),
                    now_ms,
                );
                eprintln!(
                    "afterguard: ship: darksignal REFUSED row {}:{}; it is lost, check the row",
                    row.epoch, row.seq
                );
            }
            if row.epoch == self.cursor.epoch && row.seq > self.cursor.seq.saturating_add(1) {
                self.cursor.missed = self
                    .cursor
                    .missed
                    .saturating_add(row.seq - self.cursor.seq - 1);
            }
            self.cursor.epoch = row.epoch;
            self.cursor.seq = row.seq;
            if ack == ACK_ACCEPTED {
                self.cursor.sent = self.cursor.sent.saturating_add(1);
                pass.sent = pass.sent.saturating_add(1);
            } else {
                self.cursor.refused = self.cursor.refused.saturating_add(1);
                pass.refused = pass.refused.saturating_add(1);
            }
            save_cursor(&self.cfg.cursor, &self.cursor)?;
        }
        self.backoff = Duration::ZERO;
        Ok(pass)
    }

    fn pending(&self) -> Result<Vec<Row>, Error> {
        let (old, cur) = ledger::read_generations(&self.ledger)?;
        let mut rows = Vec::new();
        for body in [old, cur].into_iter().flatten() {
            for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                rows.push(parse_row(line)?);
            }
        }
        let start = rows
            .iter()
            .rposition(|r| r.epoch == self.cursor.epoch && r.seq <= self.cursor.seq)
            .map_or(0, |i| i + 1);
        // A fresh cursor names no row; everything is new.
        Ok(rows.split_off(start))
    }
}

fn parse_row(line: &[u8]) -> Result<Row, Error> {
    let body: Value = serde_json::from_slice(line)
        .map_err(|_| Error::Schema("ledger row rejected".to_owned()))?;
    let field = |key: &str| body.get(key).and_then(Value::as_u64);
    let (Some(seq), true) = (field("seq"), body.is_object()) else {
        return Err(Error::Schema("ledger row rejected".to_owned()));
    };
    Ok(Row {
        epoch: field("epoch").unwrap_or(0),
        seq,
        body,
    })
}

/// The length-prefixed frame, or `None` when the JSON is over `MAX_FRAME`.
pub fn frame(host: &str, now_ms: i64, body: &Value) -> Result<Option<Vec<u8>>, Error> {
    let envelope = serde_json::json!({
        "v": 1,
        "tool": "cveguard",
        "host": host,
        "sent_at_ms": now_ms,
        "body": body,
    });
    let json =
        serde_json::to_vec(&envelope).map_err(|_| Error::Schema("json rejected".to_owned()))?;
    if json.len() > MAX_FRAME {
        return Ok(None);
    }
    let len = u32::try_from(json.len()).map_err(|_| Error::Schema("frame rejected".to_owned()))?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);
    Ok(Some(out))
}

/// One frame per connection; returns darksignal's ack byte.
fn send(socket: &Path, frame: &[u8]) -> std::io::Result<u8> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    write_and_read_ack(&mut stream, frame)
}

/// darksignal frames are length-prefixed, so it can read the frame, ack and
/// shut the connection down before our `shutdown(Write)`. BSD then answers
/// that shutdown with `ENOTCONN` while the ack byte is still readable; that
/// error must not discard the ack, or an accepted row is resent and a refused
/// row is retried instead of skipped.
fn write_and_read_ack(stream: &mut UnixStream, frame: &[u8]) -> std::io::Result<u8> {
    stream.write_all(frame)?;
    match stream.shutdown(std::net::Shutdown::Write) {
        Err(e) if e.kind() != std::io::ErrorKind::NotConnected => return Err(e),
        _ => {}
    }
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack)?;
    Ok(ack[0])
}

fn next_backoff(cur: Duration) -> Duration {
    if cur.is_zero() {
        BACKOFF_BASE
    } else {
        cur.saturating_mul(2).min(BACKOFF_CAP)
    }
}

fn load_cursor(path: &Path) -> Result<Cursor, Error> {
    match fs::read_trusted(path, CURSOR_MAX, FilePolicy::Secret0600) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| Error::Schema("cursor rejected".to_owned()))
        }
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(Cursor::default()),
        Err(err) => Err(err),
    }
}

fn save_cursor(path: &Path, cursor: &Cursor) -> Result<(), Error> {
    let bytes =
        serde_json::to_vec(cursor).map_err(|_| Error::Schema("json rejected".to_owned()))?;
    fs::write_atomic_0600(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use cveguard_proto::model::{Action, DECISION_SCHEMA_VERSION, Decision, Origin, Outcome};
    use cveguard_proto::model::{Reason, Severity};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    fn row(pid: u32) -> Decision {
        Decision {
            schema_version: DECISION_SCHEMA_VERSION,
            epoch: None,
            seq: 0,
            prev: String::new(),
            observed_at_ms: 1_790_869_757_751,
            action: Action::Alert,
            outcome: Outcome::Shadow,
            reason: Reason::ImportedIntel,
            origin: Origin::Nocved,
            severity: Severity::High,
            plan: None,
            pid: Some(pid),
            rule_id: Some("masq-kcompactd".to_owned()),
            source_rule_id: Some("proc.masquerade".to_owned()),
            cve: None,
            subject: Some("kcompactd0".to_owned()),
            comm_invalid: false,
            args_truncated: pid.is_multiple_of(2),
            ancestors: Vec::new(),
        }
    }

    /// Fake darksignal: answers each connection with the next scripted ack
    /// and reports the frame it read. `None` closes without an ack.
    fn server(sock: &Path, acks: Vec<Option<u8>>) -> mpsc::Receiver<Value> {
        let listener = UnixListener::bind(sock).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for ack in acks {
                let (mut stream, _) = listener.accept().unwrap();
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).unwrap();
                let n = usize::try_from(u32::from_le_bytes(len)).unwrap();
                assert!(n <= MAX_FRAME);
                let mut body = vec![0u8; n];
                stream.read_exact(&mut body).unwrap();
                tx.send(serde_json::from_slice(&body).unwrap()).unwrap();
                if let Some(byte) = ack {
                    stream.write_all(&[byte]).unwrap();
                }
            }
        });
        rx
    }

    struct Fix {
        dir: tempfile::TempDir,
        _sock_dir: tempfile::TempDir,
        ledger: PathBuf,
        cfg: ShipConfig,
    }

    fn fix(ledger_max: usize) -> (Fix, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        // AF_UNIX paths are capped near 104 bytes; keep the socket short.
        let sock_dir = tempfile::Builder::new()
            .prefix("cgship")
            .tempdir_in("/tmp")
            .unwrap();
        let ledger = dir.path().join("decisions.jsonl");
        let cfg = ShipConfig {
            socket: sock_dir.path().join("ds.sock"),
            host: "e2e-host1".to_owned(),
            cursor: dir.path().join("ship.cursor"),
        };
        let writer = Ledger::new(ledger.clone(), ledger_max).unwrap();
        (
            Fix {
                dir,
                _sock_dir: sock_dir,
                ledger,
                cfg,
            },
            writer,
        )
    }

    fn seqs(frames: &[Value]) -> Vec<u64> {
        frames
            .iter()
            .map(|f| f["body"]["seq"].as_u64().unwrap())
            .collect()
    }

    #[test]
    fn frames_rows_and_cursor_survives_restart_and_rotation() {
        let row_len = cveguard_proto::chain::chain_line(
            &row(8128),
            &cveguard_proto::chain::ChainHead {
                epoch: cveguard_proto::chain::MAX_EPOCH,
                seq: 99,
                head: cveguard_proto::chain::GENESIS.to_owned(),
            },
        )
        .unwrap()
        .len()
            + 1;
        let (f, mut writer) = fix(row_len * 3);
        for pid in 1..=2 {
            writer.append(&row(pid)).unwrap();
        }
        let rx = server(&f.cfg.socket, vec![Some(1); 5]);
        let mut shipper = Shipper::new(f.ledger.clone(), f.cfg.clone()).unwrap();
        let pass = shipper.pass(1_790_869_800_000).unwrap();
        assert_eq!(
            pass,
            Pass {
                sent: 2,
                refused: 0,
                failed: false
            }
        );
        let first: Vec<Value> = rx.try_iter().collect();
        assert_eq!(seqs(&first), vec![1, 2]);
        let frame = &first[1];
        assert_eq!(frame["v"], 1);
        assert_eq!(frame["tool"], "cveguard");
        assert_eq!(frame["host"], "e2e-host1");
        assert_eq!(frame["sent_at_ms"], 1_790_869_800_000_i64);
        assert_eq!(frame["body"]["severity"], "high");
        assert_eq!(frame["body"]["source_rule_id"], "proc.masquerade");
        assert_eq!(frame["body"]["epoch"], writer.stats().head.epoch);
        let mode = std::fs::metadata(&f.cfg.cursor)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        // Restart; three more rows rotate the ledger (3 rows per file), so
        // the cursor row now lives in `.1`.
        drop(shipper);
        for pid in 3..=5 {
            writer.append(&row(pid)).unwrap();
        }
        assert!(writer.stats().rotations >= 1);
        assert!(ledger::rotated(&f.ledger).exists());
        let mut again = Shipper::new(f.ledger.clone(), f.cfg.clone()).unwrap();
        assert_eq!(again.cursor().seq, 2);
        let pass = again.pass(2).unwrap();
        assert_eq!(pass.sent, 3);
        let second: Vec<Value> = rx.try_iter().collect();
        assert_eq!(seqs(&second), vec![3, 4, 5]);
        assert_eq!(again.pass(3).unwrap(), Pass::default());
        assert_eq!(again.cursor().missed, 0);
        drop(f.dir);
    }

    #[test]
    fn refusal_advances_and_socket_error_keeps_the_cursor() {
        let (f, mut writer) = fix(1024 * 1024);
        for pid in 1..=3 {
            writer.append(&row(pid)).unwrap();
        }
        // No socket yet: error, cursor stays, backoff starts and doubles.
        let mut shipper = Shipper::new(f.ledger.clone(), f.cfg.clone()).unwrap();
        let pass = shipper.pass(1).unwrap();
        assert!(pass.failed);
        assert_eq!(shipper.cursor().seq, 0);
        assert_eq!(shipper.wait(), Duration::from_secs(1));
        assert!(shipper.pass(1).unwrap().failed);
        assert_eq!(shipper.wait(), Duration::from_secs(2));
        assert!(!f.cfg.cursor.exists());

        // Accept, refuse, then close without an ack.
        let rx = server(&f.cfg.socket, vec![Some(1), Some(0), None]);
        let pass = shipper.pass(2).unwrap();
        assert_eq!(
            pass,
            Pass {
                sent: 1,
                refused: 1,
                failed: true
            }
        );
        assert_eq!(shipper.cursor().seq, 2);
        assert_eq!(shipper.cursor().refused, 1);
        assert_eq!(seqs(&rx.iter().take(3).collect::<Vec<_>>()), vec![1, 2, 3]);
        let saved = load_cursor(&f.cfg.cursor).unwrap();
        assert_eq!((saved.seq, saved.sent, saved.refused), (2, 1, 1));

        // Row 3 goes again once darksignal is back.
        std::fs::remove_file(&f.cfg.socket).unwrap();
        let rx = server(&f.cfg.socket, vec![Some(1)]);
        assert_eq!(shipper.pass(3).unwrap().sent, 1);
        assert_eq!(seqs(&rx.iter().take(1).collect::<Vec<_>>()), vec![3]);
        assert_eq!(shipper.wait(), Duration::from_secs(1));
    }

    #[test]
    fn retry_and_unknown_acks_keep_the_cursor_and_resend_the_row() {
        let (f, mut writer) = fix(1024 * 1024);
        for pid in 1..=3 {
            writer.append(&row(pid)).unwrap();
        }
        let rx = server(
            &f.cfg.socket,
            vec![Some(ACK_RETRY), Some(0x7f), Some(1), Some(1), Some(1)],
        );
        let mut shipper = Shipper::new(f.ledger.clone(), f.cfg.clone()).unwrap();
        // 0x02: transient; nothing advances and nothing is counted.
        let pass = shipper.pass(1).unwrap();
        assert_eq!(
            pass,
            Pass {
                sent: 0,
                refused: 0,
                failed: true
            }
        );
        assert_eq!(shipper.cursor(), Cursor::default());
        assert!(!f.cfg.cursor.exists());
        assert_eq!(shipper.wait(), Duration::from_secs(1));
        // An unknown byte is treated exactly like 0x02.
        assert!(shipper.pass(2).unwrap().failed);
        assert_eq!(shipper.cursor(), Cursor::default());
        assert_eq!(shipper.wait(), Duration::from_secs(2));
        // 0x01 advances; the backoff resets.
        let pass = shipper.pass(3).unwrap();
        assert_eq!(pass.sent, 3);
        assert_eq!(shipper.cursor().seq, 3);
        assert_eq!(shipper.cursor().refused, 0);
        assert_eq!(shipper.wait(), Duration::from_secs(1));
        // Row 1 went out three times: the retried row is the same row.
        let frames: Vec<Value> = rx.iter().take(5).collect();
        assert_eq!(seqs(&frames), vec![1, 1, 1, 2, 3]);
        assert_eq!(frames[0]["body"], frames[2]["body"]);
    }

    #[test]
    fn backoff_is_capped_at_sixty_seconds() {
        let mut cur = Duration::ZERO;
        for _ in 0..20 {
            cur = next_backoff(cur);
        }
        assert_eq!(cur, Duration::from_secs(60));
    }

    #[test]
    fn hostile_cursor_and_oversize_frames_fail_closed() {
        let (f, _writer) = fix(1024 * 1024);
        std::fs::write(&f.cfg.cursor, br#"{"epoch":1,"seq":2}"#).unwrap();
        std::fs::set_permissions(&f.cfg.cursor, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Shipper::new(f.ledger.clone(), f.cfg.clone()).err().unwrap();
        assert!(err.to_string().contains("mode rejected"));
        std::fs::set_permissions(&f.cfg.cursor, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&f.cfg.cursor, b"{not json").unwrap();
        assert!(Shipper::new(f.ledger.clone(), f.cfg.clone()).is_err());
        std::fs::remove_file(&f.cfg.cursor).unwrap();
        std::os::unix::fs::symlink(&f.ledger, &f.cfg.cursor).unwrap();
        assert!(Shipper::new(f.ledger.clone(), f.cfg.clone()).is_err());

        let big = serde_json::json!({"seq": 1, "pad": "x".repeat(MAX_FRAME)});
        assert!(frame("h", 1, &big).unwrap().is_none());
        let ok = frame("h", 1, &serde_json::json!({"seq": 1}))
            .unwrap()
            .unwrap();
        let n = u32::from_le_bytes(ok[..4].try_into().unwrap());
        assert_eq!(usize::try_from(n).unwrap(), ok.len() - 4);
        assert!(valid_host("ns2"));
        assert!(valid_host("ns2.after-dark_systems.example"));
        assert!(valid_host(
            &[
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            ]
            .join(".")
        ));
        assert!(!valid_host(
            &[
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(62)
            ]
            .join(".")
        ));
        assert!(!valid_host(&"a".repeat(64)));
        assert!(!valid_host(".ns2"));
        assert!(!valid_host("ns2."));
        assert!(!valid_host("ns2..x"));
        assert!(!valid_host(""));
    }

    #[test]
    fn new_epoch_after_a_ledger_reset_is_sent_from_the_start() {
        let (f, mut writer) = fix(1024 * 1024);
        writer.append(&row(1)).unwrap();
        let rx = server(&f.cfg.socket, vec![Some(1); 2]);
        let mut shipper = Shipper::new(f.ledger.clone(), f.cfg.clone()).unwrap();
        assert_eq!(shipper.pass(1).unwrap().sent, 1);
        std::fs::remove_file(&f.ledger).unwrap();
        writer.append(&row(2)).unwrap();
        assert_eq!(shipper.pass(2).unwrap().sent, 1);
        let frames: Vec<Value> = rx.iter().take(2).collect();
        assert_eq!(seqs(&frames), vec![1, 1]);
        assert_ne!(frames[0]["body"]["epoch"], frames[1]["body"]["epoch"]);
    }

    #[test]
    fn ack_survives_peer_closing_before_our_shutdown() {
        for want in [ACK_ACCEPTED, ACK_REFUSED, ACK_RETRY] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            // The whole frame is already written; the peer reads it, acks and
            // shuts down before write_and_read_ack reaches shutdown(Write).
            client.write_all(&[7u8; 16]).unwrap();
            let peer = std::thread::spawn(move || {
                let mut got = [0u8; 16];
                server.read_exact(&mut got).unwrap();
                server.write_all(&[want]).unwrap();
                server.shutdown(std::net::Shutdown::Both).unwrap();
            });
            peer.join().unwrap();
            assert_eq!(write_and_read_ack(&mut client, &[]).unwrap(), want);
        }
    }
}
