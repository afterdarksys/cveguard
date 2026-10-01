//! Decision ledger hash chain.
//!
//! Threats: an attacker with write access to the ledger edits, deletes, or
//! truncates rows to hide a decision. Each row carries `seq` (previous + 1)
//! and `prev` (SHA-256 hex of the previous row's bytes). An edited or deleted
//! row breaks the next link. Truncation of the newest rows is caught by the
//! head (`seq`, hash) the daemon writes to `status.json`. Hashes are compared
//! in constant time.
//!
//! Not covered: an attacker who can rewrite the ledger *and* `status.json`
//! can forge a consistent chain, because nothing here is keyed or signed. An
//! edit to the newest row is only caught once `status.json` names that row.
//! When two rotations happen, the oldest generation is gone and the first
//! surviving row is accepted as the anchor.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, schema};
use crate::model::Decision;

/// `prev` of the first row ever written.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Largest epoch: 2^53 - 1, so a JavaScript consumer reads it exactly.
pub const MAX_EPOCH: u64 = (1 << 53) - 1;

/// Last row the writer appended: chain epoch, sequence number, and SHA-256
/// hex of its bytes. `epoch` 0 means the chain has no epoch yet (genesis, or
/// a schema 2 row); the writer then draws one with `new_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainHead {
    pub epoch: u64,
    pub seq: u64,
    pub head: String,
}

impl ChainHead {
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            epoch: 0,
            seq: 0,
            head: GENESIS.to_owned(),
        }
    }
}

/// A fresh chain epoch from the OS CSPRNG, in 1..=`MAX_EPOCH`. It names the
/// chain (with `seq`, the dedupe key `{epoch}:{seq}`); it is not a secret.
pub fn new_epoch() -> Result<u64, Error> {
    loop {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).map_err(|_| Error::Invalid("epoch rejected".to_owned()))?;
        let epoch = u64::from_le_bytes(raw) & MAX_EPOCH;
        if epoch != 0 {
            return Ok(epoch);
        }
    }
}

#[must_use]
pub fn line_hash(line: &[u8]) -> String {
    hex::encode(Sha256::digest(line))
}

/// Serializes `decision` as the row after `head`, without the newline.
pub fn chain_line(decision: &Decision, head: &ChainHead) -> Result<Vec<u8>, Error> {
    let mut row = decision.clone();
    row.seq = head
        .seq
        .checked_add(1)
        .ok_or_else(|| schema("seq overflow"))?;
    row.prev.clone_from(&head.head);
    row.epoch = (head.epoch != 0).then_some(head.epoch);
    serde_json::to_vec(&row).map_err(|_| schema("json rejected"))
}

#[derive(Deserialize)]
struct Link {
    #[serde(default)]
    epoch: u64,
    seq: u64,
    prev: String,
}

/// Parses one row's link fields. Returns `None` for anything malformed.
#[must_use]
pub fn row_link(line: &[u8]) -> Option<(u64, String)> {
    let link: Link = serde_json::from_slice(line).ok()?;
    if !is_hash(&link.prev) {
        return None;
    }
    Some((link.seq, link.prev))
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Constant-time equality of two 64-hex digests. Anything malformed is unequal.
#[must_use]
pub fn hash_eq(a: &str, b: &str) -> bool {
    if !is_hash(a) || !is_hash(b) {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

/// Splits a ledger body into rows. A body that does not end in a newline, or
/// that has an empty row, is malformed (`None`).
fn rows(body: &[u8]) -> Option<Vec<&[u8]>> {
    if body.is_empty() {
        return Some(Vec::new());
    }
    let inner = body.strip_suffix(b"\n")?;
    let out: Vec<&[u8]> = inner.split(|b| *b == b'\n').collect();
    if out.iter().any(|row| row.is_empty()) {
        return None;
    }
    Some(out)
}

/// Verifies the rotated generation (if any) followed by the current ledger,
/// and, when `expect` names a row, that the row's hash matches.
///
/// With no rotated file the first row must be `seq` 1 with `prev` GENESIS.
/// With a rotated file, its first row is the anchor.
#[must_use]
pub fn verify(rotated: Option<&[u8]>, current: &[u8], expect: Option<&ChainHead>) -> bool {
    let mut all: Vec<&[u8]> = Vec::new();
    let anchored = match rotated {
        Some(body) => {
            let Some(r) = rows(body) else {
                return false;
            };
            let some = !r.is_empty();
            all.extend(r);
            some
        }
        None => false,
    };
    let Some(cur) = rows(current) else {
        return false;
    };
    all.extend(cur);
    let mut last: Option<(u64, String)> = None;
    let mut found_expect = false;
    for row in &all {
        let Some((seq, prev)) = row_link(row) else {
            return false;
        };
        match &last {
            None => {
                if !anchored && (seq != 1 || !hash_eq(&prev, GENESIS)) {
                    return false;
                }
            }
            Some((last_seq, last_hash)) => {
                if Some(seq) != last_seq.checked_add(1) || !hash_eq(&prev, last_hash) {
                    return false;
                }
            }
        }
        let hash = line_hash(row);
        if let Some(want) = expect
            && want.seq == seq
        {
            if !hash_eq(&hash, &want.head) {
                return false;
            }
            found_expect = true;
        }
        last = Some((seq, hash));
    }
    match expect {
        Some(want) if want.seq > 0 && !found_expect => match (&last, all.first()) {
            // The named row is older than the oldest surviving row.
            (Some(_), Some(first)) => row_link(first).is_some_and(|(s, _)| want.seq < s),
            _ => false,
        },
        _ => true,
    }
}

/// Head of the last complete row in `tail`, which must end in a newline.
pub fn head_of(tail: &[u8]) -> Result<ChainHead, Error> {
    let inner = tail
        .strip_suffix(b"\n")
        .ok_or_else(|| schema("ledger tail rejected"))?;
    let row = match inner.iter().rposition(|b| *b == b'\n') {
        Some(nl) => &inner[nl + 1..],
        None => inner,
    };
    let link: Link = serde_json::from_slice(row).map_err(|_| schema("ledger tail rejected"))?;
    if !is_hash(&link.prev) || link.epoch > MAX_EPOCH {
        return Err(schema("ledger tail rejected"));
    }
    Ok(ChainHead {
        epoch: link.epoch,
        seq: link.seq,
        head: line_hash(row),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, DECISION_SCHEMA_VERSION, Origin, Outcome, Reason};

    fn decision(n: i64) -> Decision {
        Decision {
            schema_version: DECISION_SCHEMA_VERSION,
            epoch: None,
            seq: 0,
            prev: String::new(),
            observed_at_ms: n,
            action: Action::Alert,
            outcome: Outcome::Shadow,
            reason: Reason::PolicyShadow,
            origin: Origin::Nocved,
            severity: crate::model::Severity::Medium,
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

    fn build(n: i64) -> (Vec<Vec<u8>>, ChainHead) {
        let mut head = ChainHead::genesis();
        head.epoch = 77;
        let mut out = Vec::new();
        for i in 0..n {
            let line = chain_line(&decision(i), &head).unwrap();
            head = ChainHead {
                epoch: head.epoch,
                seq: head.seq + 1,
                head: line_hash(&line),
            };
            out.push(line);
        }
        (out, head)
    }

    fn join(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in rows {
            out.extend_from_slice(r);
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn intact_chain_and_head_verify() {
        let (rows, head) = build(4);
        assert!(verify(None, &join(&rows), Some(&head)));
        assert!(verify(None, b"", None));
        assert_eq!(head_of(&join(&rows)).unwrap(), head);
        let (older, _) = build(2);
        // Rotated generation then current continues the chain.
        assert!(verify(
            Some(&join(&rows[..2])),
            &join(&rows[2..]),
            Some(&head)
        ));
        assert!(verify(None, &join(&older), None));
    }

    #[test]
    fn edited_deleted_truncated_and_headless_rows_fail() {
        let (rows, head) = build(4);
        let mut edited = rows.clone();
        edited[1] = String::from_utf8(edited[1].clone())
            .unwrap()
            .replace("xmrig", "bash")
            .into_bytes();
        assert!(!verify(None, &join(&edited), None));

        let mut deleted = rows.clone();
        deleted.remove(1);
        assert!(!verify(None, &join(&deleted), None));

        // Truncated: the last row is gone; the chain is internally fine but
        // status.json names a row that no longer exists.
        assert!(verify(None, &join(&rows[..3]), None));
        assert!(!verify(None, &join(&rows[..3]), Some(&head)));
        assert!(!verify(None, b"", Some(&head)));

        // Leading rows removed with no rotated file: seq 1 / genesis missing.
        assert!(!verify(None, &join(&rows[1..]), None));
        // Rotated file deleted after a rotation.
        assert!(!verify(None, &join(&rows[2..]), Some(&head)));

        // Partial trailing row.
        let mut partial = join(&rows);
        partial.pop();
        assert!(!verify(None, &partial, None));

        // Last row edited is caught by the head.
        let mut last = rows.clone();
        last[3] = String::from_utf8(last[3].clone())
            .unwrap()
            .replace("xmrig", "bash")
            .into_bytes();
        assert!(!verify(None, &join(&last), Some(&head)));
        assert!(!hash_eq("zz", GENESIS));
    }

    #[test]
    fn epoch_is_written_and_read_back() {
        let (rows, head) = build(2);
        assert_eq!(head.epoch, 77);
        let text = String::from_utf8(rows[0].clone()).unwrap();
        assert!(text.starts_with(r#"{"schema_version":3,"epoch":77,"seq":1,"#));
        assert_eq!(head_of(&join(&rows)).unwrap().epoch, 77);
        // A schema 2 row read back keeps no epoch; none is invented.
        let old = br#"{"schema_version":2,"seq":4,"prev":"0000000000000000000000000000000000000000000000000000000000000000","observed_at_ms":1,"action":"alert","outcome":"shadow","reason":"matched","origin":"ring"}"#;
        let row: Decision = serde_json::from_slice(old).unwrap();
        assert_eq!(row.epoch, None);
        assert!(!serde_json::to_string(&row).unwrap().contains("epoch"));
        let epoch = new_epoch().unwrap();
        assert!((1..=MAX_EPOCH).contains(&epoch));
        assert_ne!(epoch, new_epoch().unwrap());
    }
}
