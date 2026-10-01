//! Userspace stand-in for a single-consumer ring.
//!
//! Threats: two consumers would split a kernel ring and hide events from the
//! daemon. This simulator allows one attach. A full ring drops the newest
//! record, keeps the oldest, and counts the loss. Payload bytes are untrusted.

use std::collections::VecDeque;

use serde_json::Value;

use crate::error::{Error, schema};
use crate::model::{
    GuardEvent, Kind, MAX_RING_PAYLOAD, Origin, SCHEMA_VERSION, check_remote, check_text,
    filter_args, valid_subject,
};

pub const MAGIC: u32 = 0x3152_4743;
pub const VERSION: u16 = 1;
pub const KIND_EXEC: u16 = 1;
pub const KIND_EXIT: u16 = 2;
pub const KIND_CONNECT: u16 = 3;
pub const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: u16,
    pub observed_at_ms: i64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct SharedRing {
    cap: usize,
    slots: VecDeque<Record>,
    lost: u64,
    consumer: bool,
}

impl SharedRing {
    pub fn new(cap: usize) -> Result<Self, Error> {
        if !(1..=4096).contains(&cap) {
            return Err(crate::error::invalid("ring cap rejected"));
        }
        Ok(Self {
            cap,
            slots: VecDeque::new(),
            lost: 0,
            consumer: false,
        })
    }

    pub fn attach(&mut self) -> Result<(), Error> {
        if self.consumer {
            return Err(Error::Busy);
        }
        self.consumer = true;
        Ok(())
    }

    pub fn push(&mut self, rec: Record) -> Result<(), Error> {
        if self.slots.len() >= self.cap {
            self.lost = self.lost.saturating_add(1);
            return Err(Error::Full);
        }
        self.slots.push_back(rec);
        Ok(())
    }

    #[must_use]
    pub fn pop(&mut self) -> Option<Record> {
        self.slots.pop_front()
    }

    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

pub fn encode(rec: &Record) -> Result<Vec<u8>, Error> {
    if rec.payload.len() > MAX_RING_PAYLOAD {
        return Err(schema("payload too large"));
    }
    if !matches!(rec.kind, KIND_EXEC | KIND_EXIT | KIND_CONNECT) {
        return Err(schema("kind rejected"));
    }
    let _ = std::str::from_utf8(&rec.payload).map_err(|_| schema("utf-8 rejected"))?;
    let len = u16::try_from(rec.payload.len()).map_err(|_| schema("payload too large"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + rec.payload.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&rec.kind.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&rec.observed_at_ms.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&rec.payload);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Record, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(schema("payload too large"));
    }
    let magic = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let version = u16::from_le_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let kind = u16::from_le_bytes(
        bytes[6..8]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let payload_len = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let flags = u16::from_le_bytes(
        bytes[10..12]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let observed_at_ms = i64::from_le_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    let reserved = u32::from_le_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| schema("payload rejected"))?,
    );
    if magic != MAGIC || version != VERSION || flags != 0 || reserved != 0 {
        return Err(schema("payload rejected"));
    }
    let payload_len = usize::from(payload_len);
    if payload_len > MAX_RING_PAYLOAD || bytes.len() != HEADER_LEN + payload_len {
        return Err(schema("payload rejected"));
    }
    let payload = bytes[HEADER_LEN..].to_vec();
    let _ = std::str::from_utf8(&payload).map_err(|_| schema("utf-8 rejected"))?;
    Ok(Record {
        kind,
        observed_at_ms,
        payload,
    })
}

fn opt_u32(v: &Value, key: &str) -> Result<Option<u32>, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let raw = n.as_u64().ok_or_else(|| schema("field rejected"))?;
            u32::try_from(raw)
                .map(Some)
                .map_err(|_| schema("field rejected"))
        }
        _ => Err(schema("field rejected")),
    }
}

fn opt_string(v: &Value, key: &str) -> Result<Option<String>, Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => {
            check_text(s)?;
            Ok(Some(s.clone()))
        }
        _ => Err(schema("field rejected")),
    }
}

fn args_of(v: &Value) -> Result<Vec<String>, Error> {
    match v.get("args") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => return Err(schema("field rejected")),
                }
            }
            filter_args(out)
        }
        _ => Err(schema("field rejected")),
    }
}

/// The daemon clock is `now_ms`. The probe timestamp stays in the record and
/// is not used for the budget.
pub fn record_to_event(rec: &Record, now_ms: i64) -> Result<GuardEvent, Error> {
    if rec.payload.len() > MAX_RING_PAYLOAD {
        return Err(schema("payload too large"));
    }
    let text = std::str::from_utf8(&rec.payload).map_err(|_| schema("utf-8 rejected"))?;
    let v: Value = serde_json::from_str(text).map_err(|_| schema("json rejected"))?;
    let kind = match rec.kind {
        KIND_EXEC => Kind::Exec,
        KIND_EXIT => Kind::Exit,
        KIND_CONNECT => Kind::Connect,
        _ => return Err(schema("kind rejected")),
    };
    let mut comm = opt_string(&v, "comm")?;
    if let Some(name) = &comm
        && !valid_subject(name)
    {
        return Err(schema("subject rejected"));
    }
    let exe = opt_string(&v, "exe")?;
    let remote = opt_string(&v, "remote")?;
    if kind == Kind::Connect {
        match &remote {
            Some(value) => check_remote(value)?,
            None => return Err(schema("remote rejected")),
        }
    }
    if comm.is_none()
        && let Some(exe) = &exe
    {
        let base = crate::model::basename(exe);
        if valid_subject(base) {
            comm = Some(base.to_owned());
        }
    }
    Ok(GuardEvent {
        schema_version: SCHEMA_VERSION,
        kind,
        origin: Origin::Ring,
        observed_at_ms: now_ms,
        pid: opt_u32(&v, "pid")?,
        ppid: opt_u32(&v, "ppid")?,
        uid: opt_u32(&v, "uid")?,
        exe,
        comm,
        args: args_of(&v)?,
        remote,
        package: None,
        version: None,
        container_id: opt_string(&v, "container_id")?,
        privileged: None,
        runtime: None,
        severity: None,
        ancestors: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_and_secret_args_dropped() {
        let payload = br#"{"pid":7,"ppid":1,"uid":0,"exe":"/usr/bin/xmrig","comm":"xmrig","args":["--password=x","--donate-level=1"]}"#.to_vec();
        let rec = Record {
            kind: KIND_EXEC,
            observed_at_ms: 5,
            payload,
        };
        let bytes = encode(&rec).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, rec);
        let ev = record_to_event(&rec, 99).unwrap();
        assert_eq!(ev.origin, Origin::Ring);
        assert_eq!(ev.observed_at_ms, 99);
        assert_eq!(ev.args, vec!["--donate-level=1".to_owned()]);
        assert!(!serde_json::to_string(&ev).unwrap().contains("password"));
    }

    #[test]
    fn overflow_keeps_the_oldest_and_second_consumer_is_busy() {
        let mut ring = SharedRing::new(2).unwrap();
        ring.attach().unwrap();
        assert!(matches!(ring.attach(), Err(Error::Busy)));
        let mk = |n: u8| Record {
            kind: KIND_EXIT,
            observed_at_ms: i64::from(n),
            payload: format!(r#"{{"pid":{n}}}"#).into_bytes(),
        };
        ring.push(mk(1)).unwrap();
        ring.push(mk(2)).unwrap();
        assert!(matches!(ring.push(mk(3)), Err(Error::Full)));
        assert_eq!(ring.lost(), 1);
        assert_eq!(ring.len(), 2);
        assert!(!ring.is_empty());
        assert_eq!(ring.pop().unwrap().observed_at_ms, 1);
    }

    #[test]
    fn connect_rejects_port_zero_and_ipv6() {
        let bad = Record {
            kind: KIND_CONNECT,
            observed_at_ms: 1,
            payload: br#"{"pid":1,"remote":"192.0.2.10:0"}"#.to_vec(),
        };
        assert!(record_to_event(&bad, 1).is_err());
        let v6 = Record {
            kind: KIND_CONNECT,
            observed_at_ms: 1,
            payload: br#"{"pid":1,"remote":"::1"}"#.to_vec(),
        };
        assert!(record_to_event(&v6, 1).is_err());
        let ok = Record {
            kind: KIND_CONNECT,
            observed_at_ms: 1,
            payload: br#"{"pid":1,"remote":"192.0.2.10:443"}"#.to_vec(),
        };
        assert_eq!(
            record_to_event(&ok, 8).unwrap().remote.as_deref(),
            Some("192.0.2.10:443")
        );
    }
}
