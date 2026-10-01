//! nocved writes a compact stand-in to its feed (never the spool) when an
//! envelope line is over 8192 bytes, e.g. a 12-24 KB `persistence.baseline`
//! at every sensor start. The stand-in keeps v/host/epoch/seq/prev/mac and
//! replaces `payload` with a bounded summary (`"feed_compact":true`). The
//! lines below are literal nocved output (`nocved::feed::compact_line`) for
//! seq 0..=2 of one epoch; seq 1 was a 23966-byte baseline line. The reader
//! must take all three without a gap or a rejected line.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: panics are the assertion mechanism

use afterguard::tail::Tail;
use cveguard_proto::intel::ingest_line_meta;
use cveguard_proto::model::MAX_LINE;

const EPOCH: &str = "e22229c54a578a643f88d1a9a441c8d8";
const SEQ0: &str = r##"{"v":1,"host":"web-01.example","epoch":"e22229c54a578a643f88d1a9a441c8d8","seq":0,"prev":"a024ba55cd02ca9d18689d82efab50899ffdca16520c97e6bc0859e02362cefc","payload":"{\"kind\":\"sensor.start\",\"observed_at_ms\":1790000000000,\"source\":\"nocved\"}","mac":"9bb8b0365e1e97e884c8f414eb6dabf8ee6a00e9c4d0c34de43c54f71d3029aa"}"##;
const SEQ1_COMPACT: &str = r##"{"v":1,"host":"web-01.example","epoch":"e22229c54a578a643f88d1a9a441c8d8","seq":1,"prev":"b118e21ee525f081d4d8b9e928c77e252366e7251055fae8532e94c58fc45180","payload":"{\"count\":80,\"feed_compact\":true,\"kind\":\"persistence.baseline\",\"locations\":[{\"category\":\"cron\",\"count\":27,\"path\":\"/etc/cron.d\",\"sha256\":\"6d36dd662f985e6eb0c668474bc27f22ebc5e8b14a0c071617be6660b6d3c074\"},{\"category\":\"pam\",\"count\":26,\"path\":\"/etc/pam.d\",\"sha256\":\"65b9324ad4ab68a39d72307adf25bece2779eb7a896ca35f454cce0e22362d4d\"},{\"category\":\"systemd\",\"count\":27,\"path\":\"/etc/systemd/system\",\"sha256\":\"740912c1fa1768da9ca79219a65cac0f297f1e34b87b7df1949d324f2045b7b4\"}],\"observed_at_ms\":1790000000123,\"orig_bytes\":21150,\"orig_sha256\":\"b1ccf468c054031c2807803402ff968d438d98304a56e96f5913db3fe118852d\",\"signals\":[],\"signals_count\":0,\"source\":\"persistence\",\"truncated\":false}","mac":"3cb8e85f5ef2f271a9431cf4dcbbf7e2bd3933a2d18e2fbd679f2d7125416593"}"##;
const SEQ2: &str = r##"{"v":1,"host":"web-01.example","epoch":"e22229c54a578a643f88d1a9a441c8d8","seq":2,"prev":"071d36203bf720d88240075957ef3b14a6e42ad4640a46ed16d6dd59c619b8cd","payload":"{\"kind\":\"sensor.start\",\"observed_at_ms\":1790000000200,\"source\":\"nocved\"}","mac":"616315facf48710ea6a7f6c41ca0e10eb605f58e122fcf0a330c6710e402f642"}"##;

#[test]
fn compact_line_parses_with_its_envelope_position() {
    assert!(SEQ1_COMPACT.len() < MAX_LINE);
    for (seq, line) in [(0, SEQ0), (1, SEQ1_COMPACT), (2, SEQ2)] {
        let got = ingest_line_meta(line).expect("accepted, not rejected");
        assert_eq!(got.envelope, Some((EPOCH.to_owned(), seq)));
        assert!(got.event.is_none(), "not an exec/net/package event");
    }
}

#[test]
fn compact_line_in_the_feed_raises_no_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(
        &path,
        format!(
            "{SEQ0}
{SEQ1_COMPACT}
{SEQ2}
"
        ),
    )
    .unwrap();
    let mut tail = Tail::new();
    let batch = tail.poll(&path, 1, 100).unwrap();
    assert_eq!((batch.gaps, batch.bad_lines), (0, 0));
    assert_eq!(tail.skipped(), 0);
    assert!(!tail.gap());

    // Control: the same feed without the seq-1 line (what a skipped
    // oversized line used to look like) is a gap.
    let path = dir.path().join("events-skipped.jsonl");
    std::fs::write(
        &path,
        format!(
            "{SEQ0}
{SEQ2}
"
        ),
    )
    .unwrap();
    let mut tail = Tail::new();
    assert_eq!(tail.poll(&path, 1, 100).unwrap().gaps, 1);
}
