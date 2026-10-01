//! Output contract (docs/output-contract.md) for the `afteralert` binary.
//! `serve` is a daemon: it is started on a free loopback port, scraped, and
//! killed. Its status is the `/metrics` scrape; it writes no status file.

// Test helpers outside #[test] fns: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_afteralert");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Out {
    let out = Command::new(BIN).args(args).output().unwrap();
    Out {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn error(out: &Out, category: &str, code: i32) -> Value {
    assert_eq!(out.code, code, "stderr {}", out.stderr);
    assert_eq!(out.stdout, "");
    assert_eq!(out.stderr.lines().count(), 1, "{:?}", out.stderr);
    let v: Value = serde_json::from_str(out.stderr.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "error");
    assert_eq!(v["tool"], "afteralert");
    assert_eq!(v["category"], category);
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(v["exit_code"], code);
    assert!(v.get("command").is_some());
    v
}

#[test]
fn every_subcommand_speaks_json() {
    let out = run(&["version", "--json"]);
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.lines().count(), 1);
    let v: Value = serde_json::from_str(out.stdout.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "afteralert.version");
    assert_eq!(v["tool"], "afteralert");
    assert_eq!(v["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        out.stdout
            .starts_with("{\"schema_version\":1,\"kind\":\"afteralert.version\"")
    );

    // serve --json: daemon, nothing on stdout, /metrics answers.
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen = format!("127.0.0.1:{port}");
    let ledger = dir.path().join("decisions.jsonl");
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--json",
            "--listen",
            &listen,
            "--ledger",
            ledger.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let body = loop {
        if let Ok(mut stream) = TcpStream::connect(&listen) {
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut body = String::new();
            stream.read_to_string(&mut body).unwrap();
            break body;
        }
        assert!(start.elapsed() < Duration::from_secs(20));
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(body.starts_with("HTTP/1.1 200 "));
    assert!(body.contains("cveguard_ledger_chain_ok"));
    child.kill().unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty());
}

#[test]
fn usage_and_config_errors_are_one_json_line() {
    let e = error(
        &run(&["serve", "--json", "--listen", "127.0.0.1:8752"]),
        "usage",
        1,
    );
    assert_eq!(e["command"], "serve");
    let e = error(&run(&["bogus", "--json"]), "usage", 1);
    assert!(e["command"].is_null());
    error(&run(&["--json"]), "usage", 1);
    error(&run(&["version", "extra", "--format", "json"]), "usage", 1);
    let e = error(
        &run(&[
            "serve",
            "--json",
            "--listen",
            "0.0.0.0:8752",
            "--ledger",
            "x",
        ]),
        "config",
        1,
    );
    assert_eq!(e["command"], "serve");
    let text = run(&["serve", "--listen", "0.0.0.0:8752", "--ledger", "x"]);
    assert_eq!(text.code, 1);
    assert_eq!(text.stdout, "");
    assert_eq!(text.stderr, "afteralert: --listen must be 127.0.0.1:PORT\n");
}

#[test]
fn help_exits_zero_and_lists_every_command_and_exit_codes() {
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = run(args);
        assert_eq!(out.code, 0);
        for cmd in ["version", "serve", "help"] {
            assert!(out.stdout.contains(cmd), "{cmd}");
        }
        assert!(out.stdout.contains("Exit codes:"));
        assert!(out.stdout.contains("/metrics"));
    }
    for cmd in ["version", "serve"] {
        for args in [vec![cmd, "--help"], vec!["help", cmd]] {
            let out = run(&args);
            assert_eq!(out.code, 0, "{args:?}");
            assert!(out.stdout.contains("Usage: afteralert"));
            assert!(out.stdout.contains("Exit codes:"));
        }
    }
    assert_eq!(
        run(&["version"]).stdout,
        format!("afteralert {}\n", env!("CARGO_PKG_VERSION"))
    );
}
