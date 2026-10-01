//! Output contract (docs/output-contract.md) for the `afterguard` binary.
//! Every subcommand runs against temp config and state. The daemons (`run`,
//! `ship`) are started, read through their status files, and killed.

// Test helpers outside #[test] fns: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_afterguard");
const RULES: &str = r#"[{"id":"miner-exe","enabled":true,"action":"alert","mode":"enforce","when":[{"op":"exe_basename","equals":"xmrig"}]}]"#;
const XMRIG: &str = "{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/tmp/xmrig\",\"comm\":\"xmrig\",\"observed_at_ms\":10}\n";

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

/// stdout is exactly one compact JSON object with the envelope.
fn doc(out: &Out, kind: &str, code: i32) -> Value {
    assert_eq!(out.code, code, "{kind}: stderr {}", out.stderr);
    assert!(out.stdout.ends_with('\n'), "{kind}: {:?}", out.stdout);
    assert_eq!(out.stdout.lines().count(), 1, "{kind}: {:?}", out.stdout);
    let v: Value = serde_json::from_str(out.stdout.trim_end()).unwrap();
    assert!(v.is_object());
    assert_eq!(v["schema_version"], 1, "{kind}");
    assert_eq!(v["kind"], kind);
    assert_eq!(v["tool"], "afterguard");
    assert_eq!(v["tool_version"], env!("CARGO_PKG_VERSION"));
    v
}

/// stderr is exactly one JSON error line; stdout is empty.
fn error(out: &Out, category: &str, code: i32) -> Value {
    assert_eq!(out.code, code, "stderr {}", out.stderr);
    assert_eq!(out.stdout, "", "error wrote stdout");
    assert_eq!(out.stderr.lines().count(), 1, "{:?}", out.stderr);
    let v: Value = serde_json::from_str(out.stderr.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "error");
    assert_eq!(v["tool"], "afterguard");
    assert_eq!(v["category"], category);
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(v["exit_code"], code);
    assert!(v.get("command").is_some());
    v
}

struct Fix {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Fix {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn config(&self) -> &str {
        self.config.to_str().unwrap()
    }
}

fn fixture(mode: &str) -> Fix {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rules.json"), RULES).unwrap();
    let cfg = serde_json::json!({
        "mode": mode,
        "enabled": true,
        "rules": "rules.json",
        "ledger": "decisions.jsonl",
        "status": "status.json",
        "isolate": {
            "local_cidrs": ["10.1.2.0/24"],
            "management_ips": ["192.0.2.10"],
            "store_ips": ["198.51.100.8"],
            "keep_store": true,
            "deadman_secs": 120
        },
        "ship": {
            "socket": dir.path().join("no-darksignal.sock").to_str().unwrap(),
            "host": "e2e-host1"
        }
    });
    let config = dir.path().join("config.json");
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    Fix { dir, config }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn wait_for(path: &Path, ok: impl Fn(&Value) -> bool) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(v) = serde_json::from_slice::<Value>(&bytes)
            && ok(&v)
        {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "{path:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn every_subcommand_speaks_json() {
    let fix = fixture("shadow");
    let input = fix.path("in.jsonl");
    std::fs::write(&input, format!("{XMRIG}{{not json\n")).unwrap();
    let input = input.to_str().unwrap();

    let v = doc(&run(&["version", "--json"]), "afterguard.version", 0);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    let v = doc(
        &run(&["--version", "--format", "json"]),
        "afterguard.version",
        0,
    );
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));

    let v = doc(
        &run(&["check", "--json", "--config", fix.config()]),
        "afterguard.check",
        0,
    );
    assert_eq!(v["mode"], "shadow");
    assert_eq!(v["seal"], "missing");
    assert_eq!(v["rules"], 1);
    assert!(v["plan"].as_str().unwrap().contains("nft"));
    assert!(v["plan_error"].is_null());

    // once: one decision and one rejected line, exit 2, summary in JSON.
    let v = doc(
        &run(&["once", "--config", fix.config(), "--input", input, "--json"]),
        "afterguard.once",
        2,
    );
    assert_eq!(v["decisions_written"], 2);
    assert_eq!(v["rejected"], 1);
    assert_eq!(v["lines_evaluated"], 2);
    assert_eq!(v["ledger_seq"], 2);
    assert!(v["stopped"].is_null());
    // Ledger format is unchanged: no envelope in the rows.
    let ledger = std::fs::read_to_string(fix.path("decisions.jsonl")).unwrap();
    assert_eq!(ledger.lines().count(), 2);
    assert!(!ledger.contains("afterguard.once"));

    // The status file `once` wrote has the envelope and exactly the key set
    // afteralert's fixture pins.
    let status = read_json(&fix.path("status.json"));
    assert_eq!(status["kind"], "afterguard.status");
    assert_eq!(status["daemon"], "run");
    assert!(status["updated_at_ms"].as_i64().unwrap() > 0);
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../cveguard-proto/testdata/status_run.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&status), keys(&fixture));

    // status: run file is fresh, ship has never run: exit 11.
    let v = doc(
        &run(&["status", "--config", fix.config(), "--json"]),
        "afterguard.status",
        11,
    );
    assert_eq!(v["run"]["stale"], false);
    assert_eq!(v["run"]["present"], true);
    assert_eq!(v["ship"]["present"], false);
    assert_eq!(v["ship"]["stale"], true);

    let v = doc(
        &run(&["isolate", "plan", "--config", fix.config(), "--json"]),
        "afterguard.isolate.plan",
        0,
    );
    assert_eq!(v["executed"], false);
    assert!(
        v["plan"]
            .as_str()
            .unwrap()
            .contains("nft delete table inet cveguard")
    );
    let v = doc(
        &run(&["isolate", "deactivate", "--json"]),
        "afterguard.isolate.deactivate",
        0,
    );
    assert_eq!(v["recipe"], "nft delete table inet cveguard");
    // apply is refused by design: a JSON error, never a document.
    let e = error(&run(&["isolate", "apply", "--json"]), "refused", 1);
    assert_eq!(e["command"], "isolate.apply");
}

#[test]
fn run_and_ship_daemons_write_enveloped_status_and_no_stdout() {
    let fix = fixture("shadow");
    let input = fix.path("in.jsonl");
    std::fs::write(&input, XMRIG).unwrap();
    assert_eq!(
        run(&[
            "once",
            "--config",
            fix.config(),
            "--input",
            input.to_str().unwrap()
        ])
        .code,
        0
    );
    std::fs::remove_file(fix.path("status.json")).unwrap();

    let started = now_ms();
    let mut guard = Command::new(BIN)
        .args(["run", "--json", "--config", fix.config()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ship = Command::new(BIN)
        .args(["ship", "--config", fix.config(), "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let run_status = wait_for(&fix.path("status.json"), |v| v["daemon"] == "run");
    let ship_status = wait_for(&fix.path("ship.cursor.status.json"), |v| {
        v["retried"].as_u64().unwrap_or(0) >= 1
    });
    // `status` reads both while the daemons hold their files.
    let v = doc(
        &run(&["status", "--config", fix.config(), "--json"]),
        "afterguard.status",
        0,
    );
    assert_eq!(v["run"]["stale"], false);
    assert_eq!(v["ship"]["stale"], false);
    assert_eq!(v["ship"]["file"]["daemon"], "ship");
    let text = run(&["status", "--config", fix.config()]);
    assert_eq!(text.code, 0);
    assert!(text.stdout.contains("run status=fresh"));
    assert!(text.stdout.contains("ship status=fresh"));

    guard.kill().unwrap();
    ship.kill().unwrap();
    let guard = guard.wait_with_output().unwrap();
    let ship = ship.wait_with_output().unwrap();
    assert!(guard.stdout.is_empty());
    assert!(ship.stdout.is_empty());

    for (status, daemon) in [(&run_status, "run"), (&ship_status, "ship")] {
        assert_eq!(status["schema_version"], 1);
        assert_eq!(status["kind"], "afterguard.status");
        assert_eq!(status["tool"], "afterguard");
        assert_eq!(status["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["daemon"], daemon);
        assert!(status["updated_at_ms"].as_i64().unwrap() >= started);
    }
    assert_eq!(run_status["rules_loaded"], 1);
    assert_eq!(ship_status["sent"], 0);
    assert_eq!(ship_status["refused"], 0);
    assert_eq!(ship_status["cursor"]["seq"], 0);
    assert!(
        ship_status["last_error"]
            .as_str()
            .unwrap()
            .starts_with("socket:")
    );
    assert!(ship_status["last_error_at_ms"].as_i64().is_some());
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(fix.path("ship.cursor.status.json"))
            .unwrap()
            .permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn run_integrity_stop_is_a_json_error_and_exit_three() {
    // Enforce without a seal: the gate refuses before any decision.
    let fix = fixture("enforce");
    let e = error(
        &run(&["run", "--json", "--config", fix.config()]),
        "integrity",
        3,
    );
    assert_eq!(e["command"], "run");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("enforce_seal_not_valid")
    );
    let status = read_json(&fix.path("status.json"));
    assert_eq!(status["kind"], "afterguard.status");
    assert_eq!(status["stop_reason"], "enforce_seal_not_valid");
    assert!(!fix.path("decisions.jsonl").exists());

    // once stops the same way but still prints its summary.
    let input = fix.path("in.jsonl");
    std::fs::write(&input, XMRIG).unwrap();
    let v = doc(
        &run(&[
            "once",
            "--json",
            "--config",
            fix.config(),
            "--input",
            input.to_str().unwrap(),
        ]),
        "afterguard.once",
        3,
    );
    assert_eq!(v["stopped"], "enforce_seal_not_valid");
    assert_eq!(v["decisions_written"], 0);
    let v = doc(
        &run(&["check", "--config", fix.config(), "--json"]),
        "afterguard.check",
        3,
    );
    assert_eq!(v["enforce_blocked"], true);
    // Text mode: one `afterguard: <message>` line on stderr.
    let text = run(&["run", "--config", fix.config()]);
    assert_eq!(text.code, 3);
    assert_eq!(text.stdout, "");
    assert_eq!(
        text.stderr,
        "afterguard: run stopped: enforce_seal_not_valid\n"
    );
}

#[test]
fn usage_and_config_errors_are_one_json_line() {
    let fix = fixture("shadow");
    let e = error(
        &run(&["check", "--json", "--config", fix.config(), "--bogus", "x"]),
        "usage",
        1,
    );
    assert_eq!(e["command"], "check");
    let e = error(&run(&["nope", "--json"]), "usage", 1);
    assert!(e["command"].is_null());
    error(&run(&["--json"]), "usage", 1);
    error(&run(&["version", "extra", "--json"]), "usage", 1);
    error(&run(&["check", "--json", "--format", "html"]), "usage", 1);
    error(&run(&["check", "--json", "--format", "text"]), "usage", 1);
    error(
        &run(&["once", "--json", "--config", fix.config()]),
        "usage",
        1,
    );
    let missing = fix.path("missing.json");
    for cmd in ["check", "run", "ship", "status"] {
        let e = error(
            &run(&[cmd, "--json", "--config", missing.to_str().unwrap()]),
            "config",
            1,
        );
        assert_eq!(e["command"], cmd);
    }
    // A config without a ship section cannot ship.
    let plain = fix.path("plain.json");
    let mut cfg = read_json(&fix.config);
    cfg.as_object_mut().unwrap().remove("ship");
    std::fs::write(&plain, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let e = error(
        &run(&["ship", "--json", "--config", plain.to_str().unwrap()]),
        "config",
        1,
    );
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("ship not configured")
    );
    // An isolate plan that cannot be rendered keeps its exit 3.
    let mut bad = read_json(&fix.config);
    bad["isolate"]["management_ips"] = serde_json::json!([]);
    let badp = fix.path("bad.json");
    std::fs::write(&badp, serde_json::to_vec(&bad).unwrap()).unwrap();
    let e = error(
        &run(&[
            "isolate",
            "plan",
            "--json",
            "--config",
            badp.to_str().unwrap(),
        ]),
        "config",
        3,
    );
    assert_eq!(e["command"], "isolate.plan");

    // Text mode: one line `afterguard: <message>`, nothing on stdout.
    let text = run(&["check", "--config", missing.to_str().unwrap()]);
    assert_eq!(text.code, 1);
    assert_eq!(text.stdout, "");
    assert!(text.stderr.starts_with("afterguard: config: "));
    assert_eq!(text.stderr.lines().count(), 1);
    let text = run(&["frobnicate"]);
    assert_eq!(
        text.stderr,
        "afterguard: unknown command frobnicate; try afterguard --help\n"
    );
}

#[test]
fn help_exits_zero_and_lists_every_command_and_exit_codes() {
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = run(args);
        assert_eq!(out.code, 0);
        for cmd in [
            "version",
            "check",
            "once",
            "run",
            "ship",
            "status",
            "isolate plan",
            "isolate deactivate",
            "isolate apply",
            "help",
        ] {
            assert!(out.stdout.contains(cmd), "{cmd}");
        }
        assert!(out.stdout.contains("Exit codes:"));
        for code in ["  0 ", "  1 ", "  2 ", "  3 ", "  11 "] {
            assert!(out.stdout.contains(code), "{code}");
        }
    }
    for cmd in [
        "version", "check", "once", "run", "ship", "status", "isolate",
    ] {
        for args in [
            vec![cmd, "--help"],
            vec!["help", cmd],
            vec![cmd, "-h", "--json"],
        ] {
            let out = run(&args);
            assert_eq!(out.code, 0, "{args:?}");
            assert!(out.stdout.contains("Usage: afterguard"), "{args:?}");
            assert!(out.stdout.contains("Exit codes:"), "{args:?}");
        }
    }
    let out = run(&["isolate", "plan", "--help"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("isolate plan --config PATH"));
    assert_eq!(
        run(&["version"]).stdout,
        format!("afterguard {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn status_reports_stale_and_old_files() {
    let fix = fixture("shadow");
    let ship_status = fix.path("ship.cursor.status.json");
    let write = |path: &Path, body: &Value| {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&serde_json::to_vec(body).unwrap()).unwrap();
    };
    let now = now_ms();
    write(
        &fix.path("status.json"),
        &serde_json::json!({"kind": "afterguard.status", "daemon": "run", "updated_at_ms": now}),
    );
    write(
        &ship_status,
        &serde_json::json!({"kind": "afterguard.status", "daemon": "ship", "updated_at_ms": now}),
    );
    let v = doc(
        &run(&["status", "--json", "--config", fix.config()]),
        "afterguard.status",
        0,
    );
    assert_eq!(v["run"]["stale"], false);
    assert_eq!(v["ship"]["stale"], false);

    // 31 s old: stale.
    write(
        &ship_status,
        &serde_json::json!({"daemon": "ship", "updated_at_ms": now - 31_000}),
    );
    let v = doc(
        &run(&["status", "--json", "--config", fix.config()]),
        "afterguard.status",
        11,
    );
    assert_eq!(v["run"]["stale"], false);
    assert_eq!(v["ship"]["stale"], true);
    assert!(v["ship"]["age_ms"].as_i64().unwrap() >= 31_000);
    let text = run(&["status", "--config", fix.config()]);
    assert_eq!(text.code, 11);
    assert!(text.stdout.contains("ship status=stale"));

    // A pre-envelope status file has no updated_at_ms: stale, not an error.
    write(
        &fix.path("status.json"),
        &serde_json::json!({"rules_loaded": 1}),
    );
    let v = doc(
        &run(&["status", "--json", "--config", fix.config()]),
        "afterguard.status",
        11,
    );
    assert_eq!(v["run"]["stale"], true);

    // A group-writable status file is refused.
    std::fs::set_permissions(
        &ship_status,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .unwrap();
    error(
        &run(&["status", "--json", "--config", fix.config()]),
        "io",
        1,
    );
    // Garbage is an integrity error.
    std::fs::set_permissions(
        &ship_status,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(&ship_status, b"{not json").unwrap();
    error(
        &run(&["status", "--json", "--config", fix.config()]),
        "integrity",
        1,
    );
}
