//! Output contract (docs/output-contract.md) for the `afterseal` binary.

// Test helpers outside #[test] fns: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_afterseal");

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

fn doc(out: &Out, kind: &str, code: i32) -> Value {
    assert_eq!(out.code, code, "{kind}: stderr {}", out.stderr);
    assert!(out.stdout.ends_with('\n'));
    assert_eq!(out.stdout.lines().count(), 1, "{:?}", out.stdout);
    let v: Value = serde_json::from_str(out.stdout.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], kind);
    assert_eq!(v["tool"], "afterseal");
    assert_eq!(v["tool_version"], env!("CARGO_PKG_VERSION"));
    v
}

fn error(out: &Out, category: &str, code: i32) -> Value {
    assert_eq!(out.code, code, "stderr {}", out.stderr);
    assert_eq!(out.stdout, "");
    assert_eq!(out.stderr.lines().count(), 1, "{:?}", out.stderr);
    let v: Value = serde_json::from_str(out.stderr.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "error");
    assert_eq!(v["tool"], "afterseal");
    assert_eq!(v["category"], category);
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(v["exit_code"], code);
    assert!(v.get("command").is_some());
    v
}

/// The six census binaries in a canonical temp dir.
fn tools(dir: &Path) -> Vec<PathBuf> {
    let root = std::fs::canonicalize(dir).unwrap();
    [
        "nocved",
        "nocve-store",
        "aftercve",
        "afterguard",
        "afteralert",
        "afterseal",
    ]
    .iter()
    .map(|name| {
        let path = root.join(name);
        std::fs::write(&path, name.as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    })
    .collect()
}

fn pin_args<'a>(out: &'a str, paths: &'a [String]) -> Vec<&'a str> {
    let mut args = vec!["pin", "--out", out];
    for p in paths {
        args.push("--path");
        args.push(p);
    }
    args
}

#[test]
fn every_subcommand_speaks_json() {
    let v = doc(&run(&["version", "--json"]), "afterseal.version", 0);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));

    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<String> = tools(dir.path())
        .iter()
        .map(|p| p.to_str().unwrap().to_owned())
        .collect();
    let seal = dir.path().join("seal.json");
    let seal = seal.to_str().unwrap();

    let mut args = pin_args(seal, &paths);
    args.push("--json");
    let v = doc(&run(&args), "afterseal.pin", 0);
    assert_eq!(v["entries"], 6);
    assert_eq!(v["out"], seal);
    assert_eq!(v["status"], "pinned");
    // Text mode now prints a result too.
    let text = run(&pin_args(seal, &paths));
    assert_eq!(text.code, 0);
    assert_eq!(text.stdout, format!("pinned 6 entries to {seal}\n"));

    let v = doc(
        &run(&["verify", "--seal", seal, "--json"]),
        "afterseal.verify",
        0,
    );
    assert_eq!(v["status"], "valid");
    assert_eq!(v["reason"], "sealed");
    let v = doc(
        &run(&["census", "--json", "--seal", seal]),
        "afterseal.census",
        0,
    );
    assert_eq!(v["binaries"].as_array().unwrap().len(), 6);

    // A replaced binary: the result is still printed, exit 3.
    std::fs::write(&paths[3], b"replaced").unwrap();
    let v = doc(
        &run(&["verify", "--seal", seal, "--format", "json"]),
        "afterseal.verify",
        3,
    );
    assert_eq!(v["status"], "mismatch");
    assert_eq!(v["reason"], "seal_mismatch");
    let v = doc(
        &run(&["census", "--seal", seal, "--json"]),
        "afterseal.census",
        3,
    );
    assert_eq!(v["status"], "mismatch");
    let missing = dir.path().join("none.json");
    let v = doc(
        &run(&["verify", "--json", "--seal", missing.to_str().unwrap()]),
        "afterseal.verify",
        3,
    );
    assert_eq!(v["status"], "missing");
    // Text stays the bare status word.
    assert_eq!(run(&["verify", "--seal", seal]).stdout, "mismatch\n");
}

#[test]
fn usage_and_config_errors_are_one_json_line() {
    let e = error(&run(&["verify", "--json"]), "usage", 1);
    assert_eq!(e["command"], "verify");
    let e = error(&run(&["frob", "--json"]), "usage", 1);
    assert!(e["command"].is_null());
    error(&run(&["--json"]), "usage", 1);
    error(
        &run(&["census", "--json", "--json", "--seal", "x"]),
        "usage",
        1,
    );
    error(&run(&["pin", "--json", "--out", "x"]), "usage", 1);
    // A pin that does not cover the six census binaries is refused as a
    // config error, and nothing is written.
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<String> = tools(dir.path())[..5]
        .iter()
        .map(|p| p.to_str().unwrap().to_owned())
        .collect();
    let seal = dir.path().join("seal.json");
    let mut args = pin_args(seal.to_str().unwrap(), &paths);
    args.push("--json");
    let e = error(&run(&args), "config", 1);
    assert_eq!(e["command"], "pin");
    assert!(!seal.exists());
    let text = run(&["verify"]);
    assert_eq!(text.code, 1);
    assert_eq!(text.stdout, "");
    assert_eq!(text.stderr, "afterseal: expected --seal PATH\n");
}

#[test]
fn help_exits_zero_and_lists_every_command_and_exit_codes() {
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = run(args);
        assert_eq!(out.code, 0);
        for cmd in ["version", "pin", "verify", "census", "help"] {
            assert!(out.stdout.contains(cmd), "{cmd}");
        }
        assert!(out.stdout.contains("Exit codes:"));
        assert!(out.stdout.contains("  3 "));
    }
    for cmd in ["version", "pin", "verify", "census"] {
        for args in [vec![cmd, "--help"], vec!["help", cmd]] {
            let out = run(&args);
            assert_eq!(out.code, 0, "{args:?}");
            assert!(out.stdout.contains("Usage: afterseal"));
            assert!(out.stdout.contains("Exit codes:"));
        }
    }
}
