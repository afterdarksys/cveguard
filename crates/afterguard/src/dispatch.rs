//! Operator commands. `run` sleeps; tests call `once`, `check`, and `run_at`.
//!
//! Threats: `isolate apply` is a hard error in this build. Unknown flags are
//! rejected so a typo cannot select a different file. Values that look like
//! flags are rejected.

use std::collections::HashMap;
use std::path::Path;
use std::thread;
use std::time::Duration;

use cveguard_proto::Error;
use cveguard_proto::cli::{self, Category, CliError, Format};
use cveguard_proto::isolate;

use crate::config::Loaded;
use crate::run::{self, Runtime};
use crate::ship::Shipper;
use crate::status;

#[cfg(test)]
const GUARD_UNIT: &str = include_str!("../../../deploy/afterguard.service");
#[cfg(test)]
const ALERT_UNIT: &str = include_str!("../../../deploy/afteralert.service");
#[cfg(test)]
const SHIP_UNIT: &str = include_str!("../../../deploy/afterguard-ship.service");

pub const TOOL: &str = "afterguard";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `status`: a configured daemon's status file is missing or stale.
pub const EXIT_STALE: i32 = 11;

const EXIT_CODES: &str = "Exit codes:
  0   success
  1   error: usage, config, I/O, or refused (isolate apply); with --json one
      JSON error line on stderr and nothing on stdout
  2   once / run pass: a decision was rejected (bad line, feed gap, plan_invalid)
  3   integrity stop: seal mismatch, or enforce refused (missing seal or a plan
      that cannot be rendered) for check, once, and run; isolate plan when the
      plan cannot be rendered. check and once still print their result.
  11  status: a configured daemon's status file is missing or stale";

const HELP: &str = "afterguard: cveguard decision daemon (decides and records; never enforces)

Usage: afterguard <command> [--json | --format json|text]

Commands:
  version                            print the version
  check --config PATH                mode, seal, capability plan, isolate plan
  once --config PATH --input PATH    evaluate one JSONL batch into the ledger
  run --config PATH                  decision daemon; writes the status file
  ship --config PATH                 send ledger rows to darksignal (daemon)
  status --config PATH               run and ship status, with stale detection
  isolate plan --config PATH         print the isolate recipe (never run)
  isolate deactivate                 print the teardown command (never run)
  isolate apply                      refused in this build
  help [COMMAND]                     this text, or one command's help

Options (every command):
  --json, --format json   one JSON document on stdout (daemons print none);
                          errors as one JSON line on stderr
  --format text           human output (default)
  -h, --help              help for the command";

const HELP_VERSION: &str = "Usage: afterguard version [--json]

Prints the version. kind: afterguard.version";

const HELP_CHECK: &str = "Usage: afterguard check --config PATH [--json]

Prints mode, enabled, rules, seal, caps, and the isolate plan (text: the
plan follows the key=value lines; a plan error goes to stderr). Does not
write the ledger or status. Exit 3 on seal mismatch, or when enforce is
blocked. kind: afterguard.check";

const HELP_ONCE: &str = "Usage: afterguard once --config PATH --input PATH [--json]

Evaluates one JSONL file, appends decisions to the ledger, writes the status
file, and prints a summary: lines_evaluated, decisions_written, rejected,
ledger_seq, ledger_epoch, stopped. Exit 2 when a row was rejected, 3 when the
seal or enforce gate stopped it. kind: afterguard.once";

const HELP_RUN: &str = "Usage: afterguard run --config PATH [--json]

Daemon. One pass about every second; writes the config's `status` file
(kind afterguard.status, daemon run) every pass and before it stops. Prints
nothing on stdout. Stops with exit 3 on an integrity stop (stderr says why).";

const HELP_SHIP: &str = "Usage: afterguard ship --config PATH [--json]

Daemon. Sends ledger rows to the darksignal socket in the config's `ship`
section. Writes <cursor>.status.json (kind afterguard.status, daemon ship:
sent, refused, missed, retried, cursor, backoff_ms, last_error) after every
pass and at least every 10 s. Prints nothing on stdout; retries and refused
rows are logged on stderr.";

const HELP_STATUS: &str = "Usage: afterguard status --config PATH [--json]

Reads the run status file (config `status`) and the ship status file
(<cursor>.status.json). Read-only: takes no lock. A file is stale when
updated_at_ms is missing or more than 30000 ms from now. Exit 11 when a
configured daemon's file is missing or stale. kind: afterguard.status";

const HELP_ISOLATE: &str = "Usage: afterguard isolate plan --config PATH [--json]
       afterguard isolate deactivate [--json]
       afterguard isolate apply

plan prints the nftables recipe (never run); exit 3 when it cannot be
rendered. kind: afterguard.isolate.plan
deactivate prints `nft delete table inet cveguard` (never run).
kind: afterguard.isolate.deactivate
apply is refused in this build (exit 1, category refused).";

pub fn dispatch(args: &[String]) -> Result<i32, CliError> {
    let inv = cli::split_output(args)?;
    let command = command_name(&inv.rest);
    run_command(&inv.rest, inv.format, inv.help).map_err(|e| e.with_command(command))
}

fn command_name(rest: &[String]) -> Option<&'static str> {
    match (
        rest.first().map(String::as_str),
        rest.get(1).map(String::as_str),
    ) {
        (Some("isolate"), Some("plan")) => Some("isolate.plan"),
        (Some("isolate"), Some("deactivate")) => Some("isolate.deactivate"),
        (Some("isolate"), Some("apply")) => Some("isolate.apply"),
        (Some("isolate"), _) => Some("isolate"),
        (Some("version"), _) => Some("version"),
        (Some("check"), _) => Some("check"),
        (Some("once"), _) => Some("once"),
        (Some("run"), _) => Some("run"),
        (Some("ship"), _) => Some("ship"),
        (Some("status"), _) => Some("status"),
        (Some("help"), _) => Some("help"),
        _ => None,
    }
}

fn run_command(rest: &[String], format: Format, help: bool) -> Result<i32, CliError> {
    if help {
        return print_help(rest.first().map(String::as_str));
    }
    let Some(first) = rest.first().map(String::as_str) else {
        return Err(CliError::usage("missing command; try afterguard --help"));
    };
    match first {
        "help" if rest.len() <= 2 => print_help(rest.get(1).map(String::as_str)),
        "version" | "--version" if rest.len() == 1 => {
            match format {
                Format::Text => cli::print_line(&format!("afterguard {TOOL_VERSION}"))?,
                Format::Json => print(
                    "afterguard.version",
                    &serde_json::json!({"version": TOOL_VERSION}),
                )?,
            }
            Ok(0)
        }
        "check" => {
            let loaded = load(only(&flag_map(&rest[1..])?, "--config")?)?;
            let report = run::check(&loaded);
            match format {
                Format::Text => {
                    cli::print_line(&format!(
                        "mode={}\nenabled={}\nrules={}\nseal={}\ncaps={}",
                        report.mode,
                        if report.enabled { "yes" } else { "no" },
                        report.rules,
                        report.seal,
                        report.caps
                    ))?;
                    if let Some(plan) = &report.plan {
                        cli::print_line(plan)?;
                    }
                    if let Some(err) = &report.plan_error {
                        eprintln!("isolate: {}", cli::clean(err));
                    }
                }
                Format::Json => print("afterguard.check", &to_value(&report)?)?,
            }
            Ok(report.code)
        }
        "once" => {
            let (config, input) = pair(&flag_map(&rest[1..])?, "--config", "--input")?;
            let loaded = load(config)?;
            let summary = run::once(loaded, Path::new(input))?;
            match format {
                Format::Text => {
                    let mut text = format!(
                        "lines_evaluated={}\ndecisions_written={}\nrejected={}\nledger_seq={}",
                        summary.lines_evaluated,
                        summary.decisions_written,
                        summary.rejected,
                        summary.ledger_seq
                    );
                    if let Some(stop) = summary.stopped {
                        text.push_str(&format!("\nstopped={stop}"));
                    }
                    cli::print_line(&text)?;
                }
                Format::Json => print("afterguard.once", &to_value(&summary)?)?,
            }
            Ok(summary.code)
        }
        "run" => {
            let loaded = load(only(&flag_map(&rest[1..])?, "--config")?)?;
            let mut runtime = Runtime::new(loaded)?;
            loop {
                if runtime.run_passes(1)? == 3 {
                    return Err(CliError::new(
                        Category::Integrity,
                        format!(
                            "run stopped: {}",
                            runtime.stop_reason().unwrap_or("integrity stop")
                        ),
                        3,
                    ));
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
        "ship" => {
            let loaded = load(only(&flag_map(&rest[1..])?, "--config")?)?;
            ship_loop(&loaded)
        }
        "status" => {
            let loaded = load(only(&flag_map(&rest[1..])?, "--config")?)?;
            let (payload, fresh) = status::report(&loaded, run::now_ms()?)?;
            match format {
                Format::Text => cli::print_line(&status::render_text(&payload))?,
                Format::Json => print(status::KIND, &payload)?,
            }
            Ok(if fresh { 0 } else { EXIT_STALE })
        }
        "isolate" => isolate_cmd(&rest[1..], format),
        other if command_name(rest).is_none() && !other.starts_with('-') => {
            Err(CliError::usage(format!(
                "unknown command {}; try afterguard --help",
                cli::clean(other)
            )))
        }
        _ => Err(CliError::usage("bad arguments; try afterguard --help")),
    }
}

/// Status is written after every pass and at least every
/// `status::STATUS_INTERVAL_MS` during a backoff. A fatal error is written
/// to the status file before it is returned.
fn ship_loop(loaded: &Loaded) -> Result<i32, CliError> {
    let cfg = loaded
        .ship
        .clone()
        .ok_or_else(|| CliError::config(&Error::Invalid("ship not configured".to_owned())))?;
    let mut shipper = Shipper::new(loaded.ledger.clone(), cfg)?;
    let slice = Duration::from_millis(status::STATUS_INTERVAL_MS.unsigned_abs());
    loop {
        let now = run::now_ms()?;
        let pass = match shipper.pass(now) {
            Ok(pass) => pass,
            Err(err) => {
                shipper.note_error(err.to_string(), now);
                if let Err(write) = shipper.write_status(now) {
                    eprintln!("afterguard: ship: status write failed: {write}");
                }
                return Err(err.into());
            }
        };
        if pass.failed {
            eprintln!(
                "afterguard: ship: darksignal did not take the row (retry ack, unknown ack, or socket error); backing off {}s",
                shipper.wait().as_secs()
            );
        }
        shipper.write_status(now)?;
        let mut left = shipper.wait();
        while !left.is_zero() {
            let step = left.min(slice);
            thread::sleep(step);
            left = left.saturating_sub(step);
            if !left.is_zero() {
                shipper.write_status(run::now_ms()?)?;
            }
        }
    }
}

fn isolate_cmd(args: &[String], format: Format) -> Result<i32, CliError> {
    match args {
        [cmd] if cmd == "apply" => {
            isolate::apply()?;
            Ok(0)
        }
        [cmd] if cmd == "deactivate" => {
            let recipe = isolate::deactivate_recipe();
            match format {
                Format::Text => cli::print_line(recipe)?,
                Format::Json => print(
                    "afterguard.isolate.deactivate",
                    &serde_json::json!({"recipe": recipe, "executed": false}),
                )?,
            }
            Ok(0)
        }
        [cmd, flag, path] if cmd == "plan" && flag == "--config" && !path.starts_with('-') => {
            let loaded = load(path)?;
            let text = isolate::plan(&loaded.isolate).map_err(|err| {
                CliError::new(Category::Config, format!("isolate plan: {err}"), 3)
            })?;
            match format {
                Format::Text => cli::print_line(&text)?,
                Format::Json => print(
                    "afterguard.isolate.plan",
                    &serde_json::json!({"plan": text, "executed": false}),
                )?,
            }
            Ok(0)
        }
        [] => Err(CliError::usage(
            "isolate needs plan, deactivate, or apply; try afterguard isolate --help",
        )),
        _ => Err(CliError::usage(
            "bad isolate arguments; try afterguard isolate --help",
        )),
    }
}

fn print_help(command: Option<&str>) -> Result<i32, CliError> {
    let body = match command {
        None | Some("help") => HELP,
        Some("version") => HELP_VERSION,
        Some("check") => HELP_CHECK,
        Some("once") => HELP_ONCE,
        Some("run") => HELP_RUN,
        Some("ship") => HELP_SHIP,
        Some("status") => HELP_STATUS,
        Some("isolate") => HELP_ISOLATE,
        Some(other) => {
            return Err(CliError::usage(format!(
                "no help for {}; try afterguard --help",
                cli::clean(other)
            )));
        }
    };
    cli::print_line(&format!("{body}\n\n{EXIT_CODES}"))?;
    Ok(0)
}

fn print(kind: &str, payload: &serde_json::Value) -> Result<(), CliError> {
    cli::print_envelope(TOOL, TOOL_VERSION, kind, payload)
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(value).map_err(|_| CliError::new(Category::Internal, "json rejected", 1))
}

fn load(path: &str) -> Result<Loaded, CliError> {
    Loaded::load(Path::new(path)).map_err(|e| CliError::config(&e))
}

fn flag_map(args: &[String]) -> Result<HashMap<&str, &str>, CliError> {
    let mut map = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if !key.starts_with("--") || key.len() < 3 {
            return Err(CliError::usage(format!(
                "unexpected argument {}",
                cli::clean(key)
            )));
        }
        if map.contains_key(key) {
            return Err(CliError::usage(format!("{} given twice", cli::clean(key))));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(CliError::usage(format!(
                "{} needs a value",
                cli::clean(key)
            )));
        };
        if value.starts_with('-') {
            return Err(CliError::usage(format!(
                "{} value must not start with -",
                cli::clean(key)
            )));
        }
        map.insert(key, value.as_str());
        index += 2;
    }
    Ok(map)
}

fn only<'a>(map: &HashMap<&'a str, &'a str>, key: &str) -> Result<&'a str, CliError> {
    match map.get(key) {
        Some(value) if map.len() == 1 => Ok(value),
        _ => Err(CliError::usage(format!("expected exactly {key} PATH"))),
    }
}

fn pair<'a>(
    map: &HashMap<&'a str, &'a str>,
    left: &str,
    right: &str,
) -> Result<(&'a str, &'a str), CliError> {
    match (map.get(left).copied(), map.get(right).copied()) {
        (Some(a), Some(b)) if map.len() == 2 => Ok((a, b)),
        _ => Err(CliError::usage(format!(
            "expected exactly {left} PATH {right} PATH"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;

    const ALERT_RULES: &str = r#"[{"id":"miner-exe","enabled":true,"action":"alert","mode":"enforce","when":[{"op":"exe_basename","equals":"xmrig"}]}]"#;
    const ISO_RULES: &str = r#"[{"id":"isolate-miner","enabled":true,"action":"isolate","mode":"enforce","when":[{"op":"exe_basename","equals":"xmrig"}]}]"#;
    const XMRIG: &str = "{\"schema_version\":1,\"kind\":\"exec\",\"exe\":\"/tmp/xmrig\",\"comm\":\"xmrig\",\"observed_at_ms\":10}\n";

    fn write_0600(path: &std::path::Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        config: PathBuf,
        ledger: PathBuf,
    }

    fn fixture(mode: &str, rules: &str, management: &[&str], seal_body: Option<&[u8]>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rules.json"), rules).unwrap();
        let mut cfg = serde_json::json!({
            "mode": mode,
            "enabled": true,
            "rules": "rules.json",
            "ledger": "decisions.jsonl",
            "isolate": {
                "local_cidrs": ["10.1.2.0/24"],
                "whitelist": ["192.0.2.20/32"],
                "management_ips": management,
                "store_ips": ["198.51.100.8"],
                "keep_store": true,
                "deadman_secs": 120
            }
        });
        if seal_body.is_some() {
            cfg["seal"] = serde_json::json!("seal.json");
            write_0600(&dir.path().join("seal.json"), seal_body.unwrap_or(b"{"));
        }
        let config = dir.path().join("config.json");
        std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let ledger = dir.path().join("decisions.jsonl");
        Fixture {
            _dir: dir,
            config,
            ledger,
        }
    }

    fn once(fix: &Fixture, body: &str) -> Result<i32, CliError> {
        let input = fix.config.parent().unwrap().join("in.jsonl");
        std::fs::write(&input, body).unwrap();
        dispatch(&[
            "once".to_owned(),
            "--config".to_owned(),
            fix.config.to_str().unwrap().to_owned(),
            "--input".to_owned(),
            input.to_str().unwrap().to_owned(),
        ])
    }

    #[test]
    fn example_check_exits_zero() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config.example.json");
        let text = path.to_str().unwrap().to_owned();
        assert_eq!(dispatch(&["version".to_owned()]).unwrap(), 0);
        assert_eq!(
            dispatch(&["check".to_owned(), "--config".to_owned(), text.clone()]).unwrap(),
            0
        );
        assert_eq!(
            dispatch(&[
                "isolate".to_owned(),
                "plan".to_owned(),
                "--config".to_owned(),
                text
            ])
            .unwrap(),
            0
        );
    }

    #[test]
    fn once_mismatch_writes_one_alert_and_exits_three() {
        let fix = fixture("shadow", ALERT_RULES, &["192.0.2.10"], Some(b"{"));
        assert_eq!(once(&fix, XMRIG).unwrap(), 3);
        let body = std::fs::read_to_string(&fix.ledger).unwrap();
        let lines: Vec<_> = body.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        assert!(body.contains("afterseal"));
        assert!(body.contains("seal_mismatch"));
        assert!(!body.contains("xmrig"));
        assert!(!body.contains("miner-exe"));
    }

    #[test]
    fn enforce_without_seal_exits_three_without_ledger() {
        let fix = fixture("enforce", ALERT_RULES, &["192.0.2.10"], None);
        assert_eq!(once(&fix, XMRIG).unwrap(), 3);
        assert!(!fix.ledger.exists());
    }

    #[test]
    fn shadow_bad_isolate_exits_two_and_mismatch_wins() {
        let bad = fixture("shadow", ISO_RULES, &[], None);
        assert_eq!(once(&bad, XMRIG).unwrap(), 2);
        let body = std::fs::read_to_string(&bad.ledger).unwrap();
        assert!(body.contains("plan_invalid"));

        let won = fixture("shadow", ISO_RULES, &[], Some(b"{"));
        assert_eq!(once(&won, XMRIG).unwrap(), 3);
        let body = std::fs::read_to_string(&won.ledger).unwrap();
        let lines: Vec<_> = body.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        assert!(body.contains("afterseal"));
        assert!(body.contains("seal_mismatch"));
        assert!(!body.contains("plan_invalid"));
        assert!(!body.contains("xmrig"));
    }

    #[test]
    fn oversized_once_line_is_a_rejected_row() {
        let fix = fixture("shadow", ALERT_RULES, &["192.0.2.10"], None);
        let huge = "a".repeat(9000);
        assert_eq!(once(&fix, &huge).unwrap(), 2);
        let body = std::fs::read_to_string(&fix.ledger).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains("\"outcome\":\"rejected\""));
        assert!(body.contains("\"reason\":\"schema\""));
        assert!(!body.contains("aaa"));
    }

    #[test]
    fn once_bad_line_does_not_abort_the_batch() {
        let fix = fixture("shadow", ALERT_RULES, &["192.0.2.10"], None);
        let body = format!(
            "{XMRIG}{{not json\n{{\"kind\":\"audit.exec\",\"pid\":5,\"comm\":\"Web Content\",\"exe\":\"/tmp/xmrig\"}}\n"
        );
        assert_eq!(once(&fix, &body).unwrap(), 2);
        let ledger = std::fs::read_to_string(&fix.ledger).unwrap();
        let rows: Vec<serde_json::Value> = ledger
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["rule_id"], "miner-exe");
        assert_eq!(rows[1]["outcome"], "rejected");
        assert_eq!(rows[1]["reason"], "schema");
        assert_eq!(rows[2]["rule_id"], "miner-exe");
        assert_eq!(rows[2]["comm_invalid"], true);
        let seqs: Vec<u64> = rows.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn example_config_names_an_events_feed() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config.example.json");
        let loaded = Loaded::load(&path).unwrap();
        assert!(loaded.events.is_some());
        assert!(loaded.ledger.starts_with("/var/lib/cveguard"));
    }

    #[test]
    fn systemd_units_drop_capabilities() {
        assert!(GUARD_UNIT.contains("CapabilityBoundingSet="));
        assert!(GUARD_UNIT.contains("AmbientCapabilities="));
        assert!(GUARD_UNIT.contains("NoNewPrivileges=yes"));
        assert!(GUARD_UNIT.contains("PrivateNetwork=yes"));
        assert!(GUARD_UNIT.contains("RestrictAddressFamilies=AF_UNIX"));
        assert!(GUARD_UNIT.contains("User=cveguard"));
        for unit in [GUARD_UNIT, ALERT_UNIT] {
            for line in [
                "Restart=always",
                "ProtectKernelTunables=yes",
                "ProtectKernelModules=yes",
                "ProtectKernelLogs=yes",
                "ProtectControlGroups=yes",
                "RestrictNamespaces=yes",
                "LockPersonality=yes",
                "MemoryDenyWriteExecute=yes",
                "SystemCallFilter=@system-service",
                "SystemCallArchitectures=native",
                "NoNewPrivileges=yes",
            ] {
                assert!(unit.lines().any(|l| l == line), "{line}");
            }
        }
        assert!(GUARD_UNIT.lines().any(|l| l == "StateDirectory=cveguard"));
        assert!(GUARD_UNIT.lines().any(|l| l == "StateDirectoryMode=0700"));
        assert!(!GUARD_UNIT.contains("CAP_NET_ADMIN"));
        assert!(!GUARD_UNIT.contains("CAP_SYS_ADMIN"));
        assert!(!GUARD_UNIT.contains("CAP_SYS_PTRACE"));
        assert!(ALERT_UNIT.contains("IPAddressAllow=localhost"));
        assert!(ALERT_UNIT.contains("IPAddressDeny=any"));
        assert!(ALERT_UNIT.contains("User=cveguard"));
        assert!(!ALERT_UNIT.contains("PrivateNetwork"));
    }

    #[test]
    fn ship_unit_joins_the_producer_group_and_config_is_checked() {
        for line in [
            "User=cveguard",
            "SupplementaryGroups=darksignal-producers",
            "ExecStart=/usr/local/bin/afterguard ship --config /etc/cveguard/config.json",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "CapabilityBoundingSet=",
            "NoNewPrivileges=yes",
            "StateDirectory=cveguard",
        ] {
            assert!(SHIP_UNIT.lines().any(|l| l == line), "{line}");
        }
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config.example.json");
        let loaded = Loaded::load(&path).unwrap();
        let ship = loaded.ship.unwrap();
        assert!(ship.socket.is_absolute());
        assert_eq!(ship.cursor, PathBuf::from("/var/lib/cveguard/ship.cursor"));

        let fix = fixture("shadow", ALERT_RULES, &["192.0.2.10"], None);
        let mut cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fix.config).unwrap()).unwrap();
        for (socket, host) in [
            ("relative.sock", "ns2"),
            ("/run/d.sock", ".bad"),
            ("/run/d.sock", ""),
        ] {
            cfg["ship"] = serde_json::json!({"socket": socket, "host": host});
            std::fs::write(&fix.config, serde_json::to_vec(&cfg).unwrap()).unwrap();
            assert!(Loaded::load(&fix.config).is_err(), "{socket} {host}");
        }
        cfg["ship"] = serde_json::json!({"socket": "/run/d.sock", "host": "ns2", "extra": 1});
        std::fs::write(&fix.config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert!(Loaded::load(&fix.config).is_err());
        // `ship` without a ship section is an error, not a silent no-op.
        let plain = fixture("shadow", ALERT_RULES, &["192.0.2.10"], None);
        let err = dispatch(&[
            "ship".to_owned(),
            "--config".to_owned(),
            plain.config.to_str().unwrap().to_owned(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("ship not configured"));
    }

    #[test]
    fn apply_is_not_in_debut_and_deactivate_prints_recipe() {
        let err = dispatch(&["isolate".to_owned(), "apply".to_owned()]).unwrap_err();
        assert_eq!(err.category, Category::Refused);
        assert_eq!(err.exit_code, 1);
        assert_eq!(err.to_string(), "isolate apply is not in the debut build");
        assert_eq!(
            isolate::deactivate_recipe(),
            "nft delete table inet cveguard"
        );
        assert_eq!(
            dispatch(&["isolate".to_owned(), "deactivate".to_owned()]).unwrap(),
            0
        );
        let bad = fixture("shadow", ISO_RULES, &[], None);
        assert_eq!(
            dispatch(&[
                "isolate".to_owned(),
                "plan".to_owned(),
                "--config".to_owned(),
                bad.config.to_str().unwrap().to_owned(),
            ])
            .unwrap_err()
            .exit_code,
            3
        );
    }

    #[test]
    fn unknown_and_duplicate_flags_are_rejected() {
        assert!(dispatch(&["version".to_owned(), "extra".to_owned()]).is_err());
        assert!(dispatch(&["check".to_owned(), "--config".to_owned(), "-x".to_owned()]).is_err());
        assert!(
            dispatch(&[
                "check".to_owned(),
                "--config".to_owned(),
                "a.json".to_owned(),
                "--config".to_owned(),
                "b.json".to_owned(),
            ])
            .is_err()
        );
        assert!(dispatch(&["nope".to_owned()]).is_err());
        assert!(
            dispatch(&[
                "isolate".to_owned(),
                "apply".to_owned(),
                "--config".to_owned(),
                "a.json".to_owned()
            ])
            .is_err()
        );
    }
}
