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
use cveguard_proto::isolate;

use crate::config::Loaded;
use crate::run::{self, Runtime};
use crate::ship::Shipper;

#[cfg(test)]
const GUARD_UNIT: &str = include_str!("../../../deploy/afterguard.service");
#[cfg(test)]
const ALERT_UNIT: &str = include_str!("../../../deploy/afteralert.service");
#[cfg(test)]
const SHIP_UNIT: &str = include_str!("../../../deploy/afterguard-ship.service");

pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => {
            println!("afterguard 0.1.0");
            Ok(0)
        }
        Some("check") => {
            let config = only(&flag_map(&args[1..])?, "--config")?;
            let loaded = Loaded::load(Path::new(config))?;
            run::check(&loaded)
        }
        Some("once") => {
            let (config, input) = pair(&flag_map(&args[1..])?, "--config", "--input")?;
            let loaded = Loaded::load(Path::new(config))?;
            run::once(loaded, Path::new(input))
        }
        Some("run") => {
            let config = only(&flag_map(&args[1..])?, "--config")?;
            let loaded = Loaded::load(Path::new(config))?;
            let mut runtime = Runtime::new(loaded)?;
            loop {
                match runtime.run_passes(1)? {
                    3 => return Ok(3),
                    _ => thread::sleep(Duration::from_secs(1)),
                }
            }
        }
        Some("ship") => {
            let config = only(&flag_map(&args[1..])?, "--config")?;
            let loaded = Loaded::load(Path::new(config))?;
            let cfg = loaded
                .ship
                .clone()
                .ok_or_else(|| Error::Invalid("ship not configured".to_owned()))?;
            let mut shipper = Shipper::new(loaded.ledger.clone(), cfg)?;
            loop {
                let pass = shipper.pass(run::now_ms()?)?;
                if pass.failed {
                    eprintln!(
                        "afterguard: ship: darksignal did not take the row (retry ack, unknown ack, or socket error); backing off {}s",
                        shipper.wait().as_secs()
                    );
                }
                thread::sleep(shipper.wait());
            }
        }
        Some("isolate") => isolate_cmd(&args[1..]),
        _ => Err(usage()),
    }
}

fn isolate_cmd(args: &[String]) -> Result<i32, Error> {
    match args {
        [cmd] if cmd == "apply" => isolate::apply().map(|()| 0),
        [cmd] if cmd == "deactivate" => {
            println!("{}", isolate::deactivate_recipe());
            Ok(0)
        }
        [cmd, flag, path] if cmd == "plan" && flag == "--config" && !path.starts_with('-') => {
            let loaded = Loaded::load(Path::new(path))?;
            match isolate::plan(&loaded.isolate) {
                Ok(text) => {
                    println!("{text}");
                    Ok(0)
                }
                Err(err) => {
                    eprintln!("isolate: {err}");
                    Ok(3)
                }
            }
        }
        _ => Err(usage()),
    }
}

fn usage() -> Error {
    Error::Invalid("usage".to_owned())
}

fn flag_map(args: &[String]) -> Result<HashMap<&str, &str>, Error> {
    let mut map = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if !key.starts_with("--") || key.len() < 3 {
            return Err(usage());
        }
        if map.contains_key(key) {
            return Err(usage());
        }
        let Some(value) = args.get(index + 1) else {
            return Err(usage());
        };
        if value.starts_with('-') {
            return Err(usage());
        }
        map.insert(key, value.as_str());
        index += 2;
    }
    Ok(map)
}

fn only<'a>(map: &HashMap<&'a str, &'a str>, key: &str) -> Result<&'a str, Error> {
    if map.len() != 1 {
        return Err(usage());
    }
    map.get(key).copied().ok_or_else(usage)
}

fn pair<'a>(
    map: &HashMap<&'a str, &'a str>,
    left: &str,
    right: &str,
) -> Result<(&'a str, &'a str), Error> {
    if map.len() != 2 {
        return Err(usage());
    }
    match (map.get(left).copied(), map.get(right).copied()) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(usage()),
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

    fn once(fix: &Fixture, body: &str) -> Result<i32, Error> {
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
        assert!(matches!(err, Error::NotInDebut(_)));
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
            .unwrap(),
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
