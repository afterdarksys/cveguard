//! Daemon configuration. Paths are resolved against the config file's directory.
//!
//! Threats: a missing field must not default to enforce. Any requested
//! capability is rejected. Rules are loaded with the same nofollow checks as
//! the seal. A rules error is a load failure, distinct from a seal mismatch.

use std::path::{Path, PathBuf};

use cveguard_proto::Error;
use cveguard_proto::fs::{self, FilePolicy};
use cveguard_proto::isolate::IsolateSpec;
use cveguard_proto::model::{ActionBudget, Mode, Rule, load_rules};
use cveguard_proto::seal::{self, SealCheck, SealStatus};
use serde::Deserialize;

use crate::ship::{ShipConfig, valid_host};

const CONFIG_MAX: usize = 64 * 1024;
const DEFAULT_WINDOW_MS: u64 = 60_000;
const DEFAULT_MAX_ACTIONS: u32 = 10;
const DEFAULT_RING_CAP: usize = 256;
const DEFAULT_LEDGER_MAX: u64 = 1024 * 1024;
const DEFAULT_SEAL_RECHECK_PASSES: u32 = 60;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    window_ms: u64,
    max_actions: u32,
}

/// `afterguard ship`: where darksignal listens and what host it expects.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShip {
    socket: String,
    host: String,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    mode: Mode,
    enabled: bool,
    rules: String,
    isolate: IsolateSpec,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    seal: Option<String>,
    #[serde(default)]
    ledger: Option<String>,
    #[serde(default)]
    events: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    ring_cap: Option<u64>,
    #[serde(default)]
    ledger_max: Option<u64>,
    #[serde(default)]
    budget: Option<RawBudget>,
    #[serde(default)]
    seal_recheck_passes: Option<u32>,
    #[serde(default)]
    ship: Option<RawShip>,
}

#[derive(Debug)]
pub struct Loaded {
    pub(crate) mode: Mode,
    pub(crate) enabled: bool,
    pub(crate) rules: Vec<Rule>,
    pub(crate) isolate: IsolateSpec,
    pub(crate) seal: Option<PathBuf>,
    pub(crate) ledger: PathBuf,
    pub(crate) events: Option<PathBuf>,
    pub(crate) status: Option<PathBuf>,
    pub(crate) ring_cap: usize,
    pub(crate) ledger_max: usize,
    pub(crate) budget: ActionBudget,
    pub(crate) seal_recheck_passes: u32,
    pub(crate) ship: Option<ShipConfig>,
}

impl Loaded {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read_trusted(path, CONFIG_MAX, FilePolicy::Config)?;
        let raw: RawConfig = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Schema("json rejected".to_owned()))?;
        crate::caps::reject_requested(&raw.capabilities)?;
        let (window_ms, max_actions) = match raw.budget {
            Some(budget) => (budget.window_ms, budget.max_actions),
            None => (DEFAULT_WINDOW_MS, DEFAULT_MAX_ACTIONS),
        };
        let budget = ActionBudget::new(window_ms, max_actions)?;
        let ring_cap = match raw.ring_cap {
            Some(value) => {
                let cap = usize::try_from(value)
                    .map_err(|_| Error::Invalid("ring cap rejected".to_owned()))?;
                if !(1..=4096).contains(&cap) {
                    return Err(Error::Invalid("ring cap rejected".to_owned()));
                }
                cap
            }
            None => DEFAULT_RING_CAP,
        };
        let ledger_max_u = raw.ledger_max.unwrap_or(DEFAULT_LEDGER_MAX);
        if !(64..=DEFAULT_LEDGER_MAX).contains(&ledger_max_u) {
            return Err(Error::Invalid("ledger max rejected".to_owned()));
        }
        let seal_recheck_passes = raw
            .seal_recheck_passes
            .unwrap_or(DEFAULT_SEAL_RECHECK_PASSES);
        if !(1..=86_400).contains(&seal_recheck_passes) {
            return Err(Error::Invalid("seal recheck rejected".to_owned()));
        }
        let ledger_max = usize::try_from(ledger_max_u)
            .map_err(|_| Error::Invalid("ledger max rejected".to_owned()))?;
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let rules = load_rules(&resolve(dir, &raw.rules))?;
        let ledger = match &raw.ledger {
            Some(value) => resolve(dir, value),
            None => dir.join("decisions.jsonl"),
        };
        let ship = raw
            .ship
            .map(|ship| ship_config(dir, &ledger, ship))
            .transpose()?;
        Ok(Self {
            mode: raw.mode,
            enabled: raw.enabled,
            rules,
            isolate: raw.isolate,
            seal: raw.seal.as_deref().map(|value| resolve(dir, value)),
            ledger,
            events: raw.events.as_deref().map(|value| resolve(dir, value)),
            status: raw.status.as_deref().map(|value| resolve(dir, value)),
            ring_cap,
            ledger_max,
            budget,
            seal_recheck_passes,
            ship,
        })
    }

    #[must_use]
    pub fn seal_check(&self) -> SealCheck {
        seal_check_at(self.seal.as_deref())
    }

    #[must_use]
    pub fn seal_status(&self) -> SealStatus {
        self.seal_check().status
    }
}

/// The socket must be absolute; the host must pass darksignal's grammar.
/// The cursor defaults to `ship.cursor` beside the ledger.
fn ship_config(dir: &Path, ledger: &Path, raw: RawShip) -> Result<ShipConfig, Error> {
    let socket = PathBuf::from(&raw.socket);
    if !socket.is_absolute() {
        return Err(Error::Invalid("ship socket rejected".to_owned()));
    }
    if !valid_host(&raw.host) {
        return Err(Error::Invalid("ship host rejected".to_owned()));
    }
    let cursor = match &raw.cursor {
        Some(value) => resolve(dir, value),
        None => ledger
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("ship.cursor"),
    };
    Ok(ShipConfig {
        socket,
        host: raw.host,
        cursor,
    })
}

#[must_use]
pub fn seal_check_at(path: Option<&Path>) -> SealCheck {
    match path {
        Some(path) => seal::check(path),
        None => SealCheck::of(SealStatus::Missing),
    }
}

fn resolve(dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        dir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_admin_capability_and_resolves_relative_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules.json");
        std::fs::write(
            &rules,
            br#"[{"id":"miner-exe","enabled":true,"action":"alert","mode":"shadow","when":[{"op":"exe_basename","equals":"xmrig"}]}]"#,
        )
        .unwrap();
        let config = dir.path().join("config.json");
        std::fs::write(
            &config,
            br#"{
                "mode":"shadow",
                "enabled":true,
                "rules":"rules.json",
                "capabilities":["CAP_SYS_ADMIN"],
                "isolate":{
                    "local_cidrs":["10.1.2.0/24"],
                    "management_ips":["192.0.2.10"],
                    "store_ips":["198.51.100.8"],
                    "keep_store":true,
                    "deadman_secs":120
                }
            }"#,
        )
        .unwrap();
        let err = Loaded::load(&config).unwrap_err();
        assert!(err.to_string().contains("capability rejected"));

        let ok_path = dir.path().join("ok.json");
        std::fs::write(
            &ok_path,
            br#"{
                "mode":"shadow",
                "enabled":true,
                "rules":"rules.json",
                "isolate":{
                    "local_cidrs":["10.1.2.0/24"],
                    "management_ips":["192.0.2.10"],
                    "store_ips":["198.51.100.8"],
                    "keep_store":true,
                    "deadman_secs":120
                }
            }"#,
        )
        .unwrap();
        let loaded = Loaded::load(&ok_path).unwrap();
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.seal_status(), SealStatus::Missing);
        assert!(loaded.budget.is_empty());
        assert_eq!(loaded.seal_recheck_passes, 60);
    }
}
