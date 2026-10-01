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
use cveguard_proto::seal::{self, SealStatus};
use serde::Deserialize;

const CONFIG_MAX: usize = 64 * 1024;
const DEFAULT_WINDOW_MS: u64 = 60_000;
const DEFAULT_MAX_ACTIONS: u32 = 10;
const DEFAULT_RING_CAP: usize = 256;
const DEFAULT_LEDGER_MAX: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    window_ms: u64,
    max_actions: u32,
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
        })
    }

    #[must_use]
    pub fn seal_status(&self) -> SealStatus {
        match &self.seal {
            Some(path) => seal::verify(path),
            None => SealStatus::Missing,
        }
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
    }
}
