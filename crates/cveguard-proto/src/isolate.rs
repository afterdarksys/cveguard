//! nftables isolate *plan*. Nothing here runs nft, conntrack, or systemd-run.
//!
//! Threats: a world route, a prefix wider than /16, or an implicit RFC1918
//! allow would either lock the operator out or leave the fleet routable.
//! Management addresses are mandatory. The debut build refuses to apply a plan.
//!
//! The plan is a shell recipe in a fixed order:
//! 1. Arm the deadman: a transient systemd timer that deletes the table after
//!    `deadman_secs`. It runs first, so a ruleset that locks the operator out
//!    still rolls back. `set -eu` stops the recipe if arming fails.
//! 2. Load the table. Input accepts only loopback and packets whose *source*
//!    is in the allow set; output accepts only loopback and packets whose
//!    *destination* is in the allow set. Established traffic is not
//!    blanket-accepted, so a C2 session that predates isolation is dropped.
//!    The host's own address being in `local_cidrs` therefore opens nothing.
//! 3. Flush conntrack so no pre-isolation flow keeps state. Flows to allowed
//!    peers are re-tracked as new and re-accepted by the allow rules; flows to
//!    any other peer are dropped by policy.
//!
//! Not covered: IPv6 has no allow set, so every non-loopback IPv6 packet is
//! dropped. A rooted host can delete the table or the timer.

use serde::{Deserialize, Serialize};

use crate::cidr::{Net, parse_allow};
use crate::error::{Error, invalid};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolateSpec {
    #[serde(default)]
    pub local_cidrs: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub management_ips: Vec<String>,
    #[serde(default)]
    pub store_ips: Vec<String>,
    #[serde(default)]
    pub keep_store: bool,
    pub deadman_secs: u32,
}

#[must_use]
pub fn deactivate_recipe() -> &'static str {
    "nft delete table inet cveguard"
}

pub fn apply() -> Result<(), Error> {
    Err(Error::NotInDebut("isolate apply is not in the debut build"))
}

pub fn plan(spec: &IsolateSpec) -> Result<String, Error> {
    if !(60..=900).contains(&spec.deadman_secs) {
        return Err(invalid("deadman rejected"));
    }
    if spec.management_ips.is_empty() {
        return Err(invalid("management ips required"));
    }
    if spec.keep_store && spec.store_ips.is_empty() {
        return Err(invalid("store ips required"));
    }
    let mut nets = vec![Net::loopback()];
    let listed = spec
        .local_cidrs
        .iter()
        .chain(spec.whitelist.iter())
        .chain(spec.management_ips.iter());
    for item in listed {
        nets.push(parse_allow(item)?);
    }
    if spec.keep_store {
        for item in &spec.store_ips {
            nets.push(parse_allow(item)?);
        }
    }
    nets.sort();
    nets.dedup();
    let elements = nets
        .iter()
        .copied()
        .map(Net::format)
        .collect::<Vec<_>>()
        .join(", ");
    let revert = deactivate_recipe();
    Ok(format!(
        "\
#!/bin/sh
# cveguard isolate plan. Printed by cveguard, never run by it.
set -eu
# step 1: deadman. Scheduled rollback removes the table after {deadman}s.
systemd-run --unit=cveguard-deadman --on-active={deadman}s {revert}
# step 2: ruleset.
nft -f - <<'CVEGUARD_NFT'
table inet cveguard {{
\tset allow4 {{
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = {{ {elements} }}
\t}}
\tchain input {{
\t\ttype filter hook input priority 0; policy drop;
\t\tiif \"lo\" accept
\t\tip saddr @allow4 ct state established,related,new accept
\t}}
\tchain output {{
\t\ttype filter hook output priority 0; policy drop;
\t\toif \"lo\" accept
\t\tip daddr @allow4 ct state established,related,new accept
\t}}
}}
CVEGUARD_NFT
# step 3: drop tracked flows; allow-set peers re-match as new, others drop.
conntrack -F
# keep isolation past the deadman: systemctl stop cveguard-deadman.timer
# revert now: {revert}
",
        deadman = spec.deadman_secs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> IsolateSpec {
        IsolateSpec {
            local_cidrs: vec!["10.1.2.3/16".into()],
            whitelist: vec!["192.0.2.20".into()],
            management_ips: vec!["192.0.2.10".into()],
            store_ips: vec!["198.51.100.8".into()],
            keep_store: true,
            deadman_secs: 120,
        }
    }

    #[test]
    fn plan_masks_sorts_and_drops_by_default() {
        let text = plan(&sample()).unwrap();
        assert!(text.contains("policy drop"));
        assert!(text.contains("iif \"lo\""));
        assert!(text.contains("10.1.0.0/16"));
        assert!(!text.contains("10.1.2.3"));
        assert!(!text.contains("0.0.0.0/0"));
        assert!(text.contains("nft delete table inet cveguard"));
        let allow = text
            .lines()
            .find(|l| l.contains("elements"))
            .unwrap()
            .to_owned();
        let again = allow.clone();
        assert!(allow.find("10.1.0.0/16").unwrap() < again.find("127.0.0.0/8").unwrap());
    }

    #[test]
    fn plan_rejects_world_short_prefix_zero_and_missing_management() {
        let mut spec = sample();
        spec.local_cidrs = vec!["0.0.0.0/0".into()];
        assert!(plan(&spec).is_err());
        spec.local_cidrs = vec!["01.2.3.4/32".into()];
        assert!(plan(&spec).is_err());
        spec.local_cidrs = vec!["10.0.0.0/8".into()];
        assert!(plan(&spec).is_err());
        spec.local_cidrs = vec!["0.0.0.0/32".into()];
        assert!(plan(&spec).is_err());
        spec.local_cidrs.clear();
        spec.management_ips.clear();
        assert!(plan(&spec).unwrap_err().to_string().contains("management"));
        spec.management_ips = vec!["192.0.2.10".into()];
        spec.store_ips.clear();
        assert!(plan(&spec).unwrap_err().to_string().contains("store"));
        spec.keep_store = false;
        spec.deadman_secs = 59;
        assert!(plan(&spec).is_err());
        spec.deadman_secs = 901;
        assert!(plan(&spec).is_err());
    }

    fn chain<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
        let head = format!("chain {name} {{");
        text.lines()
            .skip_while(|l| l.trim() != head)
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .map(str::trim)
            .collect()
    }

    fn commands(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    #[test]
    fn plan_filters_by_peer_direction() {
        let text = plan(&sample()).unwrap();
        let input = chain(&text, "input");
        let output = chain(&text, "output");
        assert!(!input.is_empty() && !output.is_empty());
        assert!(input.iter().all(|l| !l.contains("ip daddr @allow4")));
        assert!(output.iter().all(|l| !l.contains("ip saddr @allow4")));
        assert!(input.contains(&"ip saddr @allow4 ct state established,related,new accept"));
        assert!(output.contains(&"ip daddr @allow4 ct state established,related,new accept"));
        assert!(input.contains(&"iif \"lo\" accept"));
        assert!(output.contains(&"oif \"lo\" accept"));
    }

    #[test]
    fn established_is_not_blanket_accepted() {
        let text = plan(&sample()).unwrap();
        for line in text.lines().filter(|l| l.contains("ct state")) {
            assert!(line.contains("@allow4"), "{line}");
        }
        for name in ["input", "output"] {
            for line in chain(&text, name) {
                let is_lo = line == "iif \"lo\" accept" || line == "oif \"lo\" accept";
                assert!(
                    is_lo || line.contains("@allow4") || line.starts_with("type filter"),
                    "{line}"
                );
            }
        }
        let cmds = commands(&text);
        assert!(cmds.contains(&"conntrack -F"));
    }

    #[test]
    fn deadman_is_a_real_first_step() {
        let text = plan(&sample()).unwrap();
        let cmds = commands(&text);
        let deadman = cmds
            .iter()
            .position(|l| {
                *l == "systemd-run --unit=cveguard-deadman --on-active=120s nft delete table inet cveguard"
            })
            .unwrap();
        let load = cmds.iter().position(|l| l.starts_with("nft -f -")).unwrap();
        let flush = cmds.iter().position(|l| *l == "conntrack -F").unwrap();
        assert!(deadman < load && load < flush);
        assert!(cmds.contains(&"set -eu"));
    }

    #[test]
    fn apply_is_not_in_the_debut() {
        let err = apply().unwrap_err();
        assert!(matches!(err, Error::NotInDebut(_)));
        assert_eq!(err.to_string(), "isolate apply is not in the debut build");
        assert_eq!(deactivate_recipe(), "nft delete table inet cveguard");
    }
}
