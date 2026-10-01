//! nftables isolate *plan*. Nothing here runs nft.
//!
//! Threats: a world route, a prefix wider than /16, or an implicit RFC1918
//! allow would either lock the operator out or leave the fleet routable.
//! Management addresses are mandatory. The debut build refuses to apply a plan.

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
table inet cveguard {{
\tset allow4 {{
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = {{ {elements} }}
\t}}
\tchain input {{
\t\ttype filter hook input priority 0; policy drop;
\t\tiif \"lo\" accept
\t\tct state established,related accept
\t\tip saddr @allow4 accept
\t\tip daddr @allow4 accept
\t}}
\tchain output {{
\t\ttype filter hook output priority 0; policy drop;
\t\toif \"lo\" accept
\t\tct state established,related accept
\t\tip daddr @allow4 accept
\t\tip saddr @allow4 accept
\t}}
}}
# deadman_secs {deadman}
# revert: {revert}
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

    #[test]
    fn apply_is_not_in_the_debut() {
        let err = apply().unwrap_err();
        assert!(matches!(err, Error::NotInDebut(_)));
        assert_eq!(err.to_string(), "isolate apply is not in the debut build");
        assert_eq!(deactivate_recipe(), "nft delete table inet cveguard");
    }
}
