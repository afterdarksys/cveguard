//! Capability plan for the debut daemon. Nothing here calls capset.
//!
//! Threats: CAP_SYS_ADMIN, CAP_NET_ADMIN, and CAP_SYS_PTRACE would turn the
//! guard into a new root-equivalent path. The debut grants an empty bounding
//! set. A config that asks for any capability is rejected.

use cveguard_proto::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapPlan {
    pub bounding: Vec<String>,
    pub ambient: Vec<String>,
    pub no_new_privs: bool,
}

#[must_use]
pub fn debut_plan() -> CapPlan {
    CapPlan {
        bounding: Vec::new(),
        ambient: Vec::new(),
        no_new_privs: true,
    }
}

pub fn reject_requested(caps: &[String]) -> Result<(), Error> {
    if caps.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid("capability rejected".to_owned()))
    }
}

#[must_use]
pub fn format_plan(plan: &CapPlan) -> String {
    format!(
        "bounding={} ambient={} no_new_privs={}",
        plan.bounding.join(","),
        plan.ambient.join(","),
        if plan.no_new_privs { "yes" } else { "no" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debut_plan_is_empty_and_requests_are_rejected() {
        let plan = debut_plan();
        assert!(plan.bounding.is_empty());
        assert!(plan.ambient.is_empty());
        assert!(plan.no_new_privs);
        let text = format_plan(&plan);
        assert!(!text.contains("CAP_NET_ADMIN"));
        assert!(!text.contains("CAP_SYS_ADMIN"));
        assert!(!text.contains("CAP_SYS_PTRACE"));
        assert!(reject_requested(&[]).is_ok());
        for name in [
            "CAP_SYS_ADMIN",
            "CAP_NET_ADMIN",
            "CAP_SYS_PTRACE",
            "CAP_DAC_READ_SEARCH",
        ] {
            let err = reject_requested(&[name.to_owned()]).unwrap_err();
            assert!(err.to_string().contains("capability rejected"));
        }
    }
}
