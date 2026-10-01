//! Shared cveguard contract.
//!
//! Threats: a rooted host can forge local events, replace binaries, and stop
//! the daemon. Seal digests are compared in constant time. Imported intel
//! cannot become an enforce decision. Isolate output is a plan, never a
//! command. This crate does not load eBPF and does not run nftables.

#![deny(unsafe_code)]

pub mod chain;
pub mod cidr;
pub mod counts;
pub mod error;
pub mod fs;
pub mod intel;
pub mod isolate;
pub mod model;
pub mod ring;
pub mod seal;

pub use error::Error;
pub use model::{
    Action, ActionBudget, DECISION_SCHEMA_VERSION, Decision, GuardEvent, Mode, Origin, Outcome,
    Reason, Rule, SCHEMA_VERSION,
};
