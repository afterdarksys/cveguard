//! afterguard decides and records. It does not load eBPF, run nftables, or stop processes.
//!
//! Threats: a rooted host can stop the daemon and forge local events. Imported
//! intel cannot become an enforce decision. A seal mismatch halts evaluation.
//! Capability requests are rejected. Isolate output is a plan string.

#![deny(unsafe_code)]

pub mod caps;
pub mod config;
pub mod container;
pub mod dispatch;
pub mod engine;
pub mod ledger;
pub mod lineage;
pub mod run;
pub mod ship;
pub mod status;
pub mod tail;

pub use dispatch::dispatch;
