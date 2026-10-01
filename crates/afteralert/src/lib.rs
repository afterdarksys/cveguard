//! Prometheus text for cveguard decisions. Binds loopback only.
//!
//! Threats: metrics must not carry plans, arguments, or secrets. A ledger
//! that fails its mode, owner, or size check is not published as zeros.

#![deny(unsafe_code)]

mod dispatch;
mod serve;
mod snapshot;

pub use dispatch::dispatch;
