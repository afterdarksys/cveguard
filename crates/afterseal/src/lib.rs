//! Toolchain pin and census. Detection only: nothing here hides a process.
//!
//! Threats: an empty pin would record a seal that matches every host. A
//! replaced binary must show up as a mismatch. The census hashes each of the
//! six toolchain binaries named in the manifest; it is a report, not an
//! allow action.

#![deny(unsafe_code)]

mod dispatch;

pub use dispatch::dispatch;

#[must_use]
pub fn toolchain_names() -> &'static [&'static str] {
    &cveguard_proto::seal::CENSUS
}
