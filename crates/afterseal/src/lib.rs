//! Toolchain pin and census. Detection only: nothing here hides a process.
//!
//! Threats: an empty pin would record a seal that matches every host. A
//! replaced binary must show up as a mismatch. The census is a name list,
//! not an allow action.

#![deny(unsafe_code)]

mod dispatch;

pub use dispatch::dispatch;

#[must_use]
pub fn toolchain_names() -> &'static [&'static str] {
    &[
        "nocved",
        "nocve-store",
        "aftercve",
        "afterguard",
        "afteralert",
        "afterseal",
    ]
}
