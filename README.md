# cveguard

Enforcement and response plane for the After Dark host toolkit. `nocved`
answers what happened, in order, off the host. `aftercve` answers what is on
the host right now, and it is the only tool that stops a process. `cveguard`
answers whether a local rule would allow the event, and it writes a decision
the operator can roll back.

Status: debut, not deployed.

## Binaries

| Binary | Role |
| --- | --- |
| `afterguard` | Long-running decision daemon. Default mode is shadow. |
| `afteralert` | Reads the decision ledger and serves Prometheus text on `127.0.0.1`. |
| `afterseal` | SHA-256 pin and census of the toolchain binaries. Detect and alarm. |

## What this debut does

- Shared userspace ring (`CGR1`). Full ring drops the newest record and counts `lost`.
- Rule pack: first match, every predicate must match, a rule cannot outrank policy mode.
- One-way intel from nocved events and aftercve findings. Imports stay shadow.
- Container id join (64 hex, runtime hint) and process lineage (`generation`).
- nftables *plan* for loopback, operator-set local CIDRs, whitelist, management addresses, and the nocved store when `keep_store` is set. Deadman recipe is printed, not applied.
- Empty capability bounding set. `NoNewPrivileges`. `check` does not call `capset`.
- Append-only decision ledger, mode 0600, hard cap.
- Action budget, toolchain-descendant suppression, seal mismatch halt.
- `afteralert` publishes every `cveguard_decisions_total{action,outcome}` series plus ring, tamper, rules, enforce, and ledger-parse gauges. No plan text in the labels.

## What this debut does not do

It does not load eBPF, run `nft`, stop a process, disable an account, hide a
process, edit nocved or aftercve, or remote-write Prometheus. `isolate apply`
returns `isolate apply is not in the debut build`. The probe note is
`probe/README.md`: Linux 6.1+ with BTF and `bpf-linker` 0.11.1, not in this
workspace.

## Build

```bash
rustup run 1.97.1 cargo fmt --check
rustup run 1.97.1 cargo clippy --all-targets --all-features --locked -- -D warnings
rustup run 1.97.1 cargo test --all-features --locked
```

Pinned to Rust 1.97.1. Homebrew `cargo` on this Mac can shadow rustup.

## Commands

```bash
afterguard check --config deploy/config.example.json
afterguard once --config deploy/config.example.json --input events.jsonl
afterguard run --config /etc/cveguard/config.json
afterguard isolate plan --config deploy/config.example.json
afterguard isolate deactivate
afterguard isolate apply

afteralert serve --listen 127.0.0.1:8752 --ledger /var/lib/cveguard/decisions.jsonl

afterseal pin --out /var/lib/cveguard/seal.json --path /usr/local/bin/afterguard
afterseal verify --seal /var/lib/cveguard/seal.json
afterseal census
```

`deploy/afterguard.service` and `deploy/afteralert.service` are sketches.
They are not installed by this tree. Example policy is shadow, local CIDR
`10.1.2.0/24`, management `192.0.2.10`, store `198.51.100.8`.

Exit `3` means the seal mismatched or enforce was refused (missing seal or
a plan that cannot be rendered). Exit `2` means a decision was rejected
(bad event, or an isolate match whose plan cannot be rendered). Shadow with
a missing seal can `check` and `once`.
