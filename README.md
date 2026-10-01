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
| `afterguard` | Long-running decision daemon. Default mode is shadow. `afterguard ship` sends ledger rows to the local darksignal socket. |
| `afteralert` | Reads the decision ledger and serves Prometheus text on `127.0.0.1`. |
| `afterseal` | SHA-256 pin and census of the toolchain binaries. Detect and alarm. |

## What this debut does

- Shared userspace ring (`CGR1`). Full ring drops the newest record and counts `lost`.
- Rule pack: first match, every predicate must match, a rule cannot outrank policy mode.
- One-way intel from nocved events (bare lines or spool envelopes; the envelope MAC is not verified) and aftercve findings. Imports stay shadow. An invalid `comm` is dropped and flagged `comm_invalid`; evaluation continues on `exe`. argv shape never drops an event: it is cut to 64 entries of 512 bytes with control characters escaped, and the decision says `args_truncated`. `net.listen` and IPv6 `net.connect` / `net.listen` lines are accepted. The producer's own rule (nocved signal, aftercve `rule_id`) is kept as `source_rule_id`.
- The feed tail follows nocved's rotation (`events.jsonl` to `events.jsonl.1`) by draining the old inode before the new one; a rotation it could not follow, a shrink, or an envelope `seq` jump is a `feed_gap` row and `events_gap` in `status.json`.
- Container id join (64 hex, runtime hint) and process lineage (`generation`).
- Isolate *recipe* (printed shell, never run): arm a `systemd-run` deadman that deletes the table, load an nftables table that accepts only loopback and allow-set peers (input by source, output by destination, no blanket `established`), then `conntrack -F`. Allow set is loopback, operator-set local CIDRs, whitelist, management addresses, and the nocved store when `keep_store` is set.
- Empty capability bounding set. `NoNewPrivileges`. `check` does not call `capset`.
- Hash-chained decision ledger (`epoch`, `seq`, `prev`), schema 3, mode 0600, `flock`-serialized writers. A full ledger rotates to `decisions.jsonl.1`; the daemon keeps running. Rows carry `severity` (from the rule pack, default medium) and `source_rule_id`. The row shape darksignal consumes is "Decision row" in `DESIGN.md`.
- `afterguard ship` frames each new row for darksignal (u32 LE length + JSON, one connection per row, ack `0x01`/`0x00`), keeps a 0600 `(epoch, seq)` cursor that survives restart and ledger rotation, and backs off on socket errors.
- Action budget, seal mismatch halt, seal re-verified every `seal_recheck_passes` passes (default 60). Toolchain suppression is by sealed identity only (canonical path plus dev/ino); `comm` and basenames never exempt a process.
- `afteralert` publishes every `cveguard_decisions_total{action,outcome}` series plus ring, tamper, rules, enforce, ledger-parse, ledger-drops, and `cveguard_ledger_chain_ok` gauges, and the feed counters `cveguard_feed_bad_lines`, `cveguard_feed_events_replaced`, and `cveguard_feed_gaps`. No plan text in the labels. Idle clients time out after 2 s.

## What this debut does not do

It does not load eBPF, run `nft`, stop a process, disable an account, hide a
process, edit nocved or aftercve, or remote-write Prometheus. The live ring
is not wired (no eBPF producer), so on a real host every decision comes from
the JSONL feed and stays shadow, and nothing enforces a `planned` decision.
Reading nocved's real spool needs a nocved-side feed readable by the
`cveguard` group; see "nocved feed" in `DESIGN.md`. `isolate apply`
returns `isolate apply is not in the debut build`. The probe note is
`probe/README.md`: Linux 6.1+ with BTF and `bpf-linker` 0.11.1, not in this
workspace.

## Build

```bash
rustup run 1.97.1 cargo fmt --check
rustup run 1.97.1 cargo clippy --all-targets --all-features --locked -- -D warnings
rustup run 1.97.1 cargo test --all-features --locked
cargo deny check
```

Pinned to Rust 1.97.1. Homebrew `cargo` on this Mac can shadow rustup.

## Commands

```bash
afterguard check --config deploy/config.example.json
afterguard once --config deploy/config.example.json --input events.jsonl
afterguard run --config /etc/cveguard/config.json
afterguard ship --config /etc/cveguard/config.json
afterguard isolate plan --config deploy/config.example.json
afterguard isolate deactivate
afterguard isolate apply

afteralert serve --listen 127.0.0.1:8752 --ledger /var/lib/cveguard/decisions.jsonl \
  --gauges /var/lib/cveguard/status.json

afterseal pin --out /var/lib/cveguard/seal.json \
  --path /usr/local/bin/nocved --path /usr/local/bin/nocve-store \
  --path /usr/local/bin/aftercve --path /usr/local/bin/afterguard \
  --path /usr/local/bin/afteralert --path /usr/local/bin/afterseal
afterseal verify --seal /var/lib/cveguard/seal.json [--json]
afterseal census --seal /var/lib/cveguard/seal.json [--json]
```

`afteralert --gauges` points at the `status.json` that `afterguard` writes
(config key `status`). It supplies `cveguard_ring_lost`,
`cveguard_tamper_mismatch`, `cveguard_rules_loaded`,
`cveguard_enforce_enabled`, `cveguard_ledger_drops`, the three
`cveguard_feed_*` counters, and the chain head that
`cveguard_ledger_chain_ok` checks. Without `--gauges` those gauges read 0 and
the chain check cannot detect truncation of the newest rows. A missing gauges
file is treated as empty; a symlinked or group-writable one fails the scrape.

`afterseal pin` must cover all six toolchain binaries; an empty or partial
manifest is a mismatch. `verify --json` and `census --json` print
`{"status":"valid|missing|mismatch","reason":"sealed|seal_missing|seal_mismatch"}`;
`census` also lists each binary. `census` hashes the files; it is a report,
not an allow list.

`deploy/afterguard.service`, `deploy/afterguard-ship.service`, and
`deploy/afteralert.service` are sketches. The ship unit adds
`SupplementaryGroups=darksignal-producers` so `cveguard` can reach the
darksignal socket (`0660` in a `0750` directory when darksignal sets
`socket_gid`).
They are not installed by this tree. Example policy is shadow, local CIDR
`10.1.2.0/24`, management `192.0.2.10`, store `198.51.100.8`.

Exit `3` means the seal mismatched (at start or at a periodic re-check) or
enforce was refused (missing seal or a plan that cannot be rendered). Exit `2` means a decision was rejected
(bad event or bad `once` line, which is recorded as a `rejected` row, a
`feed_gap` row, or an isolate match whose plan cannot be rendered). Shadow with
a missing seal can `check` and `once`.
