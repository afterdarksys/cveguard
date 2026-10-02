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
- `afterguard ship` frames each new row for darksignal (u32 LE length + JSON, one connection per row, ack `0x01` advance, `0x00` advance and log as refused, `0x02` or anything else retry the same row), keeps a 0600 `(epoch, seq)` cursor that survives restart and ledger rotation, and backs off 1 s doubling to 60 s.
- Action budget, seal mismatch halt, seal re-verified every `seal_recheck_passes` passes (default 60). Toolchain suppression is by sealed identity only (canonical path plus dev/ino); `comm` and basenames never exempt a process.
- `afteralert` publishes every `cveguard_decisions_total{action,outcome}` series (cumulative across ledger rotations via `<ledger>.retired`) plus ring, tamper, rules, enforce, ledger-parse, ledger-drops, and `cveguard_ledger_chain_ok` gauges, and the feed counters `cveguard_feed_bad_lines`, `cveguard_feed_events_replaced`, and `cveguard_feed_gaps`. No plan text in the labels. Idle clients time out after 2 s.

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

Release builds embed the locked crate list with cargo-auditable 0.7.6: `cargo auditable build --locked --release`. `cargo audit bin` reads that list from `afterguard`, `afteralert`, and `afterseal`.

## Commands

```bash
afterguard check --config deploy/config.example.json
afterguard once --config deploy/config.example.json --input events.jsonl
afterguard run --config /etc/cveguard/config.json
afterguard ship --config /etc/cveguard/config.json
afterguard status --config /etc/cveguard/config.json [--json]
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
manifest is a mismatch. `verify --json` and `census --json` print the
output envelope plus
`"status":"valid|missing|mismatch","reason":"sealed|seal_missing|seal_mismatch"`;
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

## CLI output and exit codes

Contract: [`docs/output-contract.md`](docs/output-contract.md). Every command
of `afterguard`, `afteralert`, and `afterseal` accepts `--json` (alias
`--format json`; `--format text` is the default). With `--json`, stdout is
exactly one compact JSON object, newline-terminated; the daemons (`run`,
`ship`, `serve`) print nothing on stdout. Diagnostics go to stderr. There
are no machine-primary commands: every command defaults to human text.

Every document starts with the envelope:

```json
{"schema_version":1,"kind":"afterguard.check","tool":"afterguard","tool_version":"0.1.0", ...}
```

| Command | Default | `kind` | Exit codes |
| --- | --- | --- | --- |
| `afterguard version` | human | `afterguard.version` | 0, 1 |
| `afterguard check --config P` | human (`key=value` lines, then the plan) | `afterguard.check` | 0, 1, 3 (seal mismatch or enforce blocked; result still printed) |
| `afterguard once --config P --input P` | human (`key=value` summary) | `afterguard.once` | 0, 1, 2 (a row was rejected), 3 (seal or enforce gate; summary still printed with `stopped`) |
| `afterguard run --config P` | daemon, no stdout | status file `afterguard.status` | 1, 3 (integrity stop; stderr says why) |
| `afterguard ship --config P` | daemon, no stdout | status file `afterguard.status` | 1 |
| `afterguard status --config P` | human (one line per daemon) | `afterguard.status` | 0, 1, 11 (a configured daemon's status is missing or stale) |
| `afterguard isolate plan --config P` | human (the recipe) | `afterguard.isolate.plan` | 0, 1, 3 (plan cannot be rendered; JSON error) |
| `afterguard isolate deactivate` | human | `afterguard.isolate.deactivate` | 0 |
| `afterguard isolate apply` | always an error | `error`, category `refused` | 1 |
| `afteralert version` | human | `afteralert.version` | 0, 1 |
| `afteralert serve ...` | daemon, no stdout | `/metrics` is its status | 1 |
| `afterseal version` | human | `afterseal.version` | 0, 1 |
| `afterseal pin --out P --path B ...` | human (`pinned N entries to P`) | `afterseal.pin` | 0, 1 |
| `afterseal verify --seal P` | human (status word) | `afterseal.verify` | 0, 1, 3 (missing or mismatch; result still printed) |
| `afterseal census --seal P` | human (`name status` lines) | `afterseal.census` | 0, 1, 3 (missing or mismatch; result still printed) |

`<tool> --help`, `<tool> <command> --help`, `-h`, and `<tool> help [command]`
print usage, flags, and exit codes on stdout and exit 0. `<tool> --version`
works like `version`. An unknown command, flag, or a repeated flag is a usage
error.

Exit `1` is every error, including usage and config errors, as it was before
the contract (`2` already means "a decision was rejected" in afterguard).
Exit `3` is an integrity stop or permanent refusal. Exit `11` is
`afterguard status` reporting a missing or stale daemon.

Errors: in `--json` mode every failure, including usage errors, is one line
on stderr and nothing on stdout:

```json
{"schema_version":1,"kind":"error","tool":"afterguard","command":"check","category":"config","message":"config: No such file or directory (os error 2)","exit_code":1}
```

`category` is `usage`, `config`, `io`, `refused`, `integrity`, or
`internal` here. `command` is the dotted command (`isolate.plan`) or `null`.
In text mode the error is one line, `<tool>: <message>`. Control and bidi
characters in messages are escaped.

Status files (mode 0600, written atomically, `kind` `afterguard.status`,
`updated_at_ms`, and `daemon`):

- `afterguard run` (and `once`) writes the config's `status` path
  (`/var/lib/cveguard/status.json` in the example) every pass, about once a
  second, and before it stops. The envelope fields and `daemon`,
  `updated_at_ms`, and `stop_reason` (when stopped) were added; every
  earlier field is unchanged, and `afteralert --gauges` reads it as before.
- `afterguard ship` writes `<cursor>.status.json`
  (`/var/lib/cveguard/ship.cursor.status.json` by default) after every pass,
  at least every 10 s during a backoff, and before a fatal error: `sent`,
  `refused`, `missed` (from the cursor), `retried` (since this process
  started), `cursor` `{epoch, seq}`, `backoff_ms`, `last_error`,
  `last_error_at_ms`. A kill signal does not write a final status; the file
  then goes stale.
- `afterguard status --config P [--json]` reads both without any lock and
  reports `stale: true` when `updated_at_ms` is missing or more than 30 s
  (three write intervals) away from now. A status file that is a symlink or
  group/other writable is an `io` error; one that is not JSON is `integrity`.
- `afteralert serve` has no status file: a successful `/metrics` scrape is
  its health.
