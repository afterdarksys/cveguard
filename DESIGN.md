# cveguard design

Debut dated 2026-10-01. Not deployed.

cveguard is the enforcement and response plane of the host toolkit.

- `nocved` records ordered host behaviour and ships it off the host. It does not mutate the host.
- `aftercve` describes the host as it is now. Process stop stays its only executable containment.
- `cveguard` decides whether a rule would allow an event, and how far the blast radius can shrink while a person looks.

A rooted host can still kill the daemon. The debut is there to slow the next step, make it loud, and leave a rollback recipe. It must not become a second root-equivalent path: no process hiding, no account edits, no capability grant, no firewall apply.

Default mode is **shadow**. Decisions are local. A rule cannot escalate above the policy mode. Imported intel cannot enforce.

## Binaries

| Binary | Debut behaviour |
| --- | --- |
| `afterguard` | Userspace daemon. Subcommands `check`, `once`, `run`, `isolate plan`, `isolate deactivate`, `isolate apply`, `version`. |
| `afteralert` | Prometheus text exporter. `serve --listen 127.0.0.1:8752 --ledger PATH`. |
| `afterseal` | SHA-256 manifest of regular files, plus a census of the six toolchain basenames. |

Operator control lives on `afterguard`. There is no seventh control binary.

## In this debut

1. **Shared ring.** Userspace single-consumer buffer in `cveguard-proto`. Magic `CGR1`, version 1, kinds exec/exit/connect. Payload is UTF-8 JSON, at most 1024 bytes. Push-when-full returns full, keeps the oldest records, and increments `lost`. A second consumer gets `Busy`. See `probe/README.md` for the header layout. The Linux eBPF producer is not compiled here.
2. **Rule engine.** At least one predicate. Predicates AND. First match wins. Disabled rules are skipped. Actions are `record`, `alert`, and `isolate`. Outcomes are `shadow`, `noted`, `planned`, `suppressed`, and `rejected`.
3. **Intel adapters.** nocved kinds `process.start`, `audit.exec`, `package.change`, `container.start`, `net.connect`, `net.listen`. aftercve findings are recognized by `correlation_key`, or by `schema_version` plus `rule_id` when `kind` is absent. Unknown nocved kinds are skipped. A file that claims `origin: ring` is rewritten to nocved before it is stored. Only `record_to_event` produces ring origin. Finding titles, explanations, and recommendations are not stored. Recommendations are not actions.
4. **Container join.** The first 64-hex run that is not part of a longer hex run. Runtime is the 32 bytes immediately before that run: `crio`, then `containerd`, then `docker`, otherwise `unknown`. The stored id is the first 12 hex characters, lowercase. Privileged is never inferred from cgroup text. Only an explicit `privileged: true` joins as privileged.
5. **Lineage.** Cap 4096 nodes. `observe_start` replaces a reused pid and stores the parent generation. Walk stops at depth 32, at ppid 0, on a generation mismatch, or on a cycle. Decisions store at most 8 ancestors. The protected check uses the full walk. Field name is `generation`. Exit does not delete the node.
6. **Isolate plan.** Pure nftables text for table `inet cveguard`. Loopback is hardcoded (`iif "lo"`, `127.0.0.0/8`). The operator sets `local_cidrs`, `whitelist`, and `management_ips`. `store_ips` are added when `keep_store` is true. Prefixes are /16 through /32. `0.0.0.0/0`, `::/0`, leading zeros, and a masked network of `0.0.0.0` are rejected. RFC1918 is not implied. Management addresses are mandatory. `keep_store` with an empty store list is rejected. Deadman is 60 to 900 seconds. `isolate apply` returns `isolate apply is not in the debut build`. `isolate deactivate` prints `nft delete table inet cveguard` and returns 0. Established, related, loopback, and the allow sets; policy drop. Elements are sorted and deduped. The example uses TEST-NET: local `10.1.2.0/24`, whitelist `192.0.2.20/32`, management `192.0.2.10`, store `198.51.100.8`, deadman 120.
7. **Capability plan.** Bounding set empty. Ambient set empty. `no_new_privs=yes`. Any requested capability in config is `capability rejected`, including names that would administer the network or read other processes. `check` prints the plan and does not call `capset`. `afteralert` parses only `127.0.0.1` and rejects port 0.
8. **Seal.** `afterseal pin` hashes regular files (nofollow, cap 32 MiB, at most 64 entries) and writes a mode-0600 manifest. Compare is constant-time on the raw 32-byte digests. Symlink, bad mode, bad owner, bad hex, oversize, and a hash mismatch are `Mismatch`. A missing path is `Missing`. Other IO on the seal file is `Mismatch`. The census names are `nocved`, `nocve-store`, `aftercve`, `afterguard`, `afteralert`, `afterseal`. A protected basename on the event, or on any ancestor in the full walk, suppresses the decision with reason `protected` and no isolate plan. A child of a toolchain binary is not acted on. The census is never an action.
9. **Ledger.** Append-only JSONL, mode 0600, `O_NOFOLLOW`, default cap 1 MiB (`ledger_max` 64 bytes through 1 MiB). A failed write restores the previous length. A brand-new file that fails the size check is removed. An existing file with the wrong mode is not chmodded.
10. **Budget.** Window uses event time. Ring events are stamped with the daemon clock. A backwards clock keeps existing hits and fails closed at the cap. Shadow decisions do not consume the budget. Default window 60s, 10 actions. Configured window is 1 ms through 24 h, max actions 1 through 1000.
11. **JSONL tail.** If the file shrinks below the cursor, the tail sets a sticky gap, jumps to the new length, and does not replay. Lines over 8192 bytes are rejected and the cursor advances. A trailing partial line waits.
12. **Metrics.** `afteralert` always emits all 15 `cveguard_decisions_total{action,outcome}` series plus `cveguard_ring_lost`, `cveguard_tamper_mismatch`, `cveguard_rules_loaded`, `cveguard_enforce_enabled`, and `cveguard_ledger_parse_errors`. No timestamps. No argv, secret, or plan labels. Non-GET is 400. Any path other than `/metrics` is 404. Invalid UTF-8 is 400. A header whose blank line ends past 2048 bytes is 400. A missing ledger is empty series and zero parse errors. A ledger over 1 MiB, a symlink, or a mode other than 0600 refuses the scrape. Load failure fails the process; it does not publish zeros for a file that exists and is unreadable.

## Decision order

Seal mismatch writes exactly one noted alert per run (`subject` `afterseal`, action `alert`, outcome `noted`, reason `seal_mismatch`, origin `ring`, `observed_at_ms` 0) and then stops. Exit 3. That path runs before input is parsed, so a bad line cannot hide a mismatch.

Enforce refuses to start when the seal is not valid or the isolate plan cannot be rendered. Exit 3, no ordinary decisions. Shadow with a missing seal can run. Shadow with an invalid plan still runs; an isolate match becomes `rejected` / `plan_invalid` (exit 2). Exit 3 wins over exit 2.

Isolate match, after the plan renders:

1. Protected self or ancestor: `suppressed` / `protected`, no plan.
2. Policy not enforce: `shadow` / `policy_shadow`, with plan.
3. Rule not enforce: `shadow` / `rule_shadow`, with plan.
4. Origin not ring: `shadow` / `imported_intel`, with plan.
5. Seal missing: `suppressed` / `seal_missing`, no plan.
6. Seal mismatch: `suppressed` / `seal_mismatch`, no plan.
7. Budget miss: `suppressed` / `budget`, with plan.
8. Else: `planned` / `matched`, with plan.

Alert and record: protected first. Otherwise, if the decision is not (policy enforce AND rule enforce AND origin ring AND seal valid), shadow with reason priority `imported_intel`, `seal_mismatch`, `seal_missing`, `policy_shadow`, `rule_shadow`. Then the budget. A miss is `suppressed` / `budget`. Otherwise `noted` / `matched`.

Invalid events are `rejected` / `schema` and the pass continues, except `once`, which parses the whole file first and appends nothing if any line fails.

`run` counts bad lines and continues. It ignores exit 2 and stops on exit 3.

## CVE citation

cveguard is not a scanner. A rule may store `CVE-YYYY-NNNN` (case-sensitive `CVE-`, four-digit year, four to seven digit number) beside an exact package name and version. `1.2.3` does not match `1.2.3-1`. Package facts come from nocved `package.change` (`version_new`; a null version is skipped) or from an aftercve observation. The example rule cites fictional `example-miner` `1.2.3` and `CVE-2099-0001`. The CVE is copied from the rule. It is not required on the event.

## Files

Config is at most 64 KiB, rules and `once` input at most 1 MiB, ring cap 1 through 4096 (default 256). `deny_unknown_fields` on config and rules. Mode and `enabled` are required; there is no default enforce. Paths in the config are resolved against the config file's directory. Opens use `O_NOFOLLOW`. Group or other write is rejected. Owner is root or the current uid. Ledger and seal mode are exactly 0600.

`afterguard check` prints mode, enabled, rule count, seal word, the capability plan, and the isolate plan or its error. It does not append the ledger or write status. Exit 3 on mismatch, or when mode is enforce and the seal is not valid or the plan is invalid.

## Explicitly not in this debut

Loading eBPF. Applying nftables. Killing processes. Disabling accounts. Hiding processes. Editing nocved or aftercve. Fleet deploy. Prometheus remote write. A CI workflow that claims the build is qualified. A journald parser. Claiming the probe works.

The nocved chain does not depend on the guard. The guard reads nocved and aftercve JSON and writes a ledger aftercve could collect later.

## systemd sketches

`deploy/afterguard.service` drops the bounding and ambient sets, sets `NoNewPrivileges=yes`, `PrivateNetwork=yes`, and `RestrictAddressFamilies=AF_UNIX`. `deploy/afteralert.service` allows localhost and denies any other address. Neither unit is installed by this repository. Both use `User=cveguard`.
