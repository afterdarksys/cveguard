# cveguard design

Debut dated 2026-10-01. Not deployed. Revised 2026-10-01 after an independent security review (findings A1 to A8, L1 to L4), and again after the cross-repo end-to-end run (B1 to B4, B10, P7).

cveguard is the enforcement and response plane of the host toolkit.

- `nocved` records ordered host behaviour and ships it off the host. It does not mutate the host.
- `aftercve` describes the host as it is now. Process stop stays its only executable containment.
- `cveguard` decides whether a rule would allow an event, and how far the blast radius can shrink while a person looks.

A rooted host can still kill the daemon. The debut is there to slow the next step, make it loud, and leave a rollback recipe. It must not become a second root-equivalent path: no process hiding, no account edits, no capability grant, no firewall apply.

Default mode is **shadow**. Decisions are local. A rule cannot escalate above the policy mode. Imported intel cannot enforce.

## Binaries

| Binary | Debut behaviour |
| --- | --- |
| `afterguard` | Userspace daemon. Subcommands `check`, `once`, `run`, `ship`, `isolate plan`, `isolate deactivate`, `isolate apply`, `version`. |
| `afteralert` | Prometheus text exporter. `serve --listen 127.0.0.1:8752 --ledger PATH`. |
| `afterseal` | SHA-256 manifest of regular files (`pin`, `verify`), plus a `census` that hashes each of the six toolchain binaries named in the manifest. `verify` and `census` take `--json` and print `{"status","reason"}` (`census` adds `binaries`). |

Operator control lives on `afterguard`. There is no seventh control binary.

## In this debut

1. **Shared ring.** Userspace single-consumer buffer in `cveguard-proto`. Nothing produces into it on a real host yet: the live eBPF ring is not wired, so `run` sees only the JSONL tail. Magic `CGR1`, version 1, kinds exec/exit/connect. Payload is UTF-8 JSON, at most 1024 bytes. Push-when-full returns full, keeps the oldest records, and increments `lost`. A second consumer gets `Busy`. See `probe/README.md` for the header layout. The Linux eBPF producer is not compiled here.
2. **Rule engine.** At least one predicate. Predicates AND. First match wins. Disabled rules are skipped. Actions are `record`, `alert`, and `isolate`. Outcomes are `shadow`, `noted`, `planned`, `suppressed`, and `rejected`.
3. **Intel adapters.** nocved kinds `process.start`, `audit.exec`, `package.change`, `container.start`, `net.connect`, `net.listen`. aftercve findings are recognized by `correlation_key`, or by `schema_version` plus `rule_id` when `kind` is absent. Unknown nocved kinds are skipped. A file that claims `origin: ring` is rewritten to nocved before it is stored. Only `record_to_event` produces ring origin. Finding titles, explanations, and recommendations are not stored. Recommendations are not actions.
   - **nocved spool envelopes.** A line with exactly the keys `v`, `host`, `epoch`, `seq`, `prev`, `payload`, `mac` is a nocved envelope. `v` must be 1, `epoch` 32 lowercase hex, `prev` and `mac` 64 lowercase hex, `host` 1 to 253 bytes. The string `payload` is parsed as the event (a nested envelope is rejected). A heartbeat envelope (`v`, `host`, `payload`, `mac`) is skipped. **The envelope MAC and the nocved hash chain are not verified**: cveguard holds no nocved key. Anyone who can write the feed can forge events; they still import as shadow.
   - **argv never rejects an event.** `cmdline` / `argv` / `args` lose secret-looking entries, then keep the first 64 entries, cut each to 512 bytes at a char boundary, and escape `\n`, `\r`, `\t` and every other control character (`\u{1b}`); an escape is never split by the cut. When anything was cut the event, and the decision, carry `args_truncated: true`. Evaluation continues on `exe` and `name`. The live run showed why: a miner started with 70 arguments, an argument over 512 bytes, or a `bash -c` script with newlines used to drop the whole event. A non-string argv entry is still a bad field.
   - **Network events.** `net.listen` with `remote_ip` `0.0.0.0` or `::` and `remote_port` 0 (what nocved sends for a listener) has no `remote`. IPv4 and IPv6 are both accepted for `net.connect` and `net.listen`; IPv4 uses the strict dotted quad, IPv6 `std::net`. `remote` is stored as `a.b.c.d:port` or `[v6]:port`, and a `net.connect` port must be 1 to 65535. The local endpoint is stored as `local` in the same form: from nocved's `local_ip` and `local_port` when present (nocved 2026-10+), otherwise from the `local` string, splitting the port off the last colon and stripping brackets (older nocved wrote IPv6 unbracketed, `::1:9998`).
   - **Producer rule.** The highest-severity nocved signal `rule` (first wins a tie), or the aftercve finding `rule_id`, is kept as `source_rule_id` when it is 1 to 128 bytes of `[A-Za-z0-9._-]`. Signal summaries are never read.
   - **One comm normalizer.** `process.start` `name`, `audit.exec` `comm`, ring `comm`, guard-JSON `comm`, and an aftercve `rule_id` all go through `normalize_comm`. A value that is not a string or is not a valid subject (`[A-Za-z0-9_.-]`, 1 to 64 bytes) is dropped, the event gets `comm_invalid: true` (copied to the decision), and evaluation continues on `exe`. Firefox's `Web Content` is dropped this way. Comm is never identity.
4. **Container join.** The first 64-hex run that is not part of a longer hex run. Runtime is the 32 bytes immediately before that run: `crio`, then `containerd`, then `docker`, otherwise `unknown`. The stored id is the first 12 hex characters, lowercase. Privileged is never inferred from cgroup text. Only an explicit `privileged: true` joins as privileged.
5. **Lineage.** Cap 4096 nodes. `observe_start` replaces a reused pid and stores the parent generation. Walk stops at depth 32, at ppid 0, on a generation mismatch, or on a cycle. Decisions store at most 8 ancestors. The protected check uses the full walk. Field name is `generation`. Exit does not delete the node.
6. **Isolate plan.** A printed `/bin/sh` recipe around table `inet cveguard`. Loopback is hardcoded (`iif "lo"`, `127.0.0.0/8`). The operator sets `local_cidrs`, `whitelist`, and `management_ips`. `store_ips` are added when `keep_store` is true. Prefixes are /16 through /32. `0.0.0.0/0`, `::/0`, leading zeros, and a masked network of `0.0.0.0` are rejected. RFC1918 is not implied. Management addresses are mandatory. `keep_store` with an empty store list is rejected. Deadman is 60 to 900 seconds. `isolate apply` returns `isolate apply is not in the debut build`. `isolate deactivate` prints `nft delete table inet cveguard` and returns 0. The recipe runs `set -eu` and three steps in order:
   1. Deadman: `systemd-run --unit=cveguard-deadman --on-active=<deadman_secs>s nft delete table inet cveguard`. It is armed before the ruleset, so a lockout still rolls back; if arming fails the recipe stops before isolating. `systemctl stop cveguard-deadman.timer` keeps isolation past the deadman.
   2. Ruleset via `nft -f -`. Input: `policy drop; iif "lo" accept; ip saddr @allow4 ct state established,related,new accept`. Output: `policy drop; oif "lo" accept; ip daddr @allow4 ct state established,related,new accept`. Filtering is on the *peer* address in each direction, so the host's own address being inside `local_cidrs` opens nothing, and established traffic is not blanket-accepted, so a C2 session that predates isolation is dropped.
   3. `conntrack -F`. No pre-isolation flow keeps state. Flows to allow-set peers are picked up again as new and re-accepted; any other peer is dropped by policy.

   IPv6 has no allow set, so all non-loopback IPv6 is dropped. Elements are sorted and deduped. The example uses TEST-NET: local `10.1.2.0/24`, whitelist `192.0.2.20/32`, management `192.0.2.10`, store `198.51.100.8`, deadman 120.
7. **Capability plan.** Bounding set empty. Ambient set empty. `no_new_privs=yes`. Any requested capability in config is `capability rejected`, including names that would administer the network or read other processes. `check` prints the plan and does not call `capset`. `afteralert` parses only `127.0.0.1` and rejects port 0.
8. **Seal.** `afterseal pin` canonicalizes each path, hashes regular files (nofollow, cap 32 MiB, at most 64 entries), and writes a mode-0600 manifest. Compare is constant-time on the raw 32-byte digests. A missing seal *file* is `Missing`. Everything else is `Mismatch`: symlink, bad mode, bad owner, bad hex, oversize, a hash mismatch, a sealed path that no longer exists, a relative or non-canonical path, an empty manifest, a manifest that does not cover all six census binaries (`nocved`, `nocve-store`, `aftercve`, `afterguard`, `afteralert`, `afterseal`, matched by basename of the sealed path), and other IO on the seal file. `pin` refuses to write a manifest `verify` would reject.
   - **Re-verification.** `run` re-verifies the seal every `seal_recheck_passes` passes (config, 1 to 86400, default 60; one pass is about one second). A new mismatch writes the one seal alert and stops with exit 3.
   - **Protected by verified identity only.** The seal check records the canonical path and the dev/ino of each file it hashed. An event is protected when its `exe` is exactly one of those paths and the file at that path still has the same dev/ino; an ancestor is protected the same way, using the exe recorded in the lineage. `comm` and basenames never protect, so `exe=/tmp/xmrig` with `comm=nocved`, an ancestor at `/dev/shm/aftercve`, and `/tmp/.x/afterseal` are all acted on. With no valid seal, nothing is protected. Protected decisions are `suppressed` / `protected` with no isolate plan. The census is never an action.
   - **Future work, not built:** offline Ed25519 signing of the manifest, so a local writer of the 0600 seal file cannot re-pin a replaced binary. The public key would ship with the package and the signing key would stay off the host.
9. **Ledger.** Hash-chained JSONL, mode 0600, `O_NOFOLLOW`, default cap 1 MiB (`ledger_max` 64 bytes through 1 MiB). Decision `schema_version` is 3 (events, findings, and seal manifests stay at 1); the row shape is under "Decision row" below. Each row has `epoch` (the chain's name: drawn from the OS CSPRNG, 1 to 2^53-1, when the ledger has no head or its head is a schema 2 row without one, then copied to every later row, across rotation), `seq` (1 for the first row, then +1) and `prev` (SHA-256 hex of the previous row's bytes without the newline; 64 zeros for the first row). Appends hold an exclusive `flock` on `<ledger>.lock` and re-read the chain head from disk under it, so `once` and `run` cannot truncate or fork each other. A failed write restores the previous length. An existing file with the wrong mode is not chmodded.
   - **Full ledger.** When a row would pass `ledger_max`, the ledger is renamed to `<ledger>.1` (replacing the previous `.1`) and the new file continues the chain from the old head. A single row larger than `ledger_max` is dropped and counted. The daemon never exits because the ledger is full. Only one rotated generation is kept; the second rotation discards the oldest rows.
   - **status.json** carries `ledger_seq`, `ledger_head` (this process's last appended row), `ledger_epoch`, `ledger_drops`, `ledger_rotations`, `events_replaced`, and `events_gap`, beside `rules_loaded`, `enforce_enabled`, `ring_lost`, `tamper_mismatch`, `bad_lines`.
   - **What the chain does not cover:** it is unkeyed. An attacker who can rewrite both the ledger and `status.json` can forge a consistent chain. An edit to the newest row is caught only once `status.json` names that row.
10. **Budget.** Window uses event time. Ring events are stamped with the daemon clock. A backwards clock keeps existing hits and fails closed at the cap. Shadow decisions do not consume the budget. Default window 60s, 10 actions. Configured window is 1 ms through 24 h, max actions 1 through 1000.
11. **JSONL tail.** The events file is opened with `O_NOFOLLOW` and must pass the config policy (owner root or the daemon uid, no group or other write); otherwise the pass fails. The tail tracks `(dev, ino)` and keeps the fd of every inode it follows. When the path names a new inode (nocved rotates `events.jsonl` to `events.jsonl.1` and creates a new file) it counts `events_replaced`, drains the old inode to EOF through the held fd, and only then reads the new file from offset 0, so lines written before the rename are never lost. The live run lost 194 of 306 process starts, including the miner, when the old code jumped to offset 0 of the new file instead. If `<path>.1` is then an inode the tail never opened, the file rotated more than once between polls: that generation is read whole too, and a gap is raised anyway because a third rotation would be invisible. A jump in envelope `seq` within one nocved epoch (nocved skipped lines in a burst or dropped an oversized one) is a gap. A shrink of the same file sets the sticky `gap`, jumps to the new length, does not replay, and is a gap. Each gap increments `events_gap` in `status.json` and writes one `record` / `rejected` / `feed_gap` row (severity high). A missing live path (nocved between its two renames) is no new data. nocved envelopes whose `(epoch, seq)` is not newer than the last one seen are skipped, so overlap and compaction do not replay events. Lines over 8192 bytes are rejected and the cursor advances; a nocved event whose escaped payload pushes the envelope past 8 KiB is counted as a bad line. A trailing partial line waits; an unterminated last line of a rotated-away inode is a bad line. Not covered: offsets live in memory, so a restart reads the current file from offset 0 and does not read `.1`.
12. **Metrics.** `afteralert` always emits all 15 `cveguard_decisions_total{action,outcome}` series plus `cveguard_ring_lost`, `cveguard_tamper_mismatch`, `cveguard_rules_loaded`, `cveguard_enforce_enabled`, `cveguard_ledger_parse_errors`, `cveguard_ledger_chain_ok`, and `cveguard_ledger_drops`, and the feed counters `cveguard_feed_bad_lines`, `cveguard_feed_events_replaced`, and `cveguard_feed_gaps` (from `bad_lines`, `events_replaced`, `events_gap`). The gauge values other than the decision counts come from `--gauges` (the daemon's `status.json`); without it they are 0. `cveguard_ledger_chain_ok` is 1 only when `<ledger>.1` (if present) and the ledger form one unbroken chain, the first row is `seq` 1 with the zero `prev` when there is no `.1`, every row ends in a newline, and the row `status.json` names (`ledger_seq`, `ledger_head`) is present with that hash, or is older than the oldest surviving row. An edited, deleted, or truncated row makes it 0. Accepted streams get 2 s read and write timeouts, so an idle client cannot hold the single-threaded loop; client and accept errors do not stop the loop. No timestamps. No argv, secret, or plan labels. Non-GET is 400. Any path other than `/metrics` is 404. Invalid UTF-8 is 400. A header whose blank line ends past 2048 bytes is 400. A missing ledger is empty series and zero parse errors. A ledger over 1 MiB, a symlink, or a mode other than 0600 refuses the scrape. Load failure fails the process; it does not publish zeros for a file that exists and is unreadable.

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

Invalid events are `rejected` / `schema` and the pass continues. `once` writes one `record` / `rejected` / `schema` row (origin nocved, no subject) for each line that does not parse, including a line over 8192 bytes, evaluates the rest, and exits 2. A file over 1 MiB or with more than 1000 non-empty lines is still refused whole.

`run` counts bad tail lines and continues. It ignores exit 2 and stops on exit 3. Once the engine has halted on a seal mismatch every later pass returns 3.

## CVE citation

cveguard is not a scanner. A rule may store `CVE-YYYY-NNNN` (case-sensitive `CVE-`, four-digit year, four to seven digit number) beside an exact package name and version. `1.2.3` does not match `1.2.3-1`. Package facts come from nocved `package.change` (`version_new`; a null version is skipped) or from an aftercve observation. The example rule cites fictional `example-miner` `1.2.3` and `CVE-2099-0001`. The CVE is copied from the rule. It is not required on the event.

## Files

Config is at most 64 KiB, rules and `once` input at most 1 MiB, ring cap 1 through 4096 (default 256), `seal_recheck_passes` 1 through 86400 (default 60). `deny_unknown_fields` on config and rules. Mode and `enabled` are required; there is no default enforce. Paths in the config are resolved against the config file's directory. Opens use `O_NOFOLLOW`. Group or other write is rejected. Owner is root or the effective uid (`geteuid`, never inferred from `$HOME`). Ledger, ledger lock, and seal mode are exactly 0600.

`afterguard check` prints mode, enabled, rule count, seal word, the capability plan, and the isolate plan or its error. It does not append the ledger or write status. Exit 3 on mismatch, or when mode is enforce and the seal is not valid or the plan is invalid.

## nocved feed (deployment requirement, nocved side)

afterguard cannot read nocved's own spool in production: nocved creates the spool directory 0700 and `spool.jsonl` 0600 as its own user, and `afterguard` runs as `cveguard` with no capabilities. cveguard does not edit nocved. The nocved change needed is:

- nocved writes a second, read-only feed of the same envelope lines it appends to `spool.jsonl` (one JSON envelope per line, unchanged), at a fixed path such as `/var/lib/nocved/cveguard-feed/events.jsonl`.
- The feed directory is owned by the nocved user, group `cveguard`, mode 0750. The feed file is owned by the nocved user (or root), group `cveguard`, mode 0640. No group or other write; afterguard refuses a group-writable or symlinked feed.
- The feed is append-only. nocved rotates it by renaming `events.jsonl` to `events.jsonl.1` (one generation, never replaced within 60 s of its creation) and creating a new file by temp-file rename; it never truncates. afterguard drains the old inode through its held fd before reading the new one, checks that `.1` is the inode it followed, and skips envelopes it already saw by `(epoch, seq)`. Truncating in place is still tolerated (sticky gap, no replay).
- Each line stays at most 8192 bytes, or afterguard counts it as bad.
- Set `"events"` in the cveguard config to that path (see `deploy/config.example.json`).

Out of scope here: verifying the envelope MAC or chain. That needs the nocved key on the guard host, which this design does not grant.

## Decision row (darksignal contract)

One JSON object per ledger line, UTF-8, no newline inside, keys in this order. darksignal consumes it as the frame `body` (see "Shipper"). Example rows from the live miner lines (`crates/cveguard-proto/testdata/e2e_miner_burst.jsonl`, seq 534 and 535):

```json
{"schema_version":3,"epoch":5357274790562873,"seq":1,"prev":"0000000000000000000000000000000000000000000000000000000000000000","observed_at_ms":1790869757751,"action":"alert","outcome":"shadow","reason":"imported_intel","origin":"nocved","severity":"high","pid":8126,"rule_id":"masq-kcompactd","source_rule_id":"proc.masquerade","subject":"kcompactd0"}
{"schema_version":3,"epoch":5357274790562873,"seq":2,"prev":"19c9e87ccbd3f7314913fd94490b0ced16d5945eb01f678c6880ba235ed69cde","observed_at_ms":1790869757751,"action":"alert","outcome":"shadow","reason":"imported_intel","origin":"nocved","severity":"high","pid":8128,"rule_id":"masq-kcompactd","source_rule_id":"proc.masquerade","subject":"kcompactd0","args_truncated":true}
```

| Field | Type | Presence | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | always | `3`. Rows written before this change are `2` and have no `epoch`, `severity`, `source_rule_id`, or `args_truncated`. |
| `epoch` | integer, 1 to 2^53-1 | always on schema 3 | Names the ledger chain. Same value on every row of one chain, across rotation; a new ledger gets a new one. Not a time, not ordered, not secret. Absent on schema 2 rows; never invented (no `0`). |
| `seq` | integer >= 1 | always | Position in the chain. `{epoch}:{seq}` is unique per host and is the dedupe id. |
| `prev` | 64 lowercase hex | always | SHA-256 of the previous row's bytes, 64 zeros for seq 1. |
| `observed_at_ms` | integer, Unix ms | always | Event time. `0` on the seal-mismatch alert (no event). |
| `action` | `record` \| `alert` \| `isolate` | always | Rule action. |
| `outcome` | `shadow` \| `noted` \| `planned` \| `suppressed` \| `rejected` | always | |
| `reason` | `matched` \| `policy_shadow` \| `rule_shadow` \| `imported_intel` \| `seal_missing` \| `seal_mismatch` \| `budget` \| `protected` \| `plan_invalid` \| `schema` \| `feed_gap` | always | |
| `origin` | `ring` \| `nocved` \| `aftercve` | always | Producer of the event. `nocved` for nocved lines, `aftercve` for aftercve findings, `ring` for the local probe and the seal alert. `feed_gap` and `schema` rows from the feed are `nocved`. Look `source_rule_id` up in this producer's table. |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` | always on schema 3 | Rule rows: the rule's `severity`, default `medium`. No-rule rows: `seal_mismatch` critical, `feed_gap` high, `schema` low. |
| `plan` | string | optional | nft recipe on isolate rows. Stays on the host; do not ship it on. |
| `pid` | integer | optional | |
| `rule_id` | string, `[A-Za-z0-9_.-]` 1 to 64 | optional | The cveguard policy rule that matched. Absent on no-rule rows. |
| `source_rule_id` | string, `[A-Za-z0-9._-]` 1 to 128 | optional | The producer's own rule that raised the event: highest-severity nocved signal `rule`, or the aftercve finding `rule_id`. Absent when the input carried none. |
| `cve` | `CVE-YYYY-NNNN...` | optional | Copied from the rule. |
| `subject` | string, `[A-Za-z0-9_.-]` 1 to 64 | optional | Exe basename, else comm. `afterseal` on the seal alert. |
| `comm_invalid` | `true` | optional, absent means false | The source comm was dropped. |
| `args_truncated` | `true` | optional, absent means false | argv was cut to 64 entries or an entry to 512 bytes. argv itself is never in the row. |
| `ancestors` | array of exe paths, at most 8 | optional, absent means empty | |

No argv, environment, file contents, finding prose, or signal summaries are ever in a row. Unknown fields may be added in a later schema; a consumer should ignore them.

## Shipper (`afterguard ship`)

`afterguard ship --config /etc/cveguard/config.json` sends ledger rows to the local darksignal socket. It is a subcommand of the same binary because darksignal accepts `cveguard` frames only from the configured exe (`/usr/local/bin/afterguard`) and uid. Config:

```json
"ship": {"socket": "/run/darksignal/darksignal.sock", "host": "ns2", "cursor": "/var/lib/cveguard/ship.cursor"}
```

`socket` must be absolute. `host` must be darksignal's configured host (1 to 64 of `[A-Za-z0-9._-]`, no leading or trailing dot). `cursor` defaults to `ship.cursor` beside the ledger. `ship` without a `ship` section is an error.

- **Frame.** One connection per row: u32 little-endian length, then `{"v":1,"tool":"cveguard","host":<host>,"sent_at_ms":<now>,"body":<row>}`, at most 64 KiB of JSON. The row is copied as written. darksignal answers one byte: `0x01` accepted (or dropped as a duplicate), `0x00` refused.
- **Cursor.** `{"epoch","seq","sent","refused","missed"}`, mode 0600, written atomically after every row. Each pass reads `<ledger>.1` then `<ledger>` under a shared `flock` on `<ledger>.lock` (the writer holds it exclusively), finds the last row whose epoch is the cursor's and whose seq is not past it, and sends everything after it in order. No such row (first run, a new ledger, or both generations newer than the cursor) sends every row, so the cursor survives rotation and restart. A jump past `seq + 1` within the cursor's epoch adds to `missed` (two ledger rotations while the shipper was down).
- **Acks.** `0x01` advances and counts `sent`. `0x00` advances and counts `refused`. A frame over 64 KiB can never be accepted: it advances and counts `refused`. A connect or IO error, a 5 s timeout, a closed stream, or any other byte keeps the cursor and backs off 1 s, doubling to 300 s; one success resets it to the 1 s idle poll.
- **Delivery.** At least once. A crash between the ack and the cursor write resends one row; dedupe on `{epoch}:{seq}`.
- **Fail closed.** A symlinked, non-0600, or unparseable cursor stops the shipper (systemd restarts it and it fails again until an operator looks); it does not resend or skip the ledger. A ledger row that does not parse stops the pass.
- **Deploy.** darksignal run as root with `socket_gid` set keeps its socket `0660` in a `0750` directory, both group `darksignal-producers`. `deploy/afterguard-ship.service` runs as `User=cveguard` with `SupplementaryGroups=darksignal-producers` and the same sandbox as `afterguard.service` (`PrivateNetwork=yes` leaves filesystem Unix sockets reachable). darksignal's producer entry is `"cveguard": {"exe": "/usr/local/bin/afterguard", "uid": <cveguard uid>}`.
- **Not covered.** The shipper does not authenticate the socket; whoever can bind `/run/darksignal` (root) can read the rows.

## Still not wired

- **Live ring.** No eBPF producer exists; on a real host `run` only tails the JSONL feed. Ring origin, and therefore any non-shadow decision, cannot occur outside tests today.
- **Enforcement.** `planned` and `noted` are ledger rows. Nothing applies the isolate recipe, stops a process, or pages anyone; `isolate apply` is an error.

## Explicitly not in this debut

Loading eBPF. Applying nftables. Killing processes. Disabling accounts. Hiding processes. Editing nocved or aftercve. Fleet deploy. Prometheus remote write. A CI workflow that claims the build is qualified. A journald parser. Claiming the probe works.

The nocved chain does not depend on the guard. The guard reads nocved and aftercve JSON and writes a ledger aftercve could collect later.

## systemd sketches

`deploy/afterguard-ship.service` is `afterguard.service` with `ExecStart=/usr/local/bin/afterguard ship --config /etc/cveguard/config.json` and `SupplementaryGroups=darksignal-producers`. `deploy/afterguard.service` drops the bounding and ambient sets, sets `NoNewPrivileges=yes`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, and `StateDirectory=cveguard` with `StateDirectoryMode=0700`. `deploy/afteralert.service` drops capabilities, allows localhost and denies any other address, and restricts families to `AF_INET AF_UNIX`. Both set `Restart=always` (`RestartSec=5`), `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, and `SystemCallArchitectures=native`. Neither unit is installed by this repository. Both use `User=cveguard`.
