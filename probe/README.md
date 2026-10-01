# probe

The debut does not ship a loadable eBPF program. `cargo test` on the macOS
dev host must stay green, so this workspace does not depend on `aya` or
`bpf-linker`.

The Linux program, when it exists, is a separate build:

- kernel 6.1 or newer, with BTF
- [aya](https://github.com/aya-rs/aya) `bpf-linker` 0.11.1
- one consumer: the `afterguard` process
- Debian 10 (kernel 4.19) has no reliable eBPF path; the userspace tail stays

Nothing in this tree loads a program, attaches a map, or claims the probe
ran. The shared ring the daemon uses today is the userspace simulator in
`cveguard-proto`. A future probe writes the same records.

## Record ABI

Little-endian header, 24 bytes, then a UTF-8 JSON payload of at most 1024
bytes.

| Offset | Field | Value |
| --- | --- | --- |
| 0 | magic `u32` | `0x31524743` (`CGR1`) |
| 4 | version `u16` | `1` |
| 6 | kind `u16` | `1` exec, `2` exit, `3` connect |
| 8 | payload length `u16` | `0..=1024` |
| 10 | flags `u16` | `0` |
| 12 | observed_at_ms `i64` | producer clock |
| 20 | reserved `u32` | `0` |

The map is single-consumer. A second attach fails. When the ring is full
the newest record is dropped and `lost` increments. `lost > 0` means the
pass is partial. `afterguard` stamps its own clock onto ring events and
drops arguments that look like secrets before anything is stored.
