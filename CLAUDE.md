# CLAUDE.md

cveguard: enforcement and response plane for the After Dark host toolkit
(Rust 1.97.1 workspace). Complements `~/development/nocved` (continuous
off-host sensor) and `~/development/aftercve` (one-shot forensics). Design:
`DESIGN.md`.

Binaries: `afterguard` (decision daemon), `afteralert` (Prometheus text on
127.0.0.1), `afterseal` (toolchain SHA-256 pin and census).

## Rules

- Never run anything against real fleet hosts. Tests use temp dirs and
  127.0.0.1 only. Do not apply nftables, load eBPF, or stop a process.
- Do not edit `nocved` or `aftercve`. Intel adapters read published JSON.
  Imports cannot flip enforce.
- `~/development/ads-fable-utils/SECURITY-RULES.md` is binding: OS CSPRNG,
  constant-time compares, fail closed, no secret logging, `Threats:` notes,
  negative tests. No `unwrap`/`expect` outside tests.
- Never ship file contents, argv, or environment values. Metrics labels come
  from the decision enums.
- `isolate apply` stays an error until a later build. Deactivate prints
  `nft delete table inet cveguard` and does not run it.
- Ask Ryan before committing. Do not commit this tree unless he asks.

## Commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked
cargo deny check
```

The toolchain is pinned to 1.97.1. On this Mac, Homebrew `cargo` can shadow
rustup; use `rustup run 1.97.1 cargo ...`.
