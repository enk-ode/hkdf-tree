# Contributing

Contributions are welcome as pull requests against `main`.

## Before you open one

- `cargo test`, `cargo clippy --all-targets -- -D warnings` and
  `cargo fmt --all -- --check` must pass. CI runs exactly these.
- Keep the crate free of `unsafe`.
- Secrets stay in `Zeroizing` containers, and buffers that will hold
  secret material are allocated at their final size — a growing `Vec`
  reallocates and strands an un-zeroized copy on the heap.
- Errors are `Result` with a `thiserror` enum in the library and
  `anyhow` with context in the CLI. No `unwrap`/`expect` outside tests
  unless the call is provably infallible, and then with a comment
  saying why.

## The determinism contract

Any change that alters a derived value for an unchanged inventory is a
breaking change. That includes bit ordering, sample size, rejection
rules, alphabet order, wordlist contents and iteration order —
`docs/architecture.md` lists them explicitly. Such a change needs a
major version bump and a migration note; users cannot re-derive what
they have already deployed.

New features must not change existing outputs. New encodings are added
alongside the existing ones, never by adjusting them.

## Documentation

Code and documentation travel together: a new subcommand or flag lands
with its manpage section (`man/hkdf-tree.1`), its cookbook recipe where
one applies (`docs/cookbook.md`), and a `CHANGELOG.md` entry.

## Cryptographic changes

Changes to the derivation itself need a reference: which RFC, which
paper, which test vectors. `docs/background.md` is the place where that
reasoning is recorded, and `src/lib.rs` carries the RFC 5869 vectors as
tests.
