# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Report filters** — `report --entry`, `--status` and `--derivation`
  select which cards are printed. Selection happens before derivation,
  so unselected passphrases are never computed. Reprinting a single
  lost card no longer means putting the whole inventory on paper.
- **`docs/background.md`** — the reasoning behind the construction
  (why a master seed instead of a master password, why HKDF, how the
  encodings avoid modulo bias) with references to RFC 5869, RFC 2104,
  Krawczyk's HKDF paper, the EFF wordlist and NIST SP 800-63B.
- **`CONTRIBUTING.md`** — including the determinism contract that any
  change to derived values is breaking.

### Fixed

- **Report path zeroization** — card passphrases and the assembled PDF
  buffer are now held in `Zeroizing` containers; previously the
  plaintext lingered in freed heap memory although the threat model
  claimed otherwise. The written file remains plaintext by design
  (print, then destroy) and `docs/threat-model.md` now says so.

### Changed

- **Report card layout** — the header now shows a human-readable title
  (the purpose's `usage` text, falling back to the last info-string
  segment) left of the QR code, wrapped instead of colliding with it;
  info-string, encoding, passphrase, and the remaining details moved
  below the QR code across the full card width.

## [0.1.0] — 2026-07-22

Initial release.

### Added

- **Cryptographic core** (`lib.rs`) — `derive_bytes()` wrapping
  HKDF-SHA256 (RFC 5869), returning `Zeroizing<Vec<u8>>`. Verified
  against RFC 5869 Appendix A test vectors A.1, A.2, and A.3.
- **YAML inventory** (`inventory.rs`) — schema for domains, realms,
  purposes, and versions, with encoding metadata per version and
  structural validation (canonicalization rule enforcement, empty-
  container detection, unsupported-schema-version rejection).
  Deterministic sorted iteration via `BTreeMap` throughout.
- **Encoding plugins** (`encoding.rs`) — Diceware, alphanumeric,
  numeric, base64. Rejection-sampling `BitReader` eliminates modulo
  bias for non-power-of-two alphabets. Outputs wrapped in
  `Zeroizing<String>`.
- **Wordlist resolution** (`wordlist.rs`) — embedded EFF Large
  wordlist (7 776 words, CC BY 3.0) plus optional file loading with
  permissive parsing (one-word-per-line and tab-separated formats).
- **PDF report** (`report.rs`) — printable A4 output with cover page
  (title, subtitle, salt label, master-seed fingerprint slot, and
  security notes) followed by one-card-per-page entries containing
  the info-string, encoding descriptor, human-readable passphrase,
  and QR-code encoding of the passphrase. Non-derivable entries
  produce placeholder cards labelled NOT DERIVED so the printed
  report remains a complete audit surface.
- **CLI subcommands** — `derive` (raw HKDF output), `list` (inventory
  audit with `--status` and `--derivation` filters, plain and
  verbose modes), `show` (single-entry derivation and encoding),
  `report` (full-inventory PDF).
- **Integration tests** — end-to-end coverage of all four subcommands
  spawning the compiled binary against tempfile inventories.
- **Documentation** — cookbook with ten practical recipes,
  architecture overview with determinism contract, threat model with
  explicit non-goals.
- **CI** — GitHub Actions running `cargo build`, `cargo test`,
  `cargo fmt --check`, and `cargo clippy -D warnings` on Ubuntu and
  macOS.

### Security

- Master seed is only read from stdin; never persisted, logged, or
  copied into non-zeroing containers by this crate.
- Master seed and all derived material are held in `Zeroizing`
  wrappers that overwrite their buffers on drop.
- No network access; no filesystem writes outside explicitly
  requested output paths.
- No user-specific data is baked into the binary — the salt, the
  namespace, and every encoding parameter live in the user's YAML
  inventory. The binary is generic and reusable.

[Unreleased]: https://github.com/enk-ode/hkdf-tree/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/enk-ode/hkdf-tree/releases/tag/v0.1.0
