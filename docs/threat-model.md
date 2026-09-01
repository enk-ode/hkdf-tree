# Threat Model

This document describes what `hkdf-tree` protects against, what it
does not, and the assumptions its guarantees rest on.

## What we protect

**Confidentiality of the master seed while `hkdf-tree` runs.**

- The master seed enters the process via stdin as raw bytes and is
  stored in a `Zeroizing<Vec<u8>>`, which overwrites the buffer on
  drop.
- The seed is not persisted, logged, echoed, or copied into
  non-zeroing containers by the tool.
- Derived outputs are also wrapped in `Zeroizing<String>` internally
  before being emitted to stdout.
- The `report` subcommand is the one place where derived material is
  held for longer than a single write: every card's passphrase, and the
  assembled PDF buffer, live in memory until the file is written. Both
  are wrapped in `Zeroizing` as well, but the resulting **file** is
  plaintext by design — print it, then destroy it. `hkdf-tree` cannot
  control what a printer spool, an editor, or a backup does with that
  file afterwards.

**Determinism of derived passphrases.**

- Given the same master seed, the same YAML inventory, and the same
  hkdf-tree version, every derived passphrase is bit-identical.
- Every invariant behind this claim (bit ordering, sample size,
  rejection rule, alphabet ordering, iteration order) is asserted in
  the test suite. Breaking any of them requires a version bump on
  affected inventory entries.

**Domain separation between derivations.**

- Two entries with distinct info-strings, even under the same salt
  and the same master seed, produce independent output. This is
  guaranteed by HKDF's construction (RFC 5869).
- Two entries with the same info-string under different salts are
  also independent.
- These properties enable a single master seed to serve as the root
  of an unbounded number of independent secrets.

## What we do not protect against

**Weak master seeds.**

- HKDF is a key-derivation function, not a password-based key-derivation
  function. It does not stretch weak inputs. A low-entropy master
  seed (a short password, a common phrase) produces low-entropy
  derived material regardless of the info-string.
- Users must generate the master seed from a high-quality entropy
  source. BIP-39 24-word phrases at 256 bits of entropy are the
  recommended input.

**Compromise of the environment running the tool.**

- If an attacker controls the machine running `hkdf-tree`, they can
  read the master seed from process memory, from stdin before
  `hkdf-tree` consumes it, from the swap file, from a core dump,
  from a compromised terminal emulator, from `/proc`, or from any
  number of side channels. Rust's `zeroize` reduces window size
  but does not eliminate this class of risk.
- Use only trusted, updated systems for derivation. A dedicated
  offline machine is ideal for the initial master-seed generation
  and paper-backup generation.

**Compromise of the inventory or wordlist file.**

- The inventory is trusted input. A modified inventory (different
  salt, different info-string, different encoding) produces different
  derivations. Attackers who can silently swap the inventory can
  cause the tool to emit "correct-looking" but wrong passphrases.
- Consider storing the inventory alongside the master seed in cold
  storage (paper or offline media), and comparing against the
  online copy periodically.

**Downstream service compromise.**

- Whatever service consumes the derived passphrase (Bitwarden vault,
  disk encryption, cloud login) is outside our threat model. If the
  service is breached, the passphrase leaks regardless of how
  carefully it was derived.

**Physical loss of the master seed.**

- The master seed on paper is the authoritative backup. Loss of
  every paper copy without a working memorized copy is unrecoverable.
- We do not implement any cloud sync, key escrow, or social recovery.

**PDF report leakage after generation.**

- The PDF contains every derived passphrase in plaintext, plus a
  QR-code encoding of each. Anyone with the PDF has all the
  passphrases.
- The tool writes the PDF to the path the caller specifies. Callers
  are responsible for tmpfs output, offline printing, and prompt
  deletion. The cover page states these requirements prominently.

**Side channels in third-party crates.**

- `hkdf`, `sha2`, and the encoding stack are audited components of
  the RustCrypto ecosystem, but they are not fully constant-time by
  contract, and neither is `printpdf`. Deriving passphrases in the
  presence of a co-located adversary who can measure timing is not
  a use case we design for.

## Assumptions

- **`hkdf` (RustCrypto 0.12) implements RFC 5869 correctly.**
  Verified against the three RFC 5869 Appendix A test vectors in
  the test suite.
- **`zeroize` reliably zeros memory it holds.** True under normal
  compilation; not guaranteed against a maliciously modified
  toolchain.
- **The Rust standard library and allocator do not silently copy
  buffers behind our back.** Reasonable in practice; not proven.
- **The master seed provided is high-entropy.** Enforced by external
  practice, not by the tool itself.
- **The inventory has not been tampered with.** Detection is out of
  scope; users should treat the inventory as high-integrity data
  and back it up alongside the seed.

## Non-goals

- Password strength estimation.
- Master-seed generation.
- Master-seed storage or backup.
- Key escrow or recovery.
- Cloud sync of any kind.
- Constant-time execution.
- Formal verification.

## Recovery model

If a derived passphrase is lost or forgotten:

1. Retrieve the master seed from paper backup.
2. Retrieve the inventory YAML from its backup location.
3. Re-run `hkdf-tree show --config <inventory> --entry <info-string>`
   with the seed on stdin.
4. The regenerated passphrase is byte-identical to the original.

If the master seed is lost:

1. Everything derived from it is lost forever.
2. This is why the master-seed backup regime (paper + metal +
   off-site + tested restore) is non-negotiable.

## Reporting concerns

For security-relevant issues, see [SECURITY.md](../SECURITY.md).
