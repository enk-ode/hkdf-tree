# [hkdf-tree](https://enk-ode.github.io/hkdf-tree/)

Deterministic hierarchical passphrase derivation from a single master seed via HKDF-SHA256.

> **Status: 0.1.0 — first release, pre-1.0.**
>
> The tool is functional and reasonably tested, but the interface may still
> change in incompatible ways before 1.0. Any change to derivation or encoding
> logic that would break determinism will be gated behind an inventory version
> bump (`-v1` → `-v2`), so already-derived passphrases stay reproducible under
> the version they were minted with.

## What it does

Given:

- A **master seed** (256 bits of entropy, typically stored as a BIP-39 24-word phrase in cold storage), and
- A **YAML inventory** describing a hierarchy of derivations by domain, realm, and purpose,

[`hkdf-tree`](https://enk-ode.github.io/hkdf-tree/) produces:

- Deterministic passphrases (Diceware, alphanumeric, numeric PINs, base64 blobs) for every entry in the inventory, and
- A printable PDF report with QR codes for physical paper backup.

The same master seed plus the same inventory always produces the same passphrases. Losing derived material is not data loss; it is a recovery step, provided the master seed and the inventory survive.

## Installing

```bash
cargo install --path .
sudo install -m 0444 man/hkdf-tree.1 /usr/local/share/man/man1/
```

Requires Rust 1.88 or newer. The tool is Unix-only: report files are
created with mode 0600 via the Unix file-mode API.

## Quick start

```bash

# List entries in an inventory
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml

# Derive one passphrase (master seed on stdin)
gpg --decrypt master-seed.gpg \
  | hkdf-tree show \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --entry alice/laptop/fde-daily-v1

# Generate a paper-backup PDF for the whole inventory
gpg --decrypt master-seed.gpg \
  | hkdf-tree report \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --output /tmp/report.pdf \
      --subtitle "$(date +%F)"
```

See the [cookbook](docs/cookbook.md) for detailed recipes.

## Design principles

1. **No user-specific data in the binary.** The salt, the info-string namespace, the encoding parameters — all of it lives in the user's YAML inventory. The binary is generic and reusable for any user or organization.
2. **Master seed never touches the binary source or the inventory.** It is supplied at runtime via stdin, an external decrypt process (typically `gpg --decrypt` fronting a hardware token), or a file whose format is out of scope for this tool.
3. **Salt is public.** HKDF security depends on the master seed, not on the salt. The salt provides domain separation and is documented in the inventory.
4. **Deterministic and reproducible.** Same inputs must always produce identical outputs, forever. Any change to encoding logic requires a new version suffix on affected entries.
5. **Small trusted computing base.** The binary depends only on well-audited crates (`hkdf`, `sha2`, `zeroize`). No network. No filesystem writes outside explicitly requested output paths.
6. **Secrets are wiped from memory** after use where the language and allocator permit (`zeroize`).

## Non-goals

- **Master seed generation.** Use dedicated BIP-39 tools offline.
- **Master seed storage or backup.** Paper, metal, and a safe are your backup. This tool does not persist secrets.
- **Cloud sync of any kind.** Everything runs locally.
- **General-purpose password management.** For daily use of derived passphrases, feed them into an existing password manager (Bitwarden, etc.).
- **Replacement for hardware-backed authentication.** Where a hardware key (FIDO2) is available for a service, use that instead of deriving a passphrase.

## Namespace convention

The tool does not enforce any particular hierarchy, but expects each entry to be identified by a hierarchical **info-string**. A common convention is:

```
<domain>/<realm>/<purpose>-v<N>
```

For example: `alice/laptop/fde-daily-v1`, `alice/proton/account-v1`, `acme-corp/build-server-42/ssh-signing-key-v1`.

Info-strings are case-sensitive input to HKDF. Establish and document a canonicalization rule (typically lowercase ASCII plus digits and hyphens) in your inventory.

## Documentation

- **[Cookbook](docs/cookbook.md)** — practical recipes for daily use
  (creating an inventory, deriving one passphrase, generating a paper
  backup report, rotating a passphrase, adding a service, auditing).
- **[Architecture](docs/architecture.md)** — layer overview, source-code
  map, determinism contract, trust boundaries.
- **[Threat model](docs/threat-model.md)** — what the tool protects
  against, what it does not, and the assumptions the guarantees rest on.
- **[Background](docs/background.md)** — what the derivation is built
  on, with references (RFC 5869, RFC 2104, EFF wordlist, NIST SP 800-63B).
- **[Contributing](CONTRIBUTING.md)** — including the determinism
  contract that any change to derived values is breaking.
- **[Security policy](SECURITY.md)** — how to report vulnerabilities.
- **Manual page** — `man hkdf-tree` once installed, or online at
  <https://enk-ode.github.io/hkdf-tree/>.

## Roadmap

- [x] Rust project skeleton with CI
- [x] HKDF-SHA256 core with RFC 5869 test vectors
- [x] `derive` subcommand reading master seed from stdin
- [x] YAML inventory schema and loader
- [x] `list` subcommand
- [x] Encoding plugins: Diceware, alphanumeric, numeric, base64
- [x] `show` subcommand combining inventory lookup, derivation, and encoding
- [x] `report` subcommand with PDF+QR output
- [x] Master-seed loading via external decrypt process (via stdin pipe;
      any `--decrypt`-style command works — see cookbook)
- [x] Comprehensive integration tests
- [x] Documentation: architecture, threat model, cookbook
- [x] 0.1.0 release

## License

BSD 2-Clause. See `LICENSE`.

## Security

See `SECURITY.md` for how to report vulnerabilities.
