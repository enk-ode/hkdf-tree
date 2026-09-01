# Architecture

`hkdf-tree` is a small tool with a clear layered design. This document
maps the layers to their source-code modules and explains the
information flow between them.

## Layer overview

```
┌──────────────────────────────────────────────────────────────┐
│  CLI  (src/main.rs)                                          │
│  Subcommands: derive, list, show, report                     │
└──────────────┬──────────────┬────────────────┬───────────────┘
               │              │                │
               ▼              ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐
    │  Inventory   │  │   Wordlist   │  │     Report      │
    │  (YAML)      │  │  resolution  │  │  (PDF + QR)     │
    │              │  │              │  │                 │
    │ inventory.rs │  │ wordlist.rs  │  │   report.rs     │
    └──────┬───────┘  └──────┬───────┘  └────────┬────────┘
           │                 │                    │
           └──────────┬──────┴────────────────────┘
                      │
                      ▼
             ┌────────────────────┐
             │      Encoding      │       ┌──────────────────┐
             │  Diceware, base64, │       │  Cryptographic   │
             │  numeric, alnum    │       │      core        │
             │                    │       │                  │
             │   encoding.rs      │◄──────┤     lib.rs       │
             │                    │       │  derive_bytes    │
             └────────────────────┘       └──────────────────┘
```

## Cryptographic core (`src/lib.rs`)

The single public function `derive_bytes(ikm, salt, info, output_len)`
wraps `hkdf::Hkdf<Sha256>` from the RustCrypto ecosystem. It:

- Takes ownership of no secrets (all inputs are references).
- Returns `Zeroizing<Vec<u8>>` so the derived buffer is wiped on drop.
- Enforces the RFC 5869 output-length ceiling of `255 * 32 = 8160` bytes.
- Is verified against the three RFC 5869 Appendix A test vectors.

Nothing above this layer contains cryptographic logic; all higher
layers treat this function as an opaque KDF.

## Inventory (`src/inventory.rs`)

The user's YAML file is parsed into a tree of typed structs:

```
Inventory
  └── domains: BTreeMap<name, Domain>
        └── salt, realms
              └── purposes
                    └── versions
                          └── encoding, derivation, status, ...
```

`BTreeMap` is used everywhere to guarantee **deterministic iteration
order**. Reports and listings must produce identical output for
identical inventories.

`Inventory::entries()` flattens the tree into `Entry` values, each
carrying a reconstructed info-string
(`<domain>/<realm>/<purpose>-v<N>`) and a reference to the version's
metadata. This is the pivot point where the tree structure gives way
to a flat, iterable list.

## Encoding (`src/encoding.rs`)

Four pure functions convert raw HKDF output bytes into user-visible
secrets: Diceware, alphanumeric, numeric, base64.

The critical design property is **uniform sampling via rejection**.
For non-power-of-two alphabets (7 776 words, 62 characters, 10 digits),
`byte % alphabet_size` introduces modulo bias that would slightly
weaken the passphrase entropy. Instead, a `BitReader` consumes the
input bit-by-bit; `sample_uniform` reads the minimum bit count needed
to cover the alphabet, rejects out-of-range samples, and retries.

Consequence: byte consumption is variable but bounded. Callers pass
in a generous buffer (128 bytes in the current CLI); realistic
passphrases consume far less.

## Wordlist (`src/wordlist.rs`)

Diceware needs a wordlist. `resolve(name)` maps either:

- A built-in name (`eff_large`) to an embedded compile-time constant, or
- A path-like string to a file on disk, parsed permissively (one word
  per line or EFF-style `<roll>\t<word>`).

Only one built-in is currently shipped: the EFF Large Wordlist,
7 776 words, embedded via `include_str!("../wordlists/eff_large.txt")`.

## Report (`src/report.rs`)

`build_report(meta, entries)` produces a PDF byte vector using
`printpdf` and `qrcode`. The layout is one card per page: info-string
header, encoding descriptor, passphrase in monospace, QR code of the
passphrase, paper-backup destinations, optional notes.

Manual and service-generated entries appear as placeholder cards
without a QR code, marked `NOT DERIVED`. This keeps the printed
report a complete audit surface even for values the tool cannot
reproduce.

The set of cards can be narrowed with `--entry`, `--status` and
`--derivation`. Selection happens in `main.rs` BEFORE derivation, so
an unselected entry's passphrase is never computed and never enters
memory — reprinting one lost card does not put the whole inventory at
risk. Passphrases and the assembled PDF buffer are held in `Zeroizing`
containers; the written file is plaintext by design.

Determinism note: `printpdf` embeds creation timestamps into its
output, so PDF bytes are *not* byte-identical across runs. The
derived passphrases themselves are byte-identical — this is the
invariant the tool guarantees.

## CLI (`src/main.rs`)

Four subcommands parse arguments via `clap` and orchestrate the
library modules:

- `derive`: raw HKDF output, no encoding. Diagnostic use.
- `list`: iterate inventory, print info-strings with optional filters.
- `show`: single-entry derivation + encoding, pipe-friendly output.
- `report`: full-inventory PDF report.

All three secret-consuming subcommands read the master seed as raw
bytes from stdin, so the natural invocation is:

```bash
gpg --decrypt master-seed.gpg | hkdf-tree show --config ... --entry ...
```

The tool never opens the seed file itself; the caller controls its
lifecycle.

## Determinism contract

Everything below the CLI is deterministic. The following invariants
must hold across every future release, or they constitute a breaking
change requiring an inventory rotation (`-v1` → `-v2` on affected
entries):

- HKDF-SHA256 with the given `ikm`, `salt`, `info`, and `output_len`
  produces identical output bytes.
- The `BitReader` reads bits MSB-first, byte-index 0 first.
- `sample_uniform` uses `ceil(log2(max))` bits per sample and rejects
  samples `≥ max`.
- Diceware, alphanumeric, and numeric encoders consume samples in
  order and emit output in the order sampled.
- Alphanumeric character set is `A-Z a-z 0-9` in that exact order.
- Base64 uses the STANDARD (padded) alphabet.
- Iteration over inventory entries is sorted alphabetically at each
  tree level, then numerically by version.
- Info-string format is `<domain>/<realm>/<purpose>-v<N>`.

Every one of these facts is covered by a unit or integration test.

## Trust boundaries

- **Master seed**: outside the tool. The caller supplies it via
  stdin; we never persist it.
- **Inventory YAML**: trusted input on the local filesystem. Not
  cryptographically bound to the master seed; a swapped inventory
  produces different derivations.
- **Wordlist file** (if not built-in): trusted input on the local
  filesystem. Substitution changes derivations.
- **Binary itself**: trusted. Reproducibility depends on running the
  same version. The `--version` output is meaningful to record.
