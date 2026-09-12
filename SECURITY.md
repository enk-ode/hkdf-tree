# Security Policy

## Status

`hkdf-tree` is at `0.1.0`: the derivation is specified and covered by the
RFC 5869 test vectors, and the determinism contract in
`docs/architecture.md` is what future versions are held to. Treat it as
young software nonetheless — review it before you put a master seed into
it, and keep an independent recovery path until you have run a full
restore drill (see `docs/cookbook.md`).

## Reporting a vulnerability

For security-relevant issues **do not** open a public GitHub issue.

Please contact the maintainer privately: `dr.johannes.bruegmann@gmail.com`,
or via the GitHub profile of `enk-ode`.

## Scope

In scope:

- Cryptographic correctness of the HKDF derivation.
- Handling of the master seed in memory (leaks via panics, error messages,
  swap, core dumps).
- Correctness of encoding functions (Diceware wordlist mapping, alphanumeric,
  numeric, base64).
- YAML parsing safety (untrusted inventory files).
- Report generation (QR code content leakage, PDF metadata leakage).

Out of scope:

- Weaknesses in the master seed itself (generation, backup, physical storage).
- Weaknesses in downstream services that consume the derived passphrases.
- Denial of service on the local machine running the tool.
