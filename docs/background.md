# Background: what the derivation is built on

This document explains the reasoning behind `hkdf-tree` and names the
sources it rests on, so that a reader can check the construction rather
than trust it.

## The problem

Modern practice asks a person to hold dozens of independent, high-entropy
secrets: full-disk encryption passphrases, recovery codes, device PINs,
key passwords. Two established answers exist. A password *manager* stores
them — which turns availability of the store into a precondition for
access, and makes a stolen or corrupted store an incident. A password
*generator* derives them — which replaces storage with reproduction: what
can be recomputed need not be kept.

`hkdf-tree` takes the second route, with one deliberate restriction: it
derives *from a single high-entropy master seed*, never from a
human-chosen master password.

## Why not a master password

Deriving keys from something a human invented is the failure mode
documented for years: user-chosen passwords carry far less entropy than
their length suggests, so the derivation's strength collapses to the
strength of the weakest input. That is why password-based schemes need
deliberately slow key-derivation functions (PBKDF2, scrypt, Argon2) —
they buy back a work factor that entropy did not provide.

`hkdf-tree` sidesteps that trade entirely. Its input is a random master
seed of at least 256 bits, produced by the operating system's CSPRNG and
kept offline (an encrypted file, a hardware token, or paper). With a
uniformly random input of that size, no work factor is needed: an
attacker's cheapest path is not to attack the derivation but to attack
the seed's storage. This shifts the entire security argument onto one
question a reader can actually evaluate — *how well is the seed
protected?* — instead of onto the unknowable entropy of a remembered
phrase.

## Why HKDF

HKDF (RFC 5869) is a key-derivation function built on HMAC (RFC 2104) in
the *extract-then-expand* paradigm of Krawczyk's analysis. It splits the
job in two:

- **Extract** condenses input keying material into a uniformly random
  pseudorandom key, using an optional salt.
- **Expand** stretches that key into any number of independent output
  keys, each bound to an `info` string.

The `info` parameter is what makes HKDF the right primitive here.
Krawczyk's design intent is explicit: different `info` values yield
cryptographically independent outputs from the same key material. That is
exactly the property a hierarchical secret tree needs — knowing the
passphrase for `alice/laptop/fde-daily-v1` must reveal nothing about
`alice/phone/unlock-v1`.

`hkdf-tree` therefore encodes each credential's full path into the `info`
string and uses a per-domain `salt`. Salt and info are **not secrets**;
they carry no confidentiality requirement, which is why an inventory file
can live in version control while the seed does not.

## The tree

    inventory → domain → realm → purpose → version

The path is the identity of a credential, and the version number is how
rotation works: bumping `v1` to `v2` changes the `info` string, hence the
output, while every other credential stays untouched. Rotation without
re-deriving the world is a direct consequence of HKDF's independence
property, not an extra mechanism.

Everything else in the inventory (usage text, status, notes, backup
locations) is documentation. Only four inputs affect a derived value:
path names, version number, domain salt, and the encoding parameters.

## From bits to something a human can type

Derived bytes are uniformly random; turning them into words, characters
or digits must not introduce bias. `hkdf-tree` reads the output stream
bit by bit (most significant first) and uses **rejection sampling**: a
sample outside the target range is discarded and redrawn, rather than
folded in with a modulo — the classic source of skewed distributions in
password generators.

For the word encoding, the EFF long wordlist (7776 words, five dice
rolls per word) is compiled in. It descends from Reinhold's Diceware and
was revised by the EFF for typability and to remove confusable entries.
Its arithmetic is the reason the list is popular: log2(7776) ≈ 12.92 bits
per word, so a six-word phrase carries about 77.5 bits and an eight-word
phrase about 103 bits.

For the entropy claim itself, NIST SP 800-63B is the reference point:
randomly generated secrets are credited with their full entropy, while
user-chosen ones are not — the formal expression of the argument in the
section above.

## What the construction does *not* do

- It does not protect the master seed. That is the operator's job, and
  every derived secret depends on it (see `docs/threat-model.md`).
- It does not authenticate anything. HKDF is a KDF, not a signature.
- It does not remember which secrets you have actually deployed. The
  inventory is a declaration; keeping it truthful is a discipline the
  tool supports (`hkdf-tree list`) but cannot enforce.

## References

- H. Krawczyk, P. Eronen. *HMAC-based Extract-and-Expand Key Derivation
  Function (HKDF)*. RFC 5869, May 2010.
  <https://www.rfc-editor.org/rfc/rfc5869>
- H. Krawczyk. *Cryptographic Extraction and Key Derivation: The HKDF
  Scheme*. CRYPTO 2010. <https://eprint.iacr.org/2010/264>
- H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message
  Authentication*. RFC 2104, February 1997.
  <https://www.rfc-editor.org/rfc/rfc2104>
- NIST. *FIPS 180-4: Secure Hash Standard (SHS)*, August 2015.
  <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
- NIST. *SP 800-63B: Digital Identity Guidelines — Authentication and
  Lifecycle Management*. <https://pages.nist.gov/800-63-3/sp800-63b.html>
- NIST. *SP 800-90A Rev. 1: Recommendation for Random Number Generation
  Using Deterministic Random Bit Generators*.
  <https://csrc.nist.gov/pubs/sp/800/90/a/r1/final>
- Electronic Frontier Foundation. *Deep Dive: EFF's New Wordlists for
  Random Passphrases*, 2016.
  <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>
- A. G. Reinhold. *The Diceware Passphrase Home Page*.
  <https://theworld.com/~reinhold/diceware.html>
- RustCrypto. *`hkdf` crate* (the implementation used here).
  <https://docs.rs/hkdf>
