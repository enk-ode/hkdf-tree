# Cookbook

Practical recipes for common `hkdf-tree` workflows.

Every recipe assumes:

- You have a **master seed** — 32 random bytes, ideally represented
  as a BIP-39 24-word phrase — stored in cold storage (paper + metal)
  and available on the machine running `hkdf-tree` in a form your
  toolchain can decrypt (typically a GPG-encrypted file whose key
  lives on a hardware token).
- You have a **YAML inventory** describing which secrets to derive.
- You have `hkdf-tree` installed and on your `$PATH`.

---

## 1. Create your first inventory

Write a file `~/.config/hkdf-tree/inventory.yaml`:

```yaml
schema_version: 1

domains:

  alice:
    salt: "alice-hkdf-v1"

    realms:

      laptop:
        kind: workstation-freebsd
        purposes:
          fde-daily:
            usage: "geli slot 0 unlock at boot"
            versions:
              1:
                encoding:
                  type: diceware
                  wordlist: eff_large
                  length: 8
                derivation: hkdf
                status: active
                memorized: true
                paper_backup: [home-safe, bank-vault]

      proton:
        kind: cloud-service
        purposes:
          account:
            usage: "Proton account login (mail + VPN)"
            versions:
              1:
                encoding:
                  type: diceware
                  wordlist: eff_large
                  length: 6
                derivation: hkdf
                status: active
                paper_backup: [home-safe, bank-vault]
```

Validate the structure without touching secrets:

```bash
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml
```

Output should be:

```
alice/laptop/fde-daily-v1
alice/proton/account-v1
```

If you get parse errors, they'll point to the exact YAML line.

---

## 2. Derive one passphrase for daily use

Assuming your master seed is in `~/.local/share/hkdf-tree/seed.gpg`:

```bash
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree show \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --entry alice/proton/account-v1
```

`gpg` will prompt for your hardware token PIN. Once entered, the
passphrase appears on stdout. No trailing newline (so you can pipe
it straight into a password field or `wl-copy`); add `--newline` if
you want one.

Copy to clipboard (Wayland):

```bash
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree show \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --entry alice/proton/account-v1 \
  | wl-copy
```

X11 equivalent: pipe to `xclip -selection clipboard`.

The clipboard now holds your passphrase. Paste it into the login
form. Then clear the clipboard when done: `wl-copy --clear`
(or `echo -n | xclip -selection clipboard`).

---

## 3. Generate the paper-backup PDF report

Prepare a scratch location on tmpfs so the PDF never touches
persistent storage:

```bash
mkdir -p /tmp/hkdf-print
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree report \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --output /tmp/hkdf-print/report.pdf \
      --subtitle "$(date +%F)" \
      --fingerprint "abacus xyz ... sunset"
```

Open the PDF, verify the cover page, print on an **offline** printer,
and immediately:

```bash
rm /tmp/hkdf-print/report.pdf
```

Store the printed copy in your safe. If the printer has internal
storage, power-cycle it before taking it back online.

---

## 4. Add a new service to the inventory

Say you're onboarding an EteSync account. Add to
`~/.config/hkdf-tree/inventory.yaml`:

```yaml
      etesync:
        kind: cloud-service
        purposes:
          passphrase:
            usage: "EteSync end-to-end master passphrase"
            versions:
              1:
                encoding:
                  type: diceware
                  wordlist: eff_large
                  length: 6
                derivation: hkdf
                status: active
                paper_backup: [home-safe, bank-vault]
```

Re-derive:

```bash
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree show \
      --config ~/.config/hkdf-tree/inventory.yaml \
      --entry alice/etesync/passphrase-v1
```

Set that value in EteSync during account creation. Regenerate the
report so the safe copy stays current.

---

## 5. Rotate a compromised passphrase

Say you suspect the Proton passphrase was shoulder-surfed. Rotate it
by bumping the version:

```yaml
      proton:
        purposes:
          account:
            versions:
              1:                          # keep for reference
                encoding: {type: diceware, wordlist: eff_large, length: 6}
                derivation: hkdf
                status: retired
              2:                          # new active
                encoding: {type: diceware, wordlist: eff_large, length: 6}
                derivation: hkdf
                status: active
```

Derive the new one:

```bash
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree show --config ... --entry alice/proton/account-v2
```

Change the password on the Proton side. Regenerate the report. Shred
the previous paper copy.

The v1 entry stays in the inventory for archaeological purposes;
`list --status retired` surfaces it later.

---

## 6. Document a non-derivable secret

Some secrets — 2FA recovery codes, legacy passwords chosen out of
band, service-issued app passwords — can't be regenerated. Document
them anyway so your paper backup remains complete:

```yaml
      proton:
        purposes:
          2fa-recovery:
            usage: "Proton 2FA recovery codes"
            versions:
              1:
                encoding:
                  type: base64        # placeholder, not derived
                  bytes: 32
                derivation: service-generated
                status: reserved
                paper_backup: [bank-vault]
                notes: |
                  Copy the 8 recovery codes Proton issues at 2FA setup
                  into this slot on the printed report by hand.
```

`show` refuses to derive it (`this tool cannot reproduce a
service-generated value`), `list` includes it, and `report` produces
a `NOT DERIVED` placeholder card with your notes so you know to
fill it in by hand.

---

## 7. Audit the inventory

```bash
# Everything, most detail:
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml -v

# Only what's live:
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml --status active

# Only what this tool can produce today:
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml --derivation hkdf

# Only what needs manual attention (documented but not derivable):
hkdf-tree list --config ~/.config/hkdf-tree/inventory.yaml \
    --derivation manual --derivation service-generated
```

Pipe to `wc -l` for counts. Diff two inventories with `diff` to review
proposed changes before committing them.

---

## 8. Recover after losing the tool

You lost your daily laptop but the master seed on paper and the
inventory backup survived. On a fresh machine:

1. Install `hkdf-tree` (`cargo install hkdf-tree`, or build from
   source).
2. Restore the inventory YAML to a known location.
3. Type the master seed from paper into a scratch file, encrypt it
   with a fresh GPG key on a new hardware token, or feed it directly:

   ```bash
   # BIP-39 to raw bytes (requires an external tool like `bip39`):
   bip39 --decode "word1 word2 ... word24" \
     | hkdf-tree show --config ... --entry ...
   ```

4. Every derived passphrase reappears identical to the original.

---

## 9. When to bump the version suffix

Rotate to `-v<N+1>` when:

- You believe a specific passphrase has been shoulder-surfed,
  screen-captured, or otherwise leaked.
- A service where you used the passphrase has a breach announcement,
  and you can't tell whether your credential was in it.
- A wordlist you were using is discovered to be flawed. (Rare; the
  EFF wordlists are stable.)
- You want to force a periodic rotation on a schedule.

Leave the previous version's entry in place with `status: retired`
so the inventory tells the whole story of a secret's lifetime.

Never delete a retired entry from the inventory unless you are
certain the corresponding secret is out of use everywhere. The
inventory is your only durable record of what once existed.

---

## 10. Compose with `pass`

If you use `pass` (the standard Unix password manager), pipe
`hkdf-tree show` output straight into it:

```bash
gpg --decrypt ~/.local/share/hkdf-tree/seed.gpg \
  | hkdf-tree show --config ... --entry alice/proton/account-v1 \
  | pass insert -e proton/account
```

Now `pass -c proton/account` puts the passphrase on the clipboard
without ever showing it on screen. The pass store is redundant with
the derivation but useful for daily convenience.
