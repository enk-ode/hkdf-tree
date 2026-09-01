// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use hkdf_tree::inventory::{Derivation, Encoding, Inventory, Status};
use hkdf_tree::report::{ReportEntry, ReportMeta, build_report};

/// Deterministic hierarchical passphrase derivation via HKDF-SHA256.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive raw HKDF-SHA256 output bytes from a master seed on stdin.
    ///
    /// Reads the entire standard input as raw input keying material,
    /// applies HKDF-SHA256 with the provided salt and info string, and
    /// writes the derived bytes to standard output.
    ///
    /// The master seed is treated as raw bytes. If your seed is stored
    /// hex-encoded, decode it first (for example: `xxd -r -p seed.hex`).
    Derive(DeriveArgs),

    /// List all entries in a YAML inventory.
    ///
    /// Loads and validates the inventory at `--config`, then prints one
    /// info-string per entry (domain/realm/purpose-vN), sorted deterministically.
    /// With `--verbose`, additional metadata (derivation type, status, encoding)
    /// is included on each line.
    List(ListArgs),

    /// Derive and encode one entry from the inventory as a usable passphrase.
    ///
    /// Combines the inventory lookup, HKDF derivation, and encoding steps.
    /// Reads the master seed as raw bytes from stdin.
    ///
    /// The entry's `derivation` must be `hkdf`. Manual and service-generated
    /// entries are refused because this tool cannot reproduce them.
    Show(ShowArgs),

    /// Generate a printable PDF report of all inventory entries.
    ///
    /// For each entry, produces a card containing the info-string, encoding
    /// description, human-readable passphrase, and a QR code encoding the
    /// same passphrase. Manual and service-generated entries appear as
    /// placeholder cards without a QR code.
    ///
    /// Reads the master seed as raw bytes from stdin. Writes the PDF to the
    /// path given by `--output`.
    ///
    /// Handle the output file with care: it contains every derived
    /// passphrase in plaintext. Print and destroy — do not archive.
    Report(ReportArgs),
}

#[derive(Args)]
struct DeriveArgs {
    /// Salt for domain separation. Public parameter; may be omitted (empty).
    #[arg(long, default_value = "")]
    salt: String,

    /// Info string binding this derivation to a specific context. Required.
    ///
    /// A common convention is a hierarchical path like
    /// `alice/laptop/fde-daily-v1`. See the project README for details.
    #[arg(long)]
    info: String,

    /// Number of output bytes to derive.
    #[arg(long, default_value_t = 32)]
    output_len: usize,

    /// Write raw bytes to stdout instead of hex.
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
struct ListArgs {
    /// Path to the YAML inventory file.
    #[arg(long)]
    config: PathBuf,

    /// Include per-entry metadata (derivation, status, encoding) on each line.
    #[arg(long, short)]
    verbose: bool,

    /// Only include entries with the given status. May be repeated.
    #[arg(long, value_enum)]
    status: Vec<StatusFilter>,

    /// Only include entries with the given derivation kind. May be repeated.
    #[arg(long, value_enum)]
    derivation: Vec<DerivationFilter>,
}

#[derive(Args)]
struct ShowArgs {
    /// Path to the YAML inventory file.
    #[arg(long)]
    config: PathBuf,

    /// Info-string of the entry to derive, e.g. `alice/laptop/fde-daily-v1`.
    #[arg(long)]
    entry: String,

    /// Append a trailing newline to the output (default: no newline).
    #[arg(long)]
    newline: bool,
}

#[derive(Args)]
struct ReportArgs {
    /// Path to the YAML inventory file.
    #[arg(long)]
    config: PathBuf,

    /// Path where the PDF report will be written.
    #[arg(long)]
    output: PathBuf,

    /// Report title (defaults to "hkdf-tree passphrase report").
    #[arg(long, default_value = "hkdf-tree passphrase report")]
    title: String,

    /// Report subtitle, typically the date. Free-form.
    #[arg(long, default_value = "")]
    subtitle: String,

    /// Optional short fingerprint of the master seed printed on the cover
    /// page (e.g. first + last 4 BIP-39 words) for cross-verification
    /// against your paper backup. Purely informational.
    #[arg(long)]
    fingerprint: Option<String>,

    /// Only include this entry, by exact info-string. May be repeated.
    /// Without it, every entry in the inventory is included.
    ///
    /// Selection happens before derivation, so unselected passphrases are
    /// never computed and never reach the output file.
    #[arg(long)]
    entry: Vec<String>,

    /// Only include entries with the given status. May be repeated.
    #[arg(long, value_enum)]
    status: Vec<StatusFilter>,

    /// Only include entries with the given derivation kind. May be repeated.
    #[arg(long, value_enum)]
    derivation: Vec<DerivationFilter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum StatusFilter {
    Active,
    Retired,
    Reserved,
}

impl StatusFilter {
    fn matches(self, status: Status) -> bool {
        matches!(
            (self, status),
            (StatusFilter::Active, Status::Active)
                | (StatusFilter::Retired, Status::Retired)
                | (StatusFilter::Reserved, Status::Reserved)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum DerivationFilter {
    Hkdf,
    Manual,
    ServiceGenerated,
}

impl DerivationFilter {
    fn matches(self, derivation: Derivation) -> bool {
        matches!(
            (self, derivation),
            (DerivationFilter::Hkdf, Derivation::Hkdf)
                | (DerivationFilter::Manual, Derivation::Manual)
                | (
                    DerivationFilter::ServiceGenerated,
                    Derivation::ServiceGenerated
                )
        )
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Derive(args) => run_derive(args),
        Command::List(args) => run_list(args),
        Command::Show(args) => run_show(args),
        Command::Report(args) => run_report(args),
    }
}

fn run_derive(args: DeriveArgs) -> Result<()> {
    // Preallocate generously: a growing Vec reallocates, and every
    // reallocation strands an un-zeroized copy of the seed in freed heap
    // memory. Seeds are tiny; one upfront reservation avoids that entirely.
    let mut ikm = Zeroizing::new(Vec::with_capacity(64 * 1024));
    io::stdin()
        .read_to_end(&mut ikm)
        .context("reading master seed from stdin")?;
    if ikm.is_empty() {
        bail!("empty master seed on stdin");
    }

    let okm = hkdf_tree::derive_bytes(
        &ikm,
        args.salt.as_bytes(),
        args.info.as_bytes(),
        args.output_len,
    )?;

    let mut stdout = io::stdout().lock();
    if args.raw {
        stdout
            .write_all(&okm)
            .context("writing raw output to stdout")?;
    } else {
        writeln!(stdout, "{}", hex::encode(okm.as_slice())).context("writing hex output")?;
    }

    Ok(())
}

fn run_list(args: ListArgs) -> Result<()> {
    let yaml = fs::read_to_string(&args.config)
        .with_context(|| format!("reading inventory from {}", args.config.display()))?;
    let inventory = Inventory::from_yaml_str(&yaml)
        .with_context(|| format!("parsing inventory {}", args.config.display()))?;

    let mut stdout = io::stdout().lock();
    for entry in inventory.entries() {
        if !args.status.is_empty() && !args.status.iter().any(|s| s.matches(entry.version.status)) {
            continue;
        }
        if !args.derivation.is_empty()
            && !args
                .derivation
                .iter()
                .any(|d| d.matches(entry.version.derivation))
        {
            continue;
        }

        if args.verbose {
            writeln!(
                stdout,
                "{}\t{}\t{}\t{}",
                entry.info_string,
                format_derivation(entry.version.derivation),
                format_status(entry.version.status),
                format_encoding(&entry.version.encoding),
            )?;
        } else {
            writeln!(stdout, "{}", entry.info_string)?;
        }
    }

    Ok(())
}

/// Size of the HKDF output buffer passed to encoders. Chosen as a comfortable
/// upper bound: even a 20-word Diceware phrase (~260 bits with rejection)
/// or a 40-character alphanumeric passphrase (~250 bits) fits with room to
/// spare in 1024 bits.
const DERIVE_BUFFER_BYTES: usize = 128;

fn run_show(args: ShowArgs) -> Result<()> {
    let yaml = fs::read_to_string(&args.config)
        .with_context(|| format!("reading inventory from {}", args.config.display()))?;
    let inventory = Inventory::from_yaml_str(&yaml)
        .with_context(|| format!("parsing inventory {}", args.config.display()))?;

    let entry = inventory
        .find_entry(&args.entry)
        .with_context(|| format!("no entry named {:?} in inventory", args.entry))?;

    match entry.version.derivation {
        Derivation::Hkdf => {}
        Derivation::Manual => bail!(
            "entry {:?} is marked derivation: manual — this tool cannot reproduce a value chosen out-of-band",
            args.entry
        ),
        Derivation::ServiceGenerated => bail!(
            "entry {:?} is marked derivation: service-generated — this tool cannot reproduce a value issued by an external service",
            args.entry
        ),
    }

    // Preallocate generously: a growing Vec reallocates, and every
    // reallocation strands an un-zeroized copy of the seed in freed heap
    // memory. Seeds are tiny; one upfront reservation avoids that entirely.
    let mut ikm = Zeroizing::new(Vec::with_capacity(64 * 1024));
    io::stdin()
        .read_to_end(&mut ikm)
        .context("reading master seed from stdin")?;
    if ikm.is_empty() {
        bail!("empty master seed on stdin");
    }

    let raw = hkdf_tree::derive_bytes(
        &ikm,
        entry.salt.as_bytes(),
        entry.info_string.as_bytes(),
        DERIVE_BUFFER_BYTES,
    )
    .context("HKDF derivation")?;

    let passphrase = encode_for_entry(&raw, &entry.version.encoding)
        .with_context(|| format!("encoding entry {:?}", args.entry))?;

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(passphrase.as_bytes())
        .context("writing passphrase")?;
    if args.newline {
        stdout.write_all(b"\n").context("writing newline")?;
    }
    Ok(())
}

/// Apply the encoding declared in the inventory to a raw HKDF output buffer.
///
/// For Diceware encodings the wordlist is resolved via
/// [`hkdf_tree::wordlist::resolve`]. Built-in wordlists (`eff_large`) are
/// embedded; other names are read from disk if they look like a path.
fn encode_for_entry(raw: &[u8], encoding: &Encoding) -> Result<Zeroizing<String>> {
    match encoding {
        Encoding::Diceware { wordlist, length } => {
            let words = hkdf_tree::wordlist::resolve(wordlist)
                .with_context(|| format!("resolving wordlist {wordlist:?}"))?;
            let words_ref: Vec<&str> = words.iter().map(String::as_str).collect();
            hkdf_tree::encoding::encode_diceware(raw, &words_ref, *length)
                .context("Diceware encoding")
        }
        Encoding::Alphanumeric { length } => {
            hkdf_tree::encoding::encode_alphanumeric(raw, *length).context("alphanumeric encoding")
        }
        Encoding::Numeric { length } => {
            hkdf_tree::encoding::encode_numeric(raw, *length).context("numeric encoding")
        }
        Encoding::Base64 { bytes } => {
            hkdf_tree::encoding::encode_base64(raw, *bytes).context("base64 encoding")
        }
    }
}

fn format_derivation(d: Derivation) -> &'static str {
    match d {
        Derivation::Hkdf => "hkdf",
        Derivation::Manual => "manual",
        Derivation::ServiceGenerated => "service-generated",
    }
}

fn format_status(s: Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::Retired => "retired",
        Status::Reserved => "reserved",
    }
}

fn format_encoding(e: &Encoding) -> String {
    match e {
        Encoding::Diceware { wordlist, length } => format!("diceware/{wordlist}/{length}"),
        Encoding::Alphanumeric { length } => format!("alphanumeric/{length}"),
        Encoding::Numeric { length } => format!("numeric/{length}"),
        Encoding::Base64 { bytes } => format!("base64/{bytes}"),
    }
}

fn run_report(args: ReportArgs) -> Result<()> {
    let yaml = fs::read_to_string(&args.config)
        .with_context(|| format!("reading inventory from {}", args.config.display()))?;
    let inventory = Inventory::from_yaml_str(&yaml)
        .with_context(|| format!("parsing inventory {}", args.config.display()))?;

    // Preallocate generously: a growing Vec reallocates, and every
    // reallocation strands an un-zeroized copy of the seed in freed heap
    // memory. Seeds are tiny; one upfront reservation avoids that entirely.
    let mut ikm = Zeroizing::new(Vec::with_capacity(64 * 1024));
    io::stdin()
        .read_to_end(&mut ikm)
        .context("reading master seed from stdin")?;
    if ikm.is_empty() {
        bail!("empty master seed on stdin");
    }

    let mut salt_seen: Option<String> = None;

    // Selection happens before derivation, so an unselected entry's passphrase
    // is never computed and cannot reach tmpfs or the PDF. Reprinting a single
    // card therefore exposes exactly that one secret.
    //
    // An explicit --entry is never overridden by --status/--derivation: a named
    // request that got silently dropped would be indistinguishable from a
    // successful run. Those two filters apply only when --entry is absent.
    let filter_by_entry = !args.entry.is_empty();
    let mut requested: BTreeSet<String> = args.entry.iter().cloned().collect();

    let mut report_entries: Vec<ReportEntry> = Vec::new();
    for entry in inventory.entries() {
        let selected = if filter_by_entry {
            requested.remove(&entry.info_string)
        } else {
            (args.status.is_empty() || args.status.iter().any(|s| s.matches(entry.version.status)))
                && (args.derivation.is_empty()
                    || args
                        .derivation
                        .iter()
                        .any(|d| d.matches(entry.version.derivation)))
        };
        if !selected {
            continue;
        }

        if salt_seen.is_none() {
            salt_seen = Some(entry.salt.to_string());
        }
        let encoding_desc = format_encoding(&entry.version.encoding);
        let paper_backup = entry.version.paper_backup.clone();
        let notes = entry.version.notes.clone();

        let (passphrase, is_derived) = match entry.version.derivation {
            Derivation::Hkdf => {
                let raw = hkdf_tree::derive_bytes(
                    &ikm,
                    entry.salt.as_bytes(),
                    entry.info_string.as_bytes(),
                    DERIVE_BUFFER_BYTES,
                )
                .with_context(|| format!("HKDF for {}", entry.info_string))?;
                let phrase = encode_for_entry(&raw, &entry.version.encoding)
                    .with_context(|| format!("encoding {}", entry.info_string))?;
                (phrase, true)
            }
            Derivation::Manual => (
                Zeroizing::new("(manual — enter your chosen value by hand)".to_string()),
                false,
            ),
            Derivation::ServiceGenerated => (
                Zeroizing::new(
                    "(service-generated — paste recovery codes from the provider)".to_string(),
                ),
                false,
            ),
        };

        let title = match entry.usage {
            Some(usage) => usage.to_string(),
            None => entry
                .info_string
                .rsplit('/')
                .next()
                .unwrap_or(&entry.info_string)
                .to_string(),
        };

        report_entries.push(ReportEntry {
            title,
            info_string: entry.info_string.clone(),
            encoding_desc,
            passphrase,
            paper_backup,
            notes,
            is_derived,
        });
    }

    // A typo in an info-string must not look like a successful run: without
    // this, the misspelt entry is simply missing from the printout and only
    // shows up when the passphrase is needed and cannot be reproduced.
    if !requested.is_empty() {
        bail!(
            "not in the inventory: {}",
            requested.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if report_entries.is_empty() {
        bail!("no entries selected -- refusing to write an empty report");
    }

    let meta = ReportMeta {
        title: args.title,
        subtitle: args.subtitle,
        seed_fingerprint: args.fingerprint,
        salt_label: salt_seen,
    };

    let pdf_bytes =
        Zeroizing::new(build_report(&meta, &report_entries).context("building PDF report")?);

    // The report contains every derived passphrase in plaintext — restrict
    // it to the owner instead of inheriting the umask. (Applies on creation;
    // an existing output file keeps its permissions.)
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&args.output)
            .with_context(|| format!("opening {} for writing", args.output.display()))?
    };
    file.write_all(&pdf_bytes)
        .with_context(|| format!("writing PDF to {}", args.output.display()))?;

    eprintln!(
        "wrote {} bytes to {}",
        pdf_bytes.len(),
        args.output.display()
    );

    Ok(())
}
