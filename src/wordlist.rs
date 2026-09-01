// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! Wordlist resolution for Diceware-style encodings.
//!
//! Names referenced in the inventory YAML (`wordlist: eff_large`) are
//! resolved to a `Vec<String>` here. Two resolution modes:
//!
//! - **Built-in names** (`eff_large`) return an embedded, compile-time
//!   constant wordlist. No filesystem access, no failure modes.
//! - **Paths** (any name containing `/`) are read from disk with one
//!   word per line.
//!
//! Wordlist parsing accepts two formats: plain one-word-per-line
//! (as most Diceware wordlists are distributed) and the tab-separated
//! `<roll>\t<word>` format used by the EFF's own distribution.

use std::fs;
use std::path::Path;

/// Errors that can arise while resolving a wordlist.
#[derive(Debug, thiserror::Error)]
pub enum WordlistError {
    /// The requested built-in wordlist name is not known.
    #[error("unknown built-in wordlist: {0}")]
    UnknownBuiltin(String),
    /// The wordlist file could not be read.
    #[error("failed to read wordlist file {path}: {source}")]
    Read {
        /// Filesystem path attempted.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The wordlist file was empty after parsing.
    #[error("wordlist {0} contains no words")]
    Empty(String),
}

/// The EFF Large Wordlist, embedded at compile time.
/// See `wordlists/README.md` for licensing.
const EFF_LARGE_RAW: &str = include_str!("../wordlists/eff_large.txt");

/// Resolve a wordlist name from the inventory to an owned list of words.
///
/// - If `name` matches a built-in wordlist identifier, the embedded copy
///   is returned.
/// - If `name` contains a path separator or refers to an existing file,
///   the file is read and parsed.
/// - Otherwise, an error is returned so users cannot silently fall back
///   to something unexpected.
pub fn resolve(name: &str) -> Result<Vec<String>, WordlistError> {
    if let Some(words) = builtin(name) {
        return Ok(words);
    }
    if name.contains('/') || Path::new(name).exists() {
        return read_file(name);
    }
    Err(WordlistError::UnknownBuiltin(name.to_string()))
}

fn builtin(name: &str) -> Option<Vec<String>> {
    match name {
        "eff_large" => Some(parse(EFF_LARGE_RAW)),
        _ => None,
    }
}

fn read_file(path: &str) -> Result<Vec<String>, WordlistError> {
    let content = fs::read_to_string(path).map_err(|source| WordlistError::Read {
        path: path.to_string(),
        source,
    })?;
    let words = parse(&content);
    if words.is_empty() {
        return Err(WordlistError::Empty(path.to_string()));
    }
    Ok(words)
}

/// Parse a wordlist string, accepting both plain (`word\n`) and
/// EFF-style tab-separated (`<roll>\t<word>\n`) formats.
///
/// Lines are trimmed of ASCII whitespace; blank lines are skipped.
/// If a line contains a tab, only the substring after the last tab is
/// taken as the word.
fn parse(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| match l.rsplit_once('\t') {
            Some((_, word)) => word.trim().to_string(),
            None => l.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_eff_large_builtin() {
        let words = resolve("eff_large").expect("built-in should resolve");
        assert_eq!(words.len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[1], "abdomen");
        assert_eq!(words[2], "abdominal");
    }

    #[test]
    fn rejects_unknown_builtin() {
        let err = resolve("no-such-list").unwrap_err();
        matches!(err, WordlistError::UnknownBuiltin(_));
    }

    #[test]
    fn parse_handles_tab_separated_format() {
        let raw = "11111\tabacus\n11112\tabdomen\n";
        let words = parse(raw);
        assert_eq!(words, vec!["abacus", "abdomen"]);
    }

    #[test]
    fn parse_handles_plain_format() {
        let raw = "abacus\nabdomen\n";
        let words = parse(raw);
        assert_eq!(words, vec!["abacus", "abdomen"]);
    }

    #[test]
    fn parse_skips_blank_lines_and_trims() {
        let raw = "\n  abacus  \n\n\tabdomen\n\n";
        let words = parse(raw);
        assert_eq!(words, vec!["abacus", "abdomen"]);
    }
}
