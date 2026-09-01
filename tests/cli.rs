// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! End-to-end CLI tests.
//!
//! These tests spawn the compiled binary and exercise each subcommand
//! against controlled inputs, asserting on stdout, stderr, exit codes,
//! and generated files. They complement the fine-grained library tests
//! by covering the wiring layer that Rust unit tests alone cannot.

use std::io::Write;

use assert_cmd::Command;
use indoc::indoc;
use predicates::prelude::*;
use tempfile::NamedTempFile;

/// A fixed master seed used across the deterministic tests. Any non-empty
/// byte string works; the exact contents just have to be reproducible.
const SEED: &[u8] = b"deterministic-test-master-seed-32bytes";

fn cmd() -> Command {
    Command::cargo_bin("hkdf-tree").expect("binary should build")
}

fn write_inventory(yaml: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tempfile");
    file.write_all(yaml.as_bytes()).expect("write inventory");
    file
}

fn minimal_inventory() -> &'static str {
    indoc! {r#"
        schema_version: 1
        domains:
          alice:
            salt: "alice-hkdf-v1"
            realms:
              laptop:
                purposes:
                  fde-daily:
                    versions:
                      1:
                        encoding: {type: diceware, wordlist: eff_large, length: 6}
                        derivation: hkdf
                        status: active
                  uefi-pin:
                    versions:
                      1:
                        encoding: {type: numeric, length: 8}
                        derivation: hkdf
                        status: active
              github:
                purposes:
                  old-account:
                    versions:
                      1:
                        encoding: {type: alphanumeric, length: 12}
                        derivation: manual
                        status: retired
    "#}
}

// ============================================================================
// derive subcommand
// ============================================================================

#[test]
fn derive_produces_hex_by_default() {
    cmd()
        .args([
            "derive",
            "--salt",
            "s",
            "--info",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .assert()
        .success()
        .stdout(predicate::function(|s: &str| {
            let trimmed = s.trim_end();
            trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        }));
}

#[test]
fn derive_is_deterministic() {
    let a = cmd()
        .args(["derive", "--salt", "s", "--info", "i"])
        .write_stdin(SEED)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let b = cmd()
        .args(["derive", "--salt", "s", "--info", "i"])
        .write_stdin(SEED)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(a, b);
}

#[test]
fn derive_different_info_different_output() {
    let a = cmd()
        .args(["derive", "--salt", "s", "--info", "one"])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;
    let b = cmd()
        .args(["derive", "--salt", "s", "--info", "two"])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;
    assert_ne!(a, b);
}

#[test]
fn derive_empty_stdin_is_error() {
    cmd()
        .args(["derive", "--salt", "s", "--info", "i"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty master seed"));
}

#[test]
fn derive_output_len_controls_length() {
    let out = cmd()
        .args(["derive", "--info", "i", "--output-len", "16"])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;
    // 16 bytes = 32 hex chars + newline
    assert_eq!(out.len(), 33);
}

// ============================================================================
// list subcommand
// ============================================================================

#[test]
fn list_prints_all_entries_sorted() {
    let inv = write_inventory(minimal_inventory());
    cmd()
        .args(["list", "--config", inv.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice/github/old-account-v1"))
        .stdout(predicate::str::contains("alice/laptop/fde-daily-v1"))
        .stdout(predicate::str::contains("alice/laptop/uefi-pin-v1"));
}

#[test]
fn list_verbose_includes_metadata() {
    let inv = write_inventory(minimal_inventory());
    cmd()
        .args(["list", "--config", inv.path().to_str().unwrap(), "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hkdf"))
        .stdout(predicate::str::contains("manual"))
        .stdout(predicate::str::contains("diceware/eff_large/6"));
}

#[test]
fn list_filters_by_status() {
    let inv = write_inventory(minimal_inventory());
    let out = cmd()
        .args([
            "list",
            "--config",
            inv.path().to_str().unwrap(),
            "--status",
            "retired",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("alice/github/old-account-v1"));
    assert!(!stdout.contains("alice/laptop/fde-daily-v1"));
}

#[test]
fn list_filters_by_derivation() {
    let inv = write_inventory(minimal_inventory());
    let out = cmd()
        .args([
            "list",
            "--config",
            inv.path().to_str().unwrap(),
            "--derivation",
            "manual",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("alice/github/old-account-v1"));
    assert!(!stdout.contains("alice/laptop/fde-daily-v1"));
}

// ============================================================================
// show subcommand
// ============================================================================

#[test]
fn show_diceware_produces_words_from_eff_large() {
    let inv = write_inventory(minimal_inventory());
    let output = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
            "--newline",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let words: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(words.len(), 6, "got: {stdout:?}");
    // All words should be non-empty ASCII (Diceware words).
    for w in &words {
        assert!(!w.is_empty());
        assert!(w.chars().all(|c| c.is_ascii_lowercase()), "word {w:?}");
    }
}

#[test]
fn show_is_deterministic() {
    let inv = write_inventory(minimal_inventory());
    let out_a = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;
    let out_b = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;
    assert_eq!(out_a, out_b);
}

#[test]
fn show_numeric_produces_pin() {
    let inv = write_inventory(minimal_inventory());
    let output = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/uefi-pin-v1",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert_eq!(stdout.len(), 8);
    assert!(stdout.chars().all(|c| c.is_ascii_digit()), "got {stdout:?}");
}

#[test]
fn show_refuses_manual_entry() {
    let inv = write_inventory(minimal_inventory());
    cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/github/old-account-v1",
        ])
        .write_stdin(SEED)
        .assert()
        .failure()
        .stderr(predicate::str::contains("derivation: manual"));
}

#[test]
fn show_missing_entry_is_error() {
    let inv = write_inventory(minimal_inventory());
    cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/nonexistent-v1",
        ])
        .write_stdin(SEED)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no entry named"));
}

// ============================================================================
// report subcommand
// ============================================================================

#[test]
fn report_writes_pdf_file() {
    let inv = write_inventory(minimal_inventory());
    let output_pdf = NamedTempFile::new().expect("tempfile").into_temp_path();

    cmd()
        .args([
            "report",
            "--config",
            inv.path().to_str().unwrap(),
            "--output",
            output_pdf.to_str().unwrap(),
            "--subtitle",
            "2026-07-22",
        ])
        .write_stdin(SEED)
        .assert()
        .success();

    let bytes = std::fs::read(&output_pdf).expect("read pdf");
    assert!(
        bytes.starts_with(b"%PDF"),
        "not a PDF: first bytes {:?}",
        &bytes[..8.min(bytes.len())]
    );
    assert!(bytes.len() > 5000, "PDF too small: {} bytes", bytes.len());
}

#[test]
fn report_entry_filter_selects_one_card() {
    let inv = write_inventory(minimal_inventory());
    let full = NamedTempFile::new().expect("tempfile").into_temp_path();
    let single = NamedTempFile::new().expect("tempfile").into_temp_path();

    cmd()
        .args([
            "report",
            "--config",
            inv.path().to_str().unwrap(),
            "--output",
            full.to_str().unwrap(),
        ])
        .write_stdin(SEED)
        .assert()
        .success();

    cmd()
        .args([
            "report",
            "--config",
            inv.path().to_str().unwrap(),
            "--output",
            single.to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .assert()
        .success();

    let full_len = std::fs::read(&full).expect("read full").len();
    let single_len = std::fs::read(&single).expect("read single").len();
    assert!(
        single_len < full_len,
        "single-card report ({single_len}) should be smaller than the full one ({full_len})"
    );
}

#[test]
fn report_unknown_entry_is_rejected() {
    let inv = write_inventory(minimal_inventory());
    let out = NamedTempFile::new().expect("tempfile").into_temp_path();

    cmd()
        .args([
            "report",
            "--config",
            inv.path().to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--entry",
            "alice/laptop/typo-v1",
        ])
        .write_stdin(SEED)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the inventory"));
}

#[test]
fn report_empty_selection_is_rejected() {
    let inv = write_inventory(minimal_inventory());
    let out = NamedTempFile::new().expect("tempfile").into_temp_path();

    cmd()
        .args([
            "report",
            "--config",
            inv.path().to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--status",
            "reserved",
        ])
        .write_stdin(SEED)
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty report"));
}

// ============================================================================
// determinism across the pipeline
// ============================================================================

/// The report is deterministic in the sense that the derived passphrases
/// inside are stable. The PDF bytes themselves are not byte-exact
/// deterministic because printpdf embeds creation timestamps, so we
/// compare derived passphrases via the `show` subcommand instead.
#[test]
fn same_seed_same_inventory_same_passphrase() {
    let inv = write_inventory(minimal_inventory());

    let phrase_1 = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;

    let phrase_2 = cmd()
        .args([
            "show",
            "--config",
            inv.path().to_str().unwrap(),
            "--entry",
            "alice/laptop/fde-daily-v1",
        ])
        .write_stdin(SEED)
        .output()
        .expect("run")
        .stdout;

    assert_eq!(phrase_1, phrase_2);
    assert!(!phrase_1.is_empty());
}
