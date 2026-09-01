// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! PDF report generation with QR codes.
//!
//! Produces a printable A4 PDF containing one card per inventory entry:
//! a title next to the QR code in the header area, followed below by the
//! info-string, encoding description, and human-readable passphrase. The
//! QR code encodes the same passphrase for optical restore.
//!
//! The report is intended for **paper backup**, printed on an offline
//! printer and stored physically (home safe, bank vault). It should never
//! be persisted to disk in plaintext beyond the moments necessary to
//! spool it to the printer. Callers must arrange for secure disposal
//! (tmpfs output, shred on shutdown).

use printpdf::path::{PaintMode, WindingOrder};
use printpdf::{
    BuiltinFont, IndirectFontRef, Line, LineDashPattern, Mm, PdfDocument, PdfDocumentReference,
    Point, Polygon, Rgb,
};
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

/// One card's worth of content in the report.
#[derive(Debug, Clone)]
pub struct ReportEntry {
    /// Human-readable card title (the purpose's `usage` text, or the last
    /// info-string segment as fallback). Wrapped next to the QR code.
    pub title: String,
    /// The full info-string identifying this credential.
    pub info_string: String,
    /// Human-readable description of the encoding (e.g., "diceware/eff_large/8").
    pub encoding_desc: String,
    /// The derived passphrase (or a placeholder note if non-derivable).
    /// Wrapped in `Zeroizing` so the plaintext is wiped when the entry is
    /// dropped: the report path is the one place where derived material is
    /// held in memory for longer than a single write.
    pub passphrase: Zeroizing<String>,
    /// Any paper-backup destinations declared for this entry.
    pub paper_backup: Vec<String>,
    /// Optional free-form notes.
    pub notes: Option<String>,
    /// True if the passphrase was derived successfully; false if the entry
    /// is manual / service-generated (in which case `passphrase` typically
    /// contains a placeholder note).
    pub is_derived: bool,
}

/// Metadata for the report's cover page.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    /// Title displayed on the cover page.
    pub title: String,
    /// Free-form subtitle (typically the generation date).
    pub subtitle: String,
    /// Optional short fingerprint of the master seed for cross-verification
    /// against the user's BIP-39 backup (e.g., first + last 4 words).
    pub seed_fingerprint: Option<String>,
    /// Optional label of the salt used (for auditability).
    pub salt_label: Option<String>,
}

/// Errors that can arise during PDF generation.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// QR encoding failed (e.g., payload too large for any QR version).
    #[error("QR encoding failed: {0}")]
    Qr(#[from] qrcode::types::QrError),
    /// PDF library failure.
    #[error("PDF generation failed: {0}")]
    Pdf(String),
}

/// Render a PDF report of the given entries to a byte vector.
pub fn build_report(meta: &ReportMeta, entries: &[ReportEntry]) -> Result<Vec<u8>, ReportError> {
    let (doc, page1, layer1) = PdfDocument::new(&meta.title, Mm(210.0), Mm(297.0), "cover");
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ReportError::Pdf(e.to_string()))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ReportError::Pdf(e.to_string()))?;
    let font_mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| ReportError::Pdf(e.to_string()))?;
    let font_mono_bold = doc
        .add_builtin_font(BuiltinFont::CourierBold)
        .map_err(|e| ReportError::Pdf(e.to_string()))?;

    render_cover(&doc, page1, layer1, meta, entries.len(), &font, &font_bold);

    let _ = &font_mono;
    for entry in entries {
        let (page, layer) = doc.add_page(Mm(210.0), Mm(297.0), "entry");
        render_entry(&doc, page, layer, entry, &font, &font_bold, &font_mono_bold)?;
    }

    let bytes = doc
        .save_to_bytes()
        .map_err(|e| ReportError::Pdf(e.to_string()))?;
    Ok(bytes)
}

fn render_cover(
    doc: &PdfDocumentReference,
    page: printpdf::PdfPageIndex,
    layer: printpdf::PdfLayerIndex,
    meta: &ReportMeta,
    entry_count: usize,
    font: &IndirectFontRef,
    font_bold: &IndirectFontRef,
) {
    let layer_ref = doc.get_page(page).get_layer(layer);
    let mut y = 250.0;

    layer_ref.use_text(&meta.title, 28.0, Mm(20.0), Mm(y), font_bold);
    y -= 15.0;
    layer_ref.use_text(&meta.subtitle, 14.0, Mm(20.0), Mm(y), font);
    y -= 25.0;

    layer_ref.use_text(
        format!("Entries in this report: {entry_count}"),
        11.0,
        Mm(20.0),
        Mm(y),
        font,
    );
    y -= 10.0;

    if let Some(salt) = &meta.salt_label {
        layer_ref.use_text(format!("HKDF salt: {salt}"), 11.0, Mm(20.0), Mm(y), font);
        y -= 10.0;
    }

    if let Some(fp) = &meta.seed_fingerprint {
        layer_ref.use_text(
            format!("Master seed fingerprint: {fp}"),
            11.0,
            Mm(20.0),
            Mm(y),
            font,
        );
        y -= 10.0;
    }

    y -= 20.0;

    let warnings = [
        "SECURITY NOTES",
        "",
        "* This document contains secrets. Handle it accordingly.",
        "* Never store this PDF on disk beyond the moment of printing.",
        "* Print on an offline printer; some printers cache jobs in memory.",
        "* Store printed copies in a physical safe or bank vault.",
        "* Shred paper copies you retire.",
        "* Do not photograph this document.",
        "",
        "RECOVERY",
        "",
        "Every derived passphrase in this report can be regenerated from your",
        "master seed by running hkdf-tree with the same inventory. This report",
        "is a convenience; the master seed on paper and metal is the",
        "authoritative backup.",
    ];
    for line in warnings {
        if line == "SECURITY NOTES" || line == "RECOVERY" {
            layer_ref.use_text(line, 12.0, Mm(20.0), Mm(y), font_bold);
        } else {
            layer_ref.use_text(line, 10.0, Mm(20.0), Mm(y), font);
        }
        y -= 6.0;
    }
}

#[allow(clippy::too_many_arguments)]
fn render_entry(
    doc: &PdfDocumentReference,
    page: printpdf::PdfPageIndex,
    layer: printpdf::PdfLayerIndex,
    entry: &ReportEntry,
    font: &IndirectFontRef,
    font_bold: &IndirectFontRef,
    font_mono_bold: &IndirectFontRef,
) -> Result<(), ReportError> {
    let layer_ref = doc.get_page(page).get_layer(layer);

    // Frame the card.
    let frame_x = 15.0;
    let frame_y_bottom = 15.0;
    let frame_width = 180.0;
    let frame_height = 267.0;
    draw_rect_outline(
        &layer_ref,
        frame_x,
        frame_y_bottom,
        frame_width,
        frame_height,
    );

    let mut y = frame_y_bottom + frame_height - 15.0;
    let left = frame_x + 8.0;

    // QR code (if derived) sits in the top-right corner; the title gets
    // the space to its left and wraps instead of running into it.
    let qr_size = 60.0;
    let qr_x = frame_x + frame_width - qr_size - 8.0;
    let qr_y = frame_y_bottom + frame_height - qr_size - 15.0;
    if entry.is_derived {
        draw_qr(&layer_ref, &entry.passphrase, qr_x, qr_y, qr_size)?;
        layer_ref.use_text(
            "Scan to enter into a password field.",
            8.0,
            Mm(qr_x),
            Mm(qr_y - 5.0),
            font,
        );
    }

    // Header: title only, left of the QR code. Helvetica-Bold 15pt runs
    // about 3mm per character; the column left of the QR is ~100mm wide.
    for line in wrap_text(&entry.title, 32) {
        layer_ref.use_text(line, 15.0, Mm(left), Mm(y), font_bold);
        y -= 7.0;
    }

    // All textual details start below both the title block and the QR
    // code (including its caption), across the full card width.
    if entry.is_derived {
        y = y.min(qr_y - 12.0);
    } else {
        y -= 4.0;
    }

    // Info-string.
    layer_ref.use_text("INFO-STRING", 8.0, Mm(left), Mm(y), font_bold);
    y -= 6.0;
    layer_ref.use_text(&entry.info_string, 12.0, Mm(left), Mm(y), font_mono_bold);
    y -= 10.0;

    // Encoding.
    layer_ref.use_text("ENCODING", 8.0, Mm(left), Mm(y), font_bold);
    y -= 5.0;
    layer_ref.use_text(&entry.encoding_desc, 10.0, Mm(left), Mm(y), font);
    y -= 10.0;

    // Passphrase (or placeholder).
    let phrase_header = if entry.is_derived {
        "PASSPHRASE"
    } else {
        "NOT DERIVED"
    };
    layer_ref.use_text(phrase_header, 8.0, Mm(left), Mm(y), font_bold);
    y -= 6.0;

    // Wrap long passphrases at a fixed column width; Courier at 12pt has
    // roughly 2.1mm per character.
    let phrase_font = if entry.is_derived {
        font_mono_bold
    } else {
        font
    };
    let phrase_size = if entry.is_derived { 12.0 } else { 10.0 };
    let max_line_len = 60;
    for line in wrap_text(&entry.passphrase, max_line_len) {
        layer_ref.use_text(line, phrase_size, Mm(left), Mm(y), phrase_font);
        y -= 6.0;
    }
    y -= 4.0;

    // Paper backup destinations.
    if !entry.paper_backup.is_empty() {
        layer_ref.use_text("PAPER BACKUP", 8.0, Mm(left), Mm(y), font_bold);
        y -= 5.0;
        layer_ref.use_text(entry.paper_backup.join(", "), 10.0, Mm(left), Mm(y), font);
        y -= 10.0;
    }

    // Notes.
    if let Some(notes) = &entry.notes {
        layer_ref.use_text("NOTES", 8.0, Mm(left), Mm(y), font_bold);
        y -= 5.0;
        for line in wrap_text(notes, 80) {
            layer_ref.use_text(line, 10.0, Mm(left), Mm(y), font);
            y -= 5.0;
        }
    }

    Ok(())
}

fn draw_rect_outline(layer: &printpdf::PdfLayerReference, x: f32, y: f32, w: f32, h: f32) {
    let outline_color = Rgb::new(0.3, 0.3, 0.3, None);
    layer.set_outline_color(printpdf::Color::Rgb(outline_color));
    layer.set_outline_thickness(0.3);
    layer.set_line_dash_pattern(LineDashPattern::default());

    let pts = vec![
        (Point::new(Mm(x), Mm(y)), false),
        (Point::new(Mm(x + w), Mm(y)), false),
        (Point::new(Mm(x + w), Mm(y + h)), false),
        (Point::new(Mm(x), Mm(y + h)), false),
    ];
    let line = Line {
        points: pts,
        is_closed: true,
    };
    layer.add_line(line);
}

fn draw_qr(
    layer: &printpdf::PdfLayerReference,
    payload: &str,
    x: f32,
    y: f32,
    size: f32,
) -> Result<(), ReportError> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)?;
    let width = code.width();
    let modules = code.to_colors();
    let module_size = size / width as f32;

    let black = Rgb::new(0.0, 0.0, 0.0, None);
    layer.set_fill_color(printpdf::Color::Rgb(black));

    for row in 0..width {
        for col in 0..width {
            let module = modules[row * width + col];
            if module == qrcode::Color::Dark {
                // PDF coordinates: origin at bottom-left, Y grows up.
                // QR (row, col): row grows down, col grows right.
                let mx = x + col as f32 * module_size;
                let my = y + size - (row + 1) as f32 * module_size;
                let ring = vec![
                    (Point::new(Mm(mx), Mm(my)), false),
                    (Point::new(Mm(mx + module_size), Mm(my)), false),
                    (
                        Point::new(Mm(mx + module_size), Mm(my + module_size)),
                        false,
                    ),
                    (Point::new(Mm(mx), Mm(my + module_size)), false),
                ];
                let poly = Polygon {
                    rings: vec![ring],
                    mode: PaintMode::Fill,
                    winding_order: WindingOrder::NonZero,
                };
                layer.add_polygon(poly);
            }
        }
    }
    Ok(())
}

/// Word-wrap `text` at `max_col` characters, preserving whitespace between
/// words. Long unsplittable tokens are emitted on their own oversized line.
fn wrap_text(text: &str, max_col: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_col {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> ReportMeta {
        ReportMeta {
            title: "Test Report".to_string(),
            subtitle: "2026-07-22".to_string(),
            seed_fingerprint: Some("abacus ... sunset".to_string()),
            salt_label: Some("test-hkdf-v1".to_string()),
        }
    }

    fn sample_entry() -> ReportEntry {
        ReportEntry {
            title: "geli slot 0 unlock".to_string(),
            info_string: "alice/laptop/fde-daily-v1".to_string(),
            encoding_desc: "diceware/eff_large/6".to_string(),
            passphrase: Zeroizing::new("correct horse battery staple foo bar".to_string()),
            paper_backup: vec!["home-safe".to_string(), "bank-vault".to_string()],
            notes: None,
            is_derived: true,
        }
    }

    #[test]
    fn builds_pdf_with_cover_and_one_entry() {
        let bytes =
            build_report(&sample_meta(), &[sample_entry()]).expect("PDF generation succeeds");
        // PDF documents begin with the magic bytes "%PDF".
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 1000, "PDF should have some content");
    }

    #[test]
    fn builds_pdf_with_multiple_entries_including_non_derived() {
        let entries = vec![
            sample_entry(),
            ReportEntry {
                title: "A deliberately long usage description that has to wrap \
                        across several lines instead of colliding with the QR code"
                    .to_string(),
                info_string: "alice/proton/2fa-recovery".to_string(),
                encoding_desc: "base64/32".to_string(),
                passphrase: Zeroizing::new(
                    "(service-generated — write recovery codes here)".to_string(),
                ),
                paper_backup: vec!["bank-vault".to_string()],
                notes: Some("Print codes from Proton's web UI".to_string()),
                is_derived: false,
            },
        ];
        let bytes = build_report(&sample_meta(), &entries).expect("PDF generation succeeds");
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[test]
    fn builds_pdf_with_no_entries() {
        let bytes = build_report(&sample_meta(), &[]).expect("empty report ok");
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[test]
    fn wrap_text_respects_column_width() {
        let text = "one two three four five six seven eight nine ten";
        let lines = wrap_text(text, 12);
        for line in &lines {
            assert!(line.len() <= 12, "line too long: {line:?}");
        }
    }

    #[test]
    fn wrap_text_handles_empty_string() {
        let lines = wrap_text("", 10);
        assert_eq!(lines, vec![String::new()]);
    }
}
