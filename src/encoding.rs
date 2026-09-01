// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! Encoding of raw HKDF output bytes into user-visible secrets.
//!
//! Every encoding is a **deterministic pure function** of the input byte
//! slice plus encoding parameters. Given identical inputs, the same bytes
//! must always come out, forever — this invariant is what allows a user to
//! recover a passphrase months or years later from the master seed alone.
//!
//! # Uniform sampling and bias
//!
//! For alphabets whose size is not a power of two (Diceware 7776 words,
//! numeric 10 digits, alphanumeric 62 chars), a naive `byte % alphabet_size`
//! introduces modulo bias. This module uses **rejection sampling**: read the
//! smallest number of bits that covers the alphabet, reject samples that
//! fall outside the alphabet, and try again from the next bits.
//!
//! Consequence: the number of input bytes consumed to produce a passphrase
//! is variable (in practice small; the worst rejection rate is ~50%
//! for alphabets like 5 with 3-bit samples). Callers should provide a
//! sufficiently long input buffer — 128 bytes is more than enough for any
//! realistic passphrase length.
//!
//! # Determinism warning
//!
//! Every algorithmic detail in this module — bit ordering, sample size,
//! rejection rule, alphabet ordering — is part of the tool's public
//! contract. A change here changes every derived passphrase whose encoding
//! this module produced. Such a change requires a rotation of every
//! affected entry, driven by a `-v<N+1>` version bump in the inventory.

use base64::Engine;
use zeroize::Zeroizing;

/// Character set for [`encode_alphanumeric`] (lowercase, uppercase, digits;
/// 62 characters in a fixed order that must never change).
const ALPHANUMERIC_CHARSET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Errors returned by encoding functions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodeError {
    /// The input byte buffer was exhausted before the requested output was
    /// produced. Provide more HKDF output bytes.
    #[error("insufficient entropy in input buffer")]
    InsufficientEntropy,
    /// The requested wordlist size is not usable (0 or larger than 2^32).
    #[error("wordlist size {0} is out of range")]
    InvalidWordlistSize(usize),
    /// The requested numeric or alphanumeric length is zero.
    #[error("output length must be at least 1")]
    ZeroLength,
}

/// A bit-stream reader over a byte slice, MSB-first within each byte.
struct BitReader<'a> {
    bytes: &'a [u8],
    /// Bit position (0-indexed) counting from the MSB of `bytes[0]`.
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    /// Read `n` bits (`1 <= n <= 32`), MSB-first, and return them as a `u32`.
    /// Returns `None` if the stream is exhausted.
    fn read(&mut self, n: u32) -> Option<u32> {
        debug_assert!((1..=32).contains(&n));
        let end_bit = self.bit_pos + n as usize;
        if end_bit > self.bytes.len() * 8 {
            return None;
        }
        let mut out: u32 = 0;
        for _ in 0..n {
            let byte = self.bytes[self.bit_pos / 8];
            let bit_in_byte = 7 - (self.bit_pos % 8);
            let bit = (byte >> bit_in_byte) & 1;
            // `|` and `^` are interchangeable here (the shifted-in bit is
            // always 0), so no test can distinguish them -- an equivalent
            // mutant, kept as `|` because it states the intent: set the bit.
            out = (out << 1) | bit as u32;
            self.bit_pos += 1;
        }
        Some(out)
    }
}

/// Draw one uniform sample in the range `0..max` from `reader` using
/// rejection sampling. Returns `None` if the stream is exhausted before
/// a valid sample is produced.
fn sample_uniform(reader: &mut BitReader<'_>, max: u32) -> Option<u32> {
    assert!(max > 0);
    // Number of bits needed to represent max-1.
    let bits = 32 - (max - 1).leading_zeros();
    loop {
        let sample = reader.read(bits)?;
        if sample < max {
            return Some(sample);
        }
    }
}

/// Encode raw bytes as a Diceware-style passphrase of `word_count` words
/// drawn uniformly from `wordlist`.
///
/// Words in the output are separated by single ASCII spaces.
pub fn encode_diceware(
    bytes: &[u8],
    wordlist: &[&str],
    word_count: usize,
) -> Result<Zeroizing<String>, EncodeError> {
    if wordlist.is_empty() || wordlist.len() > u32::MAX as usize {
        return Err(EncodeError::InvalidWordlistSize(wordlist.len()));
    }
    if word_count == 0 {
        return Err(EncodeError::ZeroLength);
    }

    let mut reader = BitReader::new(bytes);
    // Preallocate the final size: a growing String reallocates, stranding
    // un-zeroized copies of the partial passphrase in freed heap memory.
    let max_word_len = wordlist.iter().map(|w| w.len()).max().unwrap_or(0);
    let mut out = Zeroizing::new(String::with_capacity(word_count * (max_word_len + 1)));
    for i in 0..word_count {
        let idx = sample_uniform(&mut reader, wordlist.len() as u32)
            .ok_or(EncodeError::InsufficientEntropy)?;
        if i > 0 {
            out.push(' ');
        }
        out.push_str(wordlist[idx as usize]);
    }
    Ok(out)
}

/// Encode raw bytes as a numeric PIN of `length` decimal digits.
pub fn encode_numeric(bytes: &[u8], length: usize) -> Result<Zeroizing<String>, EncodeError> {
    if length == 0 {
        return Err(EncodeError::ZeroLength);
    }
    let mut reader = BitReader::new(bytes);
    let mut out = Zeroizing::new(String::with_capacity(length));
    for _ in 0..length {
        let d = sample_uniform(&mut reader, 10).ok_or(EncodeError::InsufficientEntropy)?;
        out.push(char::from_digit(d, 10).unwrap());
    }
    Ok(out)
}

/// Encode raw bytes as an alphanumeric passphrase of `length` characters
/// drawn from `[A-Za-z0-9]`.
pub fn encode_alphanumeric(bytes: &[u8], length: usize) -> Result<Zeroizing<String>, EncodeError> {
    if length == 0 {
        return Err(EncodeError::ZeroLength);
    }
    let mut reader = BitReader::new(bytes);
    let mut out = Zeroizing::new(String::with_capacity(length));
    for _ in 0..length {
        let i = sample_uniform(&mut reader, ALPHANUMERIC_CHARSET.len() as u32)
            .ok_or(EncodeError::InsufficientEntropy)?;
        out.push(ALPHANUMERIC_CHARSET[i as usize] as char);
    }
    Ok(out)
}

/// Encode the first `byte_count` bytes as a standard (padded) base64 string.
///
/// This encoding does not use rejection sampling — every input byte
/// contributes uniformly to the output — and the input is consumed
/// deterministically front to back.
pub fn encode_base64(bytes: &[u8], byte_count: usize) -> Result<Zeroizing<String>, EncodeError> {
    if byte_count == 0 {
        return Err(EncodeError::ZeroLength);
    }
    if bytes.len() < byte_count {
        return Err(EncodeError::InsufficientEntropy);
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes[..byte_count]);
    Ok(Zeroizing::new(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny wordlist for deterministic tests. Not for real use.
    const TEST_WORDLIST: &[&str] = &[
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    ];

    /// Known-answer tests pin the DERIVED VALUE, not just its shape. The
    /// determinism contract in docs/architecture.md promises that bit
    /// ordering, sample size, rejection rule and alphabet order never
    /// change; a plausible-looking output is not enough to prove that.
    /// Mutation testing (cargo mutants) showed these operators could be
    /// altered without a single test failing, which is exactly what these
    /// vectors prevent.
    const KAT_BYTES: &[u8] = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];

    #[test]
    fn kat_bit_reader_mixed_widths() {
        let bytes = [0b1011_0010, 0b0100_1101];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read(3), Some(0b101));
        assert_eq!(r.read(5), Some(0b10010));
        assert_eq!(r.read(6), Some(0b010011));
        assert_eq!(r.read(2), Some(0b01));
        assert_eq!(r.read(1), None);
    }

    #[test]
    fn kat_sample_uniform_rejects_out_of_range() {
        let bytes = [0b1110_0000, 0b0000_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(sample_uniform(&mut r, 5), Some(0));
        assert_eq!(r.bit_pos, 6);
    }

    #[test]
    fn kat_sample_uniform_accepts_max_minus_one() {
        let bytes = [0b1000_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(sample_uniform(&mut r, 3), Some(2));
    }

    #[test]
    fn kat_diceware_exact_output() {
        let out = encode_diceware(KAT_BYTES, TEST_WORDLIST, 6).expect("encode");
        assert_eq!(
            out.as_str(),
            "alpha alpha alpha bravo alpha echo",
            "diceware output changed -- this breaks every derived passphrase"
        );
    }

    #[test]
    fn kat_alphanumeric_exact_output() {
        let out = encode_alphanumeric(KAT_BYTES, 16).expect("encode");
        assert_eq!(
            out.as_str(),
            "ABEiM0RVZneImaq7",
            "alphanumeric output changed -- this breaks every derived password"
        );
    }

    #[test]
    fn kat_numeric_exact_output() {
        let out = encode_numeric(KAT_BYTES, 12).expect("encode");
        assert_eq!(
            out.as_str(),
            "001122334455",
            "numeric output changed -- this breaks every derived PIN"
        );
    }

    /// The alphanumeric and base64 alphabets coincide for values 0..62 and
    /// both consume six bits MSB-first, so on input without a 62/63 group
    /// they produce the SAME string. What separates them is the rejection
    /// rule. These bytes force rejections, so this vector is the one that
    /// actually pins that rule down.
    #[test]
    fn kat_rejection_sampling_diverges_from_base64() {
        let all_ones = [0xff_u8; 32];
        assert!(
            matches!(
                encode_alphanumeric(&all_ones, 8),
                Err(EncodeError::InsufficientEntropy)
            ),
            "every 6-bit group of 0xff is 63, which must always be rejected: \
             an all-ones stream can never yield an alphanumeric character"
        );
        let b64 = encode_base64(&all_ones, 6).expect("encode");
        assert_eq!(b64.as_str(), "////////");

        let mixed = [
            0x0f_u8, 0xff, 0x0f, 0xff, 0x0f, 0xff, 0x0f, 0xff, 0x0f, 0xff, 0x0f, 0xff,
        ];
        let alnum = encode_alphanumeric(&mixed, 4).expect("encode");
        let b64_mixed = encode_base64(&mixed, 3).expect("encode");
        assert_eq!(
            alnum.as_str(),
            "D8Pw",
            "rejection sampling changed -- derived passwords would change"
        );
        assert_eq!(b64_mixed.as_str(), "D/8P");
        assert_ne!(alnum.as_str(), b64_mixed.as_str());
    }

    /// The alphabet has 62 entries, so a six-bit group of exactly 62 is the
    /// first value that must be REJECTED. Accepting it would index past the
    /// end of the charset. 0xf8 starts with 111110 = 62; the correct result
    /// skips it and takes the next group.
    #[test]
    fn kat_boundary_value_62_is_rejected() {
        let bytes = [0xf8_u8, 0x00];
        let out = encode_alphanumeric(&bytes, 1).expect("encode");
        assert_eq!(
            out.as_str(),
            "A",
            "the value 62 must be rejected, not accepted as an index"
        );
    }

    #[test]
    fn kat_base64_exact_output() {
        let out = encode_base64(KAT_BYTES, 12).expect("encode");
        assert_eq!(
            out.as_str(),
            "ABEiM0RVZneImaq7",
            "base64 output changed -- this breaks every derived blob"
        );
    }

    #[test]
    fn bit_reader_reads_msb_first() {
        // Byte 0b1010_1010 read as 4 bits gives 0b1010 = 10, then 0b1010 = 10.
        let bytes = [0b1010_1010];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read(4), Some(0b1010));
        assert_eq!(r.read(4), Some(0b1010));
        assert_eq!(r.read(1), None);
    }

    #[test]
    fn bit_reader_crosses_byte_boundary() {
        // Bytes 0xFF, 0x00 read as 12 bits (MSB first) = 0xFF0.
        let bytes = [0xFF, 0x00];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read(12), Some(0xFF0));
    }

    #[test]
    fn sample_uniform_never_returns_out_of_range() {
        // Deliberately varied bytes so rejection sampling has a mix to draw
        // from. `[0xFF; N]` would reject every 3-bit sample against max=7
        // and exhaust the buffer without producing a value.
        let bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37));
        let mut r = BitReader::new(&bytes);
        for _ in 0..10 {
            let s = sample_uniform(&mut r, 7).expect("should not exhaust");
            assert!(s < 7);
        }
    }

    #[test]
    fn diceware_is_deterministic() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let a = encode_diceware(&bytes, TEST_WORDLIST, 4).unwrap();
        let b = encode_diceware(&bytes, TEST_WORDLIST, 4).unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn diceware_produces_space_separated_words() {
        let bytes = [0x00, 0x00, 0x00, 0x00];
        let out = encode_diceware(&bytes, TEST_WORDLIST, 4).unwrap();
        let words: Vec<&str> = out.split(' ').collect();
        assert_eq!(words.len(), 4);
        for w in words {
            assert!(TEST_WORDLIST.contains(&w));
        }
    }

    #[test]
    fn diceware_all_zeros_gives_first_word_repeatedly() {
        // With 8-word list, sample_uniform reads 3 bits per word (2^3 = 8).
        // All-zero bytes produce sample 0 every time → "alpha alpha alpha".
        let bytes = [0x00; 4];
        let out = encode_diceware(&bytes, TEST_WORDLIST, 3).unwrap();
        assert_eq!(&*out, "alpha alpha alpha");
    }

    #[test]
    fn diceware_rejects_empty_wordlist() {
        let err = encode_diceware(&[0u8; 8], &[], 4).unwrap_err();
        assert_eq!(err, EncodeError::InvalidWordlistSize(0));
    }

    #[test]
    fn diceware_rejects_zero_length() {
        let err = encode_diceware(&[0u8; 8], TEST_WORDLIST, 0).unwrap_err();
        assert_eq!(err, EncodeError::ZeroLength);
    }

    #[test]
    fn diceware_returns_insufficient_entropy_when_buffer_short() {
        // 3 bits per word, 100 words = 300 bits = 38 bytes minimum.
        // Provide only 4 bytes.
        let err = encode_diceware(&[0xFF; 4], TEST_WORDLIST, 100).unwrap_err();
        assert_eq!(err, EncodeError::InsufficientEntropy);
    }

    #[test]
    fn numeric_produces_digits_only() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let out = encode_numeric(&bytes, 6).unwrap();
        assert_eq!(out.len(), 6);
        for c in out.chars() {
            assert!(c.is_ascii_digit(), "non-digit in {}", *out);
        }
    }

    #[test]
    fn numeric_is_deterministic() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let a = encode_numeric(&bytes, 6).unwrap();
        let b = encode_numeric(&bytes, 6).unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn alphanumeric_produces_only_charset_characters() {
        // Alphabet 62 takes 6 bits per sample with ~3% rejection.
        // 12 chars need well under 128 bits; a 32-byte buffer is safe.
        let bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37));
        let out = encode_alphanumeric(&bytes, 12).unwrap();
        assert_eq!(out.len(), 12);
        for c in out.chars() {
            assert!(c.is_ascii_alphanumeric(), "non-alphanumeric in {}", *out);
        }
    }

    #[test]
    fn alphanumeric_is_deterministic() {
        let bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(41));
        let a = encode_alphanumeric(&bytes, 16).unwrap();
        let b = encode_alphanumeric(&bytes, 16).unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn base64_matches_known_vector() {
        // "hello" → "aGVsbG8="
        let bytes = b"hello";
        let out = encode_base64(bytes, 5).unwrap();
        assert_eq!(&*out, "aGVsbG8=");
    }

    #[test]
    fn base64_rejects_short_buffer() {
        let err = encode_base64(&[0u8; 4], 10).unwrap_err();
        assert_eq!(err, EncodeError::InsufficientEntropy);
    }

    #[test]
    fn base64_takes_only_requested_bytes() {
        // First 3 bytes of b"abcdef" is b"abc" → "YWJj".
        let out = encode_base64(b"abcdef", 3).unwrap();
        assert_eq!(&*out, "YWJj");
    }
}
