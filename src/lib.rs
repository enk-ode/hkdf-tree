// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! Cryptographic core of `hkdf-tree`.
//!
//! This crate exposes a small, well-scoped API for deterministic key material
//! derivation using HKDF-SHA256 (RFC 5869). Higher-level concerns — inventory
//! management, encoding into passphrases, CLI, and reporting — are built on
//! top of the primitives defined here.
//!
//! # Security notes
//!
//! - HKDF security depends on the entropy of the input keying material (the
//!   master seed). The salt is a public parameter for domain separation and
//!   need not be secret.
//! - Derived material is returned wrapped in [`zeroize::Zeroizing`], which
//!   wipes the buffer on drop. Callers should avoid copying it into
//!   non-zeroing containers unless the derived value is not itself sensitive.
//! - The master seed passed in as `ikm` is **not** zeroed by this function —
//!   the caller owns and must manage that buffer's lifetime.

pub mod encoding;
pub mod inventory;
pub mod report;
pub mod wordlist;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Errors returned by [`derive_bytes`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeriveError {
    /// Requested output length exceeds HKDF-SHA256's maximum
    /// of 255 × 32 = 8160 bytes.
    #[error("output length {requested} bytes exceeds HKDF-SHA256 maximum of {max} bytes")]
    OutputTooLong {
        /// The number of bytes requested.
        requested: usize,
        /// The HKDF-SHA256 maximum output length (`255 * 32 = 8160`).
        max: usize,
    },
}

/// Maximum output length of HKDF-SHA256 in bytes (`255 * hash_output_size`).
pub const MAX_OUTPUT_LEN: usize = 255 * 32;

/// Derive `output_len` bytes of key material from the given inputs using
/// HKDF-SHA256 as defined in RFC 5869.
///
/// # Parameters
///
/// - `ikm`: input keying material (the master seed). Must contain sufficient
///   entropy; HKDF does not stretch weak inputs.
/// - `salt`: public domain-separation value. May be empty; when empty, HKDF
///   uses a string of zero bytes of the same length as the hash output.
/// - `info`: application-specific context binding. The primary way to obtain
///   distinct outputs from the same `ikm` and `salt`.
/// - `output_len`: number of bytes to derive. Must be at most
///   [`MAX_OUTPUT_LEN`].
///
/// # Returns
///
/// A `Zeroizing<Vec<u8>>` of exactly `output_len` bytes, or [`DeriveError`]
/// if `output_len > MAX_OUTPUT_LEN`.
///
/// # Determinism
///
/// For fixed `(ikm, salt, info, output_len)`, this function always returns
/// the same bytes. This property is verified against RFC 5869 Appendix A
/// test vectors.
pub fn derive_bytes(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, DeriveError> {
    if output_len > MAX_OUTPUT_LEN {
        return Err(DeriveError::OutputTooLong {
            requested: output_len,
            max: MAX_OUTPUT_LEN,
        });
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; output_len]);
    hk.expand(info, &mut okm)
        .expect("length check above guarantees expand cannot fail");
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("invalid hex in test vector")
    }

    // RFC 5869 Appendix A.1 — Basic test case with SHA-256.
    // https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
    #[test]
    fn rfc5869_a1_basic() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex("3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865");

        let okm = derive_bytes(&ikm, &salt, &info, 42).expect("derive succeeds");
        assert_eq!(&*okm, expected_okm.as_slice());
    }

    // RFC 5869 Appendix A.2 — Test with longer inputs/outputs.
    // https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2
    #[test]
    fn rfc5869_a2_long() {
        let ikm = hex("000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f");
        let salt = hex("606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let expected_okm = hex("b11e398dc80327a1c8e7f78c596a4934\
             4f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09\
             da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f\
             1d87");

        let okm = derive_bytes(&ikm, &salt, &info, 82).expect("derive succeeds");
        assert_eq!(&*okm, expected_okm.as_slice());
    }

    // RFC 5869 Appendix A.3 — Test with zero-length salt and info.
    // https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.3
    #[test]
    fn rfc5869_a3_empty_salt_and_info() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt: &[u8] = &[];
        let info: &[u8] = &[];
        let expected_okm = hex("8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8");

        let okm = derive_bytes(&ikm, salt, info, 42).expect("derive succeeds");
        assert_eq!(&*okm, expected_okm.as_slice());
    }

    #[test]
    fn output_too_long_is_rejected() {
        let ikm = [0u8; 32];
        let ok = derive_bytes(&ikm, &[], &[], MAX_OUTPUT_LEN).expect("max length must work");
        assert_eq!(
            ok.len(),
            8160,
            "MAX_OUTPUT_LEN is 255 * 32 -- HKDF cannot expand beyond 255 hash blocks"
        );
        let err = derive_bytes(&ikm, &[], &[], MAX_OUTPUT_LEN + 1).unwrap_err();
        assert_eq!(
            err,
            DeriveError::OutputTooLong {
                requested: MAX_OUTPUT_LEN + 1,
                max: MAX_OUTPUT_LEN,
            }
        );
    }

    #[test]
    fn max_output_len_is_accepted() {
        let ikm = [0u8; 32];
        let okm = derive_bytes(&ikm, &[], &[], MAX_OUTPUT_LEN).expect("boundary allowed");
        assert_eq!(okm.len(), MAX_OUTPUT_LEN);
    }

    #[test]
    fn same_inputs_produce_same_output() {
        let ikm = b"deterministic input";
        let salt = b"public-salt-v1";
        let info = b"alice/laptop/fde-daily-v1";
        let a = derive_bytes(ikm, salt, info, 64).unwrap();
        let b = derive_bytes(ikm, salt, info, 64).unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn different_info_produces_different_output() {
        let ikm = b"deterministic input";
        let salt = b"public-salt-v1";
        let a = derive_bytes(ikm, salt, b"alice/laptop/fde-daily-v1", 32).unwrap();
        let b = derive_bytes(ikm, salt, b"alice/laptop/fde-daily-v2", 32).unwrap();
        assert_ne!(&*a, &*b);
    }

    #[test]
    fn different_salt_produces_different_output() {
        let ikm = b"deterministic input";
        let info = b"alice/laptop/fde-daily-v1";
        let a = derive_bytes(ikm, b"salt-a-v1", info, 32).unwrap();
        let b = derive_bytes(ikm, b"salt-b-v1", info, 32).unwrap();
        assert_ne!(&*a, &*b);
    }
}
