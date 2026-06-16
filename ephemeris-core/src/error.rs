//! Error types for the Ephemeris deniable encryption library.
//!
//! Error messages intentionally redact file content to prevent
//! information leakage through logs or error channels.

use thiserror::Error;

/// Errors that can occur when parsing `.eph` or `.key` file formats.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    /// The file's magic bytes don't match the expected format identifier.
    /// The actual bytes found are NOT included to prevent information leakage.
    #[error("invalid magic bytes: expected \"{expected}\"")]
    InvalidMagic {
        /// The expected magic string (e.g. "EPH1" or "EPHk").
        expected: String,
        /// (Redacted) actual bytes found — excluded from Display for security.
        got: String,
    },

    /// The file is shorter than the minimum valid size or was truncated.
    /// File sizes are included as they are already observable from the filesystem.
    #[error("unexpected end of file: need {expected} bytes, got {got}")]
    UnexpectedEof {
        /// Minimum expected size in bytes.
        expected: usize,
        /// Actual size in bytes.
        got: usize,
    },

    /// The flags byte contains reserved bits set to 1 (future format).
    #[error("invalid flags byte: reserved bits must be zero")]
    InvalidFlags {
        /// The invalid flags byte value (redacted from Display).
        flags: u8,
    },

    /// In OTP mode, the key blob length must equal the ciphertext length.
    /// Lengths are already observable from the file size so they are included.
    #[error(
        "length mismatch in OTP mode: key_blob_len={key_len}, ciphertext_len={ct_len} (must be equal)"
    )]
    LengthMismatch {
        /// Length of the key blob in bytes.
        key_len: usize,
        /// Length of the ciphertext in bytes.
        ct_len: usize,
    },
}
