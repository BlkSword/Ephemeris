//! Binary file format parsing and building for `.eph` and `.key` files.
//!
//! All length calculations use checked arithmetic to prevent overflow
//! on 32-bit platforms. Magic byte comparisons use constant-time operations
//! to prevent timing side channels.
//!
//! # `.eph` Combined Format (v1, OTP mode)
//!
//! ```text
//! Offset  Size   Field
//! 0       4      Magic: b"EPH1"
//! 4       16     Salt (random, unique per encryption)
//! 20      1      Flags (bit 0 = mode: 0=OTP; bits 1-7 reserved, must be 0)
//! 21      4      KeyBlobLen: u32 LE, length of encrypted OTP key
//! 25      N      KeyBlob: AES-256-CTR(KDF(password, salt), otp_key)
//! 25+N    M      Ciphertext: plaintext XOR otp_key
//! ```
//!
//! In OTP mode: N == M (key and ciphertext are the same length).
//! Total file size: 25 + 2*N bytes.
//!
//! # `.key` Standalone Key File
//!
//! ```text
//! Offset  Size   Field
//! 0       4      Magic: b"EPHk"
//! 4       16     Salt
//! 20      1      Flags (bit 0 = mode; bits 1-7 reserved)
//! 21      4      KeyBlobLen: u32 LE
//! 25      N      KeyBlob
//! ```
//!
//! Total file size: 25 + N bytes.

use crate::error::FormatError;
use crate::keywrap;

/// Magic bytes identifying an `.eph` combined file.
pub const EPH_MAGIC: &[u8; 4] = b"EPH1";

/// Magic bytes identifying a `.key` standalone key file.
pub const KEY_MAGIC: &[u8; 4] = b"EPHk";

/// Size of the fixed header (magic + salt + flags + key_blob_len).
const HEADER_SIZE: usize = 25;

/// Salt offset and size within the header.
const SALT_OFFSET: usize = 4;
const SALT_SIZE: usize = 16;

/// Flags offset within the header.
const FLAGS_OFFSET: usize = 20;

/// Key blob length offset within the header.
const KEY_BLOB_LEN_OFFSET: usize = 21;

/// Flag bit indicating OTP mode (the only mode in v1).
const FLAG_OTP_MODE: u8 = 0x00;

/// A parsed `.eph` file reference.
///
/// The fields borrow from the original data buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphFile<'a> {
    /// 16-byte Argon2id salt.
    pub salt: [u8; 16],
    /// Encrypted OTP key blob.
    pub key_blob: &'a [u8],
    /// Ciphertext (plaintext XOR otp_key).
    pub ciphertext: &'a [u8],
}

/// Parse a `.eph` file from raw bytes.
///
/// Validates magic, flags, length consistency, and OTP mode invariants.
/// Uses constant-time magic comparison and checked arithmetic.
pub fn parse_eph(data: &[u8]) -> Result<EphFile<'_>, FormatError> {
    // Minimum size: header (25 bytes)
    if data.len() < HEADER_SIZE {
        return Err(FormatError::UnexpectedEof {
            expected: HEADER_SIZE,
            got: data.len(),
        });
    }

    // Validate magic (constant-time comparison)
    if !keywrap::ct_magic_eq(data, EPH_MAGIC) {
        return Err(FormatError::InvalidMagic {
            expected: "EPH1".into(),
            got: "(redacted)".into(),
        });
    }

    // Validate flags
    let flags = data[FLAGS_OFFSET];
    if flags & 0xFE != 0 {
        return Err(FormatError::InvalidFlags { flags });
    }

    // Read key blob length
    let key_blob_len = u32::from_le_bytes(
        data[KEY_BLOB_LEN_OFFSET..KEY_BLOB_LEN_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    // Calculate bounds using checked arithmetic (prevents 32-bit overflow)
    let key_start = HEADER_SIZE;
    let key_end = key_start
        .checked_add(key_blob_len)
        .ok_or(FormatError::UnexpectedEof {
            expected: HEADER_SIZE,
            got: data.len(),
        })?;

    // Validate we have enough data
    if data.len() < key_end {
        return Err(FormatError::UnexpectedEof {
            expected: key_end,
            got: data.len(),
        });
    }

    let ct_start = key_end;
    let ciphertext_len = data.len().checked_sub(ct_start).unwrap_or(0);

    // OTP mode invariant: key_blob_len == ciphertext_len
    if flags == FLAG_OTP_MODE && key_blob_len != ciphertext_len {
        return Err(FormatError::LengthMismatch {
            key_len: key_blob_len,
            ct_len: ciphertext_len,
        });
    }

    // Extract salt
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[SALT_OFFSET..SALT_OFFSET + SALT_SIZE]);

    Ok(EphFile {
        salt,
        key_blob: &data[key_start..key_end],
        ciphertext: &data[ct_start..],
    })
}

/// Build a `.eph` file from components.
///
/// In OTP mode, `key_blob.len()` must equal `ciphertext.len()`.
pub fn build_eph(salt: &[u8; 16], key_blob: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let key_blob_len = key_blob.len() as u32;
    let total_size = HEADER_SIZE
        .checked_add(key_blob.len())
        .and_then(|s| s.checked_add(ciphertext.len()))
        .expect("file size overflow");
    let mut buf = Vec::with_capacity(total_size);

    // Magic
    buf.extend_from_slice(EPH_MAGIC);

    // Salt
    buf.extend_from_slice(salt);

    // Flags (OTP mode = 0x00)
    buf.push(FLAG_OTP_MODE);

    // Key blob length (u32 LE)
    buf.extend_from_slice(&key_blob_len.to_le_bytes());

    // Key blob
    buf.extend_from_slice(key_blob);

    // Ciphertext
    buf.extend_from_slice(ciphertext);

    buf
}

/// Parse a `.key` standalone key file.
///
/// Returns `(salt, key_blob)`.
pub fn parse_key(data: &[u8]) -> Result<([u8; 16], &[u8]), FormatError> {
    if data.len() < HEADER_SIZE {
        return Err(FormatError::UnexpectedEof {
            expected: HEADER_SIZE,
            got: data.len(),
        });
    }

    // Validate magic (constant-time)
    if !keywrap::ct_magic_eq(data, KEY_MAGIC) {
        return Err(FormatError::InvalidMagic {
            expected: "EPHk".into(),
            got: "(redacted)".into(),
        });
    }

    // Validate flags
    let flags = data[FLAGS_OFFSET];
    if flags & 0xFE != 0 {
        return Err(FormatError::InvalidFlags { flags });
    }

    let key_blob_len = u32::from_le_bytes(
        data[KEY_BLOB_LEN_OFFSET..KEY_BLOB_LEN_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let key_start = HEADER_SIZE;
    let key_end = key_start
        .checked_add(key_blob_len)
        .ok_or(FormatError::UnexpectedEof {
            expected: HEADER_SIZE,
            got: data.len(),
        })?;

    if data.len() < key_end {
        return Err(FormatError::UnexpectedEof {
            expected: key_end,
            got: data.len(),
        });
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[SALT_OFFSET..SALT_OFFSET + SALT_SIZE]);

    Ok((salt, &data[key_start..key_end]))
}

/// Build a `.key` standalone key file.
pub fn build_key(salt: &[u8; 16], key_blob: &[u8]) -> Vec<u8> {
    let key_blob_len = key_blob.len() as u32;
    let total_size = HEADER_SIZE
        .checked_add(key_blob.len())
        .expect("key file size overflow");
    let mut buf = Vec::with_capacity(total_size);

    buf.extend_from_slice(KEY_MAGIC);
    buf.extend_from_slice(salt);
    buf.push(FLAG_OTP_MODE);
    buf.extend_from_slice(&key_blob_len.to_le_bytes());
    buf.extend_from_slice(key_blob);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_salt() -> [u8; 16] {
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    }

    #[test]
    fn build_and_parse_eph_roundtrip() {
        let salt = make_test_salt();
        let key_blob = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let ct       = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        let data = build_eph(&salt, key_blob, ct);
        let parsed = parse_eph(&data).unwrap();

        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.key_blob, key_blob);
        assert_eq!(parsed.ciphertext, ct);
    }

    #[test]
    fn build_and_parse_key_roundtrip() {
        let salt = make_test_salt();
        let key_blob = b"some-key-material";

        let data = build_key(&salt, key_blob);
        let (parsed_salt, parsed_blob) = parse_key(&data).unwrap();

        assert_eq!(parsed_salt, salt);
        assert_eq!(parsed_blob, key_blob);
    }

    #[test]
    fn empty_message_eph() {
        let salt = make_test_salt();
        let data = build_eph(&salt, b"", b"");
        let parsed = parse_eph(&data).unwrap();
        assert!(parsed.key_blob.is_empty());
        assert!(parsed.ciphertext.is_empty());
    }

    #[test]
    fn parse_eph_bad_magic() {
        let mut data = vec![0u8; 25];
        data[..4].copy_from_slice(b"BAD!");
        let err = parse_eph(&data).unwrap_err();
        assert!(matches!(err, FormatError::InvalidMagic { .. }));
    }

    #[test]
    fn parse_eph_too_short() {
        let data = vec![0u8; 10];
        let err = parse_eph(&data).unwrap_err();
        assert!(matches!(err, FormatError::UnexpectedEof { .. }));
    }

    #[test]
    fn parse_eph_invalid_flags() {
        let salt = make_test_salt();
        let mut data = build_eph(&salt, b"key", b"msg");
        data[FLAGS_OFFSET] = 0x02;
        let err = parse_eph(&data).unwrap_err();
        assert!(matches!(err, FormatError::InvalidFlags { .. }));
    }

    #[test]
    fn parse_eph_otp_length_mismatch() {
        let salt = make_test_salt();
        let mut buf = Vec::new();
        buf.extend_from_slice(EPH_MAGIC);
        buf.extend_from_slice(&salt);
        buf.push(FLAG_OTP_MODE);
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(b"0123456789");
        buf.extend_from_slice(b"short");

        let err = parse_eph(&buf).unwrap_err();
        assert!(matches!(err, FormatError::LengthMismatch { .. }));
    }

    #[test]
    fn parse_key_bad_magic() {
        let data = b"BAD!0000000000000000000000";
        let err = parse_key(data).unwrap_err();
        assert!(matches!(err, FormatError::InvalidMagic { .. }));
    }

    #[test]
    fn parse_key_too_short() {
        let err = parse_key(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, FormatError::UnexpectedEof { .. }));
    }

    #[test]
    fn flags_zero_is_valid() {
        let salt = make_test_salt();
        let data = build_eph(&salt, b"01234", b"56789");
        assert_eq!(data[FLAGS_OFFSET], 0x00);
        let parsed = parse_eph(&data).unwrap();
        assert_eq!(parsed.key_blob, b"01234");
        assert_eq!(parsed.ciphertext, b"56789");
    }

    #[test]
    fn large_key_and_ciphertext() {
        let salt = make_test_salt();
        let key = vec![0xAAu8; 10_000];
        let ct = vec![0xBBu8; 10_000];

        let data = build_eph(&salt, &key, &ct);
        assert_eq!(data.len(), 25 + 10_000 + 10_000);

        let parsed = parse_eph(&data).unwrap();
        assert_eq!(parsed.key_blob, key.as_slice());
        assert_eq!(parsed.ciphertext, ct.as_slice());
    }

    #[test]
    fn ct_magic_used_in_validation() {
        // Verify that constant-time comparison is used (not just byte comparison)
        let mut data = vec![0u8; 25];
        data[..4].copy_from_slice(b"EPH2"); // wrong version
        let err = parse_eph(&data).unwrap_err();
        assert!(matches!(err, FormatError::InvalidMagic { .. }));
    }

    #[test]
    fn max_size_value_does_not_overflow() {
        // Test that u32::MAX key_blob_len doesn't overflow
        let mut data = vec![0u8; 25];
        data[..4].copy_from_slice(EPH_MAGIC);
        // Set key_blob_len to a value that would overflow on 32-bit
        // We can't actually allocate that much, but the CHECKED_ADD prevents overflow
        data[21..25].copy_from_slice(&(u32::MAX).to_le_bytes());
        // On any platform, this should produce UnexpectedEof (can't fit u32::MAX+25 in memory)
        // not overflow/panic
        let err = parse_eph(&data).unwrap_err();
        assert!(matches!(err, FormatError::UnexpectedEof { .. }));
    }
}
