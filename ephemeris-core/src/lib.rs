//! Ephemeris — Message-level deniable encryption.
//!
//! Ephemeris provides information-theoretic deniable encryption for messages.
//! It uses One-Time Pad (OTP) encryption combined with non-committing key
//! wrapping to enable plausible deniability: given a ciphertext, you can
//! "prove" it decrypts to a harmless message under a different password.
//!
//! # Security Properties
//!
//! - **Information-theoretic security**: OTP guarantees that for any
//!   ciphertext C and any plaintext P' of the same length, there exists
//!   a unique key K' = C ⊕ P' that decrypts C to P'. No algorithm can
//!   determine which key is "real" — because they're all equally valid.
//!
//! - **Non-committing key wrapping**: AES-256-CTR without authentication
//!   tags means every password produces a "valid" unwrap. A wrong password
//!   yields garbage plaintext, not an error. Attackers cannot distinguish
//!   correct from incorrect passwords by observing error states.
//!
//! - **Repudiation without real password**: The `repudiate` function
//!   generates fake key material without needing the real password,
//!   preventing keylogger exposure during coercion.
//!
//! # Threat Model Limitations
//!
//! See `docs/threat-model.md` for a complete discussion. Key limitations:
//!
//! - The fake plaintext must be semantically plausible
//! - Multiple interrogations with different fake plaintexts are detectable
//! - Ciphertext length reveals plaintext length
//! - Physical coercion (rubber-hose cryptanalysis) is out of scope
//! - Keyloggers, malware, and memory inspection are not protected against
//!
//! # Quick Start
//!
//! ```rust
//! use ephemeris_core::{encrypt, decrypt, repudiate_eph, Argon2Params};
//!
//! let params = Argon2Params::default();
//!
//! // Encrypt
//! let result = encrypt(b"Launch codes: ALPHA-42", b"secret-password", &params);
//!
//! // Decrypt
//! let plaintext = decrypt(&result.eph_file, b"secret-password", &params).unwrap();
//! assert_eq!(plaintext, b"Launch codes: ALPHA-42");
//!
//! // Repudiate — claim it was a diary entry (same length: 22 bytes)
//! let fake_eph = repudiate_eph(
//!     &result.eph_file,
//!     b"Dear diary: boring day",
//!     b"diary-password",
//!     &params,
//! ).unwrap();
//!
//! // Now fake_eph decrypts to the diary entry under "diary-password"
//! let fake_plaintext = decrypt(&fake_eph, b"diary-password", &params).unwrap();
//! assert_eq!(fake_plaintext, b"Dear diary: boring day");
//! ```

mod error;
mod format;
mod keywrap;
mod otp;
mod params;
mod repudiate;

pub use error::FormatError;
pub use format::{build_eph, build_key, parse_eph, parse_key, EphFile};
pub use keywrap::{generate_salt, unwrap_key, wrap_key};
pub use params::Argon2Params;
pub use repudiate::repudiate;

use zeroize::Zeroize;

/// Result of a high-level `encrypt` operation.
///
/// Contains the `.eph` file bytes and a separate `.key` file for
/// standalone key storage.
///
/// Note: `Clone` is intentionally NOT derived on this struct.
/// The `eph_file` and `key_file` contain wrapped key material.
/// If you need to duplicate the data, use explicit `.to_vec()` calls.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptResult {
    /// The `.eph` combined file bytes (header + key blob + ciphertext).
    pub eph_file: Vec<u8>,
    /// The `.key` standalone key file bytes (header + key blob only).
    /// Can be stored separately from the `.eph` file.
    pub key_file: Vec<u8>,
    /// The 16-byte salt used for this encryption.
    pub salt: [u8; 16],
}

/// Encrypt `plaintext` with `password`, producing a full `.eph` file
/// and a standalone `.key` file.
///
/// This is the main high-level encryption function. It:
/// 1. Generates a random salt
/// 2. Generates a random OTP key (same length as plaintext)
/// 3. XORs plaintext with key to produce ciphertext
/// 4. Wraps the OTP key with password via AES-256-CTR
/// 5. Zeroizes the OTP key from memory
/// 6. Assembles the `.eph` and `.key` files
///
/// # Example
///
/// ```rust
/// use ephemeris_core::{encrypt, Argon2Params};
///
/// let result = encrypt(b"secret message", b"password", &Argon2Params::low_memory());
/// // result.eph_file — the combined file
/// // result.key_file — standalone key, can be stored separately
/// ```
pub fn encrypt(plaintext: &[u8], password: &[u8], params: &Argon2Params) -> EncryptResult {
    let salt = generate_salt();

    // Layer 1: OTP encryption
    let (ciphertext, mut otp_key) = otp::otp_encrypt(plaintext);

    // Layer 2: Wrap OTP key with password-derived KEK
    let key_blob = wrap_key(&otp_key, password, &salt, params)
        .expect("Argon2id key derivation should not fail with valid params");

    // SECURITY: Zeroize OTP key immediately after wrapping
    otp_key.zeroize();

    // Layer 3: Assemble file formats
    let eph_file = build_eph(&salt, &key_blob, &ciphertext);
    let key_file = build_key(&salt, &key_blob);

    EncryptResult {
        eph_file,
        key_file,
        salt,
    }
}

/// Decrypt an `.eph` file using `password`.
///
/// **This function always returns bytes.** If the wrong password is provided,
/// the returned bytes will be garbage. There is no error to distinguish
/// correct from incorrect passwords — this is essential for deniability.
///
/// Returns `Err(FormatError)` only if the `.eph` data is malformed
/// (bad magic, truncated, invalid flags, length mismatch).
pub fn decrypt(
    eph_data: &[u8],
    password: &[u8],
    params: &Argon2Params,
) -> Result<Vec<u8>, FormatError> {
    let parsed = parse_eph(eph_data)?;

    // Unwrap the OTP key (always succeeds — wrong password → garbage key)
    let otp_key = unwrap_key(parsed.key_blob, password, &parsed.salt, params)
        .expect("Argon2id key derivation should not fail with valid params");

    // OTP decrypt in place, reusing the OTP key buffer as the plaintext buffer
    otp::otp_decrypt_in_place(parsed.ciphertext, otp_key).map_err(|_| FormatError::LengthMismatch {
        key_len: parsed.key_blob.len(),
        ct_len: parsed.ciphertext.len(),
    })
}

/// Repudiate an `.eph` file: replace the key blob so that decrypting with
/// `fake_password` yields `fake_plaintext`.
///
/// This produces a new `.eph` file that is indistinguishable in format
/// from the original. The original real plaintext is destroyed in the
/// returned file (the real password will decrypt to garbage).
///
/// **The original `.eph` file is NOT modified.** You receive a new `.eph`
/// that you should use to replace the original.
///
/// Returns `Err(FormatError)` if the `.eph` data is malformed.
/// Returns `Err` if `fake_plaintext.len() != original plaintext length`.
pub fn repudiate_eph(
    eph_data: &[u8],
    fake_plaintext: &[u8],
    fake_password: &[u8],
    params: &Argon2Params,
) -> Result<Vec<u8>, FormatError> {
    let parsed = parse_eph(eph_data)?;

    if fake_plaintext.len() != parsed.ciphertext.len() {
        return Err(FormatError::LengthMismatch {
            key_len: fake_plaintext.len(),
            ct_len: parsed.ciphertext.len(),
        });
    }

    let fake_blob = repudiate(
        parsed.ciphertext,
        fake_plaintext,
        fake_password,
        &parsed.salt,
        params,
    )
    .expect("Argon2id key derivation should not fail with valid params");

    // Build new .eph with the same salt and ciphertext, but fake key blob
    Ok(build_eph(&parsed.salt, &fake_blob, parsed.ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_roundtrip() {
        let params = Argon2Params::low_memory();
        let msg = b"Hello, deniable world!";
        let pw = b"my-password";

        let result = encrypt(msg, pw, &params);
        let decrypted = decrypt(&result.eph_file, pw, &params).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn decrypt_with_key_file() {
        let params = Argon2Params::low_memory();
        let result = encrypt(b"test", b"pw", &params);

        let eph = parse_eph(&result.eph_file).unwrap();
        let (key_salt, key_blob) = parse_key(&result.key_file).unwrap();

        assert_eq!(eph.salt, key_salt);
        assert_eq!(eph.key_blob, key_blob);
    }

    #[test]
    fn repudiate_full_flow() {
        let params = Argon2Params::low_memory();
        let real_msg = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGG";
        let fake_msg = b"00000111112222233333444445555566";
        let real_pw = b"secret-123";
        let fake_pw = b"harmless-456";

        let result = encrypt(real_msg, real_pw, &params);

        let fake_eph = repudiate_eph(&result.eph_file, fake_msg, fake_pw, &params).unwrap();

        assert_eq!(decrypt(&fake_eph, fake_pw, &params).unwrap(), fake_msg);
        assert_ne!(decrypt(&fake_eph, real_pw, &params).unwrap(), real_msg);
    }

    #[test]
    fn empty_message_full_flow() {
        let params = Argon2Params::low_memory();
        let result = encrypt(b"", b"pw", &params);
        assert_eq!(result.eph_file.len(), 25);
        assert_eq!(result.key_file.len(), 25);

        let decrypted = decrypt(&result.eph_file, b"pw", &params).unwrap();
        assert!(decrypted.is_empty());

        let fake_eph = repudiate_eph(&result.eph_file, b"", b"other", &params).unwrap();
        assert_eq!(decrypt(&fake_eph, b"other", &params).unwrap(), b"");
    }

    #[test]
    fn wrong_password_produces_different_output() {
        let params = Argon2Params::low_memory();
        let msg = b"sensitive data";
        let result = encrypt(msg, b"correct", &params);

        let wrong_output = decrypt(&result.eph_file, b"wrong", &params).unwrap();
        assert_ne!(wrong_output, msg);
    }

    #[test]
    fn same_password_different_salts() {
        let params = Argon2Params::low_memory();
        let msg = b"same message";

        let r1 = encrypt(msg, b"pw", &params);
        let r2 = encrypt(msg, b"pw", &params);

        assert_ne!(r1.salt, r2.salt);
        assert_ne!(r1.eph_file, r2.eph_file);

        assert_eq!(decrypt(&r1.eph_file, b"pw", &params).unwrap(), msg);
        assert_eq!(decrypt(&r2.eph_file, b"pw", &params).unwrap(), msg);
    }

    #[test]
    fn repudiate_preserves_file_size() {
        let params = Argon2Params::low_memory();
        let msg = vec![0u8; 100];
        let result = encrypt(&msg, b"pw", &params);

        let fake_eph = repudiate_eph(&result.eph_file, &msg, b"fake", &params).unwrap();
        assert_eq!(fake_eph.len(), result.eph_file.len());
    }

    #[test]
    fn unicode_passwords_and_messages() {
        let params = Argon2Params::low_memory();
        let msg = "机密消息 — secret message 🕵️".as_bytes();
        let pw = "密码 — password 🔑".as_bytes();

        let result = encrypt(msg, pw, &params);
        let decrypted = decrypt(&result.eph_file, pw, &params).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn decrypt_malformed_file_returns_err() {
        let result = decrypt(
            b"not an eph file at all",
            b"pw",
            &Argon2Params::low_memory(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn repudiate_length_mismatch_returns_err() {
        let params = Argon2Params::low_memory();
        let result = encrypt(b"12345", b"pw", &params);
        let r = repudiate_eph(&result.eph_file, b"1234", b"fake", &params);
        assert!(r.is_err());
    }
}
