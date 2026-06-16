//! Non-committing key wrapping using AES-256-CTR.
//!
//! This is the core primitive that enables deniability. The design:
//!
//! 1. Derive a 48-byte KEK from (password, salt) via Argon2id
//!    - bytes 0..32 = AES-256 key
//!    - bytes 32..48 = CTR nonce (128-bit)
//!
//! 2. Encrypt/decrypt the OTP key using AES-256-CTR
//!
//! **Critically, there is NO authentication tag (no MAC, no GCM).**
//! This means `unwrap_key` always succeeds — given any password, it produces
//! *some* OTP key. If the password is wrong, the resulting key decrypts the
//! ciphertext to garbage. But an attacker cannot distinguish "wrong password
//! → garbage" from "wrong password → some other valid plaintext" by observing
//! errors, because there are no errors.
//!
//! If we used AES-GCM with an authentication tag, a wrong password would cause
//! a decryption failure. The attacker could simply try each password and observe
//! which one doesn't error — that's the real password. CTR without MAC closes
//! this side channel entirely.
//!
//! ## Nonce Derivation Note
//!
//! The CTR nonce is derived from the same Argon2id output as the AES key
//! (bytes 32..48 of the 48-byte output). This is mathematically sound because
//! Argon2id produces pseudorandom output, and the nonce is unique per encryption
//! due to the unique salt. The (key, nonce) pair's uniqueness depends on salt
//! uniqueness, which is guaranteed by OsRng (2^128 space). A conventional design
//! would generate an independent random nonce, but this would require storing
//! an additional 16 bytes in the file header. The current approach is secure
//! as long as salts are never reused.

use crate::params::Argon2Params;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Generate a 16-byte random salt from the OS CSPRNG.
///
/// Each encryption should use a unique salt to prevent key reuse.
pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Wrap (encrypt) an OTP key with a password-derived KEK.
///
/// The `key` is encrypted with AES-256-CTR using a key derived from
/// `password` and `salt` via Argon2id. The output has the same length
/// as `key`.
///
/// There is no authentication — the only way to know if unwrapping
/// succeeded is to try decrypting the ciphertext.
///
/// The derived KEK is zeroized before this function returns.
pub fn wrap_key(
    key: &[u8],
    password: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Vec<u8>, argon2::Error> {
    let mut derived = params.derive_key(password, salt)?;
    let aes_key: &[u8; 32] = derived[..32].try_into().unwrap();
    let nonce: &[u8; 16] = derived[32..48].try_into().unwrap();

    let mut cipher = Aes256Ctr::new(aes_key.into(), nonce.into());
    let mut blob = key.to_vec();
    cipher.apply_keystream(&mut blob);

    // Zeroize the derived KEK (contains AES key + nonce)
    derived.zeroize();

    Ok(blob)
}

/// Unwrap (decrypt) an OTP key using a password-derived KEK.
///
/// **This function always succeeds.** If the wrong password is provided,
/// the returned key will be garbage — but there is no way to know that
/// without also having the ciphertext and checking if the decrypted
/// plaintext is meaningful.
///
/// This non-committing behavior is the foundation of deniability.
///
/// The derived KEK is zeroized before this function returns.
pub fn unwrap_key(
    blob: &[u8],
    password: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Vec<u8>, argon2::Error> {
    let mut derived = params.derive_key(password, salt)?;
    let aes_key: &[u8; 32] = derived[..32].try_into().unwrap();
    let nonce: &[u8; 16] = derived[32..48].try_into().unwrap();

    let mut cipher = Aes256Ctr::new(aes_key.into(), nonce.into());
    let mut key = blob.to_vec();
    cipher.apply_keystream(&mut key);

    // Zeroize the derived KEK (contains AES key + nonce)
    derived.zeroize();

    Ok(key)
}

/// Constant-time comparison of magic bytes to prevent timing side channels.
pub(crate) fn ct_magic_eq(a: &[u8], expected: &[u8; 4]) -> bool {
    if a.len() < 4 {
        return false;
    }
    // Use subtle for constant-time comparison
    let a_slice: &[u8] = &a[..4];
    a_slice.ct_eq(expected.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_correct_password() {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();
        let otp_key = b"this is a 32-byte one-time pad key!".to_vec();
        let password = b"my-secret-password";

        let blob = wrap_key(&otp_key, password, &salt, &params).unwrap();
        let recovered = unwrap_key(&blob, password, &salt, &params).unwrap();
        assert_eq!(recovered, otp_key);
    }

    #[test]
    fn wrong_password_produces_different_key() {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();
        let otp_key = b"this is a 32-byte one-time pad key!".to_vec();

        let blob = wrap_key(&otp_key, b"correct", &salt, &params).unwrap();
        let recovered = unwrap_key(&blob, b"wrong", &salt, &params).unwrap();
        assert_ne!(recovered, otp_key);
    }

    #[test]
    fn different_salts_produce_different_blobs() {
        let params = Argon2Params::low_memory();
        let otp_key = b"same key material here for test!".to_vec();
        let password = b"password";

        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);

        let blob1 = wrap_key(&otp_key, password, &salt1, &params).unwrap();
        let blob2 = wrap_key(&otp_key, password, &salt2, &params).unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn empty_key() {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();
        let blob = wrap_key(b"", b"pw", &salt, &params).unwrap();
        assert!(blob.is_empty());
        let recovered = unwrap_key(&blob, b"pw", &salt, &params).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn unwrap_always_succeeds() {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();
        let blob = vec![0u8; 64];

        let passwords: &[&[u8]] = &[b"a", b"correct", b"", b"wrong-password-123"];
        for pw in passwords {
            let result = unwrap_key(&blob, pw, &salt, &params);
            assert!(result.is_ok(), "unwrap_key should never fail");
            assert_eq!(result.unwrap().len(), 64);
        }
    }

    #[test]
    fn key_blob_length_preserved() {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();

        for len in [0, 1, 16, 32, 100, 1024] {
            let key = vec![0x42u8; len];
            let blob = wrap_key(&key, b"pw", &salt, &params).unwrap();
            assert_eq!(blob.len(), len);
            let recovered = unwrap_key(&blob, b"pw", &salt, &params).unwrap();
            assert_eq!(recovered.len(), len);
        }
    }

    #[test]
    fn ct_magic_eq_correct() {
        assert!(ct_magic_eq(b"EPH1", b"EPH1"));
        assert!(ct_magic_eq(b"EPHk", b"EPHk"));
    }

    #[test]
    fn ct_magic_eq_incorrect() {
        assert!(!ct_magic_eq(b"BAD!", b"EPH1"));
        assert!(!ct_magic_eq(b"EPH1", b"EPHk"));
    }

    #[test]
    fn ct_magic_eq_too_short() {
        assert!(!ct_magic_eq(b"EP", b"EPH1"));
        assert!(!ct_magic_eq(b"", b"EPH1"));
    }
}
