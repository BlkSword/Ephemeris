//! One-Time Pad (OTP) encryption and decryption.
//!
//! Uses bitwise XOR with a cryptographically random key equal in length
//! to the plaintext. This provides information-theoretic security:
//! given a ciphertext C, for any plaintext P' of the same length, there
//! exists a key K' = C ⊕ P' that decrypts C to P'. No computational or
//! statistical test can distinguish the real key from any other key.
//!
//! The trade-off is that the key is as long as the message.
//!
//! ## Important: These functions are crate-internal
//!
//! Direct use of `otp_encrypt`/`otp_decrypt` is discouraged. The OTP key
//! is single-use — reusing it breaks information-theoretic security entirely
//! (C1 ⊕ C2 = P1 ⊕ P2). Use the high-level `encrypt`/`decrypt` functions
//! which handle key management and wrapping correctly.

use rand::RngCore;
use zeroize::Zeroize;

/// Encrypt `plaintext` using a randomly generated one-time pad key.
///
/// Returns `(ciphertext, otp_key)` where both are the same length as `plaintext`.
/// The key is generated from the OS cryptographic RNG.
///
/// ⚠ **The OTP key is single-use.** Never encrypt multiple messages with
/// the same key. Use the high-level `encrypt()` instead.
pub(crate) fn otp_encrypt(plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let len = plaintext.len();

    // Generate random OTP key from OS CSPRNG
    let mut key = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut key);

    // C = P ⊕ K
    let ciphertext: Vec<u8> = plaintext
        .iter()
        .zip(key.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    (ciphertext, key)
}

/// Decrypt `ciphertext` using the one-time pad `key`.
///
/// Returns the plaintext. The key must be exactly the same length as the
/// ciphertext.
///
/// Returns `Err` if lengths differ instead of panicking.
pub(crate) fn otp_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() != key.len() {
        return Err("ciphertext and key must have equal length");
    }

    // P = C ⊕ K
    Ok(ciphertext
        .iter()
        .zip(key.iter())
        .map(|(c, k)| c ^ k)
        .collect())
}

/// Zeroize an OTP key buffer after use.
///
/// Call this when you're done with the key to prevent
/// key material from persisting in freed heap memory.
#[allow(dead_code)]
pub(crate) fn zeroize_key(key: &mut Vec<u8>) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let plaintext = b"Hello, World!";
        let (ct, key) = otp_encrypt(plaintext);
        let decrypted = otp_decrypt(&ct, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_message() {
        let (ct, key) = otp_encrypt(b"");
        assert!(ct.is_empty());
        assert!(key.is_empty());
        let decrypted = otp_decrypt(&ct, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn single_byte() {
        for _ in 0..100 {
            let (ct, key) = otp_encrypt(&[42]);
            assert_eq!(ct.len(), 1);
            assert_eq!(key.len(), 1);
            assert_eq!(otp_decrypt(&ct, &key).unwrap(), [42]);
        }
    }

    #[test]
    fn large_message() {
        let plaintext = vec![0xAB; 1_000_000]; // 1 MB
        let (ct, key) = otp_encrypt(&plaintext);
        let decrypted = otp_decrypt(&ct, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let plaintext = vec![0x00; 1000];
        let (ct, _key) = otp_encrypt(&plaintext);
        assert_ne!(ct, plaintext);
    }

    #[test]
    fn different_keys_produce_different_ciphertexts() {
        let msg = b"same message";
        let (ct1, _k1) = otp_encrypt(msg);
        let (ct2, _k2) = otp_encrypt(msg);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn mismatched_lengths_returns_err() {
        let ct = vec![0u8; 10];
        let key = vec![0u8; 5];
        let result = otp_decrypt(&ct, &key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "ciphertext and key must have equal length");
    }

    #[test]
    fn null_bytes_preserved() {
        let msg = b"before\0after";
        let (ct, key) = otp_encrypt(msg);
        let decrypted = otp_decrypt(&ct, &key).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn unicode_utf8_roundtrip() {
        let msg = "こんにちは世界🌍".as_bytes();
        let (ct, key) = otp_encrypt(msg);
        let decrypted = otp_decrypt(&ct, &key).unwrap();
        assert_eq!(decrypted, msg);
        assert!(std::str::from_utf8(&decrypted).is_ok());
    }

    #[test]
    fn zeroize_clears_key() {
        let (_, mut key) = otp_encrypt(b"test message data here");
        assert!(!key.iter().all(|&b| b == 0));
        zeroize_key(&mut key);
        assert!(key.iter().all(|&b| b == 0));
    }
}
