//! Repudiation: generating fake (deniable) key material.
//!
//! The core insight: given a ciphertext C and a desired fake plaintext P_fake,
//! the fake OTP key is simply K_fake = C ⊕ P_fake. This works because OTP
//! encryption is C = P_real ⊕ K_real, and for any P_fake, there exists a
//! unique K_fake = C ⊕ P_fake such that C ⊕ K_fake = P_fake.
//!
//! The fake key is then wrapped with the fake password to produce a key blob
//! that is indistinguishable from a "real" key blob.

use crate::keywrap;
use crate::otp;
use crate::params::Argon2Params;

/// Generate a fake key blob for deniability.
///
/// Given the ciphertext and a desired fake plaintext (same length), this
/// computes `K_fake = ciphertext ⊕ fake_plaintext` and wraps it with
/// `fake_password`, producing a key blob.
///
/// After repudiation:
/// - `unwrap_key(fake_blob, fake_password) → K_fake` decrypts ciphertext to `fake_plaintext` ✓
/// - `unwrap_key(original_blob, original_password) → K_real` decrypts to garbage
/// - The attacker cannot distinguish the fake blob from the real one
///
/// # Panics
///
/// Panics if `ciphertext.len() != fake_plaintext.len()`.
///
/// # Note
///
/// This function does NOT require the real password. This is intentional:
/// during a coercion scenario, the user should not need to type the real
/// password (which might be keylogged).
pub fn repudiate(
    ciphertext: &[u8],
    fake_plaintext: &[u8],
    fake_password: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Vec<u8>, argon2::Error> {
    assert_eq!(
        ciphertext.len(),
        fake_plaintext.len(),
        "ciphertext and fake_plaintext must have equal length: {} != {}",
        ciphertext.len(),
        fake_plaintext.len()
    );

    // K_fake = C ⊕ P_fake, computed in place to avoid an extra allocation.
    // The buffer is then wrapped in place, so the raw fake key never persists
    // beyond this function call.
    let mut fake_key = ciphertext.to_vec();
    otp::xor_in_place(&mut fake_key, fake_plaintext);

    keywrap::wrap_key_inplace(&mut fake_key, fake_password, salt, params)?;
    Ok(fake_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decrypt, encrypt};

    #[test]
    fn repudiate_then_fake_password_works() {
        let params = Argon2Params::low_memory();
        // 40-byte messages: real and fake have same length by design
        let real_msg = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH";
        let fake_msg = b"0000011111222223333344444555556666677777";
        assert_eq!(real_msg.len(), fake_msg.len());
        let real_pw = b"real-secret-password";
        let fake_pw = b"my-diary-password-123";

        let enc = encrypt(real_msg, real_pw, &params);

        // The fake key blob should decrypt ciphertext to fake_msg
        let fake_blob = repudiate(
            &enc.eph_file[25 + real_msg.len()..], // ciphertext portion
            fake_msg,
            fake_pw,
            &enc.salt,
            &params,
        )
        .unwrap();

        // Build a new .eph with the fake blob
        let mut fake_eph = enc.eph_file.clone();
        let key_start = 25;
        let key_end = 25 + real_msg.len();
        fake_eph.splice(key_start..key_end, fake_blob);

        // Decrypt with fake password → fake message
        let decrypted = decrypt(&fake_eph, fake_pw, &params).unwrap();
        assert_eq!(decrypted, fake_msg);
    }

    #[test]
    fn repudiate_destroys_real_message() {
        let params = Argon2Params::low_memory();
        // 40-byte messages, equal length
        let real_msg = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH";
        let fake_msg = b"0000011111222223333344444555556666677777";
        assert_eq!(real_msg.len(), fake_msg.len());
        let real_pw = b"real-secret-password";
        let fake_pw = b"my-diary-password-123";

        let enc = encrypt(real_msg, real_pw, &params);

        let fake_blob = repudiate(
            &enc.eph_file[25 + real_msg.len()..],
            fake_msg,
            fake_pw,
            &enc.salt,
            &params,
        )
        .unwrap();

        // Replace key blob in .eph
        let mut fake_eph = enc.eph_file.clone();
        let key_start = 25;
        let key_end = 25 + real_msg.len();
        fake_eph.splice(key_start..key_end, fake_blob);

        // Real password now produces garbage (≠ real_msg)
        let decrypted_with_real = decrypt(&fake_eph, real_pw, &params).unwrap();
        assert_ne!(decrypted_with_real, real_msg);
    }

    #[test]
    fn repudiate_without_real_password() {
        let params = Argon2Params::low_memory();
        // 20-byte messages, equal length
        let real_msg = b"AAAAABBBBBCCCCCDDDDD";
        let fake_msg = b"00000111112222233333";
        assert_eq!(real_msg.len(), fake_msg.len());
        let real_pw = b"top-secret-real-pw";
        let fake_pw = b"public-fake-pw";

        let enc = encrypt(real_msg, real_pw, &params);

        // repudiate() doesn't need real_pw at all
        let fake_blob = repudiate(
            &enc.eph_file[25 + real_msg.len()..],
            fake_msg,
            fake_pw,
            &enc.salt,
            &params,
        )
        .unwrap();

        assert_eq!(fake_blob.len(), fake_msg.len());
    }

    #[test]
    fn repudiate_empty_message() {
        let params = Argon2Params::low_memory();
        let enc = encrypt(b"", b"pw", &params);

        let fake_blob = repudiate(&[], b"", b"any-pw", &enc.salt, &params).unwrap();
        assert!(fake_blob.is_empty());
    }

    #[test]
    #[should_panic(expected = "must have equal length")]
    fn mismatched_lengths_panic() {
        let params = Argon2Params::low_memory();
        let salt = crate::keywrap::generate_salt();
        repudiate(&[1, 2, 3], &[1, 2], b"pw", &salt, &params).unwrap();
    }
}
