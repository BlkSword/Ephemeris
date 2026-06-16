//! Property-based tests for deniability guarantees.
//!
//! These tests use `proptest` to verify the core deniability claims
//! across a wide range of random inputs.
//!
//! Note: OTP functions are crate-internal; these tests use the high-level
//! `encrypt`/`decrypt`/`repudiate_eph` API.

use ephemeris_core::*;
use proptest::prelude::*;

proptest! {
    /// Property 1: Correctness — decrypt(encrypt(m, pw), pw) == m
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        password in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let params = Argon2Params::low_memory();
        let result = encrypt(&plaintext, &password, &params);
        let decrypted = decrypt(&result.eph_file, &password, &params).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property 2: Repudiation correctness —
    /// repudiate(encrypt(m_real, pw_real), m_fake, pw_fake) decrypts to m_fake
    /// under pw_fake. The fake message has the same length as the real one.
    #[test]
    fn repudiation_correctness(
        (real_msg, fake_msg) in (1usize..512).prop_flat_map(|len| {
            (prop::collection::vec(any::<u8>(), len..=len),
             prop::collection::vec(any::<u8>(), len..=len))
        }),
        real_pw in prop::collection::vec(any::<u8>(), 1..32),
        fake_pw in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(real_msg != fake_msg);

        let params = Argon2Params::low_memory();
        let result = encrypt(&real_msg, &real_pw, &params);

        let fake_eph = repudiate_eph(&result.eph_file, &fake_msg, &fake_pw, &params).unwrap();

        // Under fake password: should get fake message
        prop_assert_eq!(decrypt(&fake_eph, &fake_pw, &params).unwrap(), fake_msg);
    }

    /// Property 3: After repudiation, original password produces garbage ≠ real_msg.
    #[test]
    fn repudiation_destroys_original(
        (real_msg, fake_msg) in (1usize..512).prop_flat_map(|len| {
            (prop::collection::vec(any::<u8>(), len..=len),
             prop::collection::vec(any::<u8>(), len..=len))
        }),
        real_pw in prop::collection::vec(any::<u8>(), 1..32),
        fake_pw in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(real_msg != fake_msg);

        let params = Argon2Params::low_memory();
        let result = encrypt(&real_msg, &real_pw, &params);

        let fake_eph = repudiate_eph(&result.eph_file, &fake_msg, &fake_pw, &params).unwrap();

        // Under real password: should NOT get real message anymore
        prop_assert_ne!(decrypt(&fake_eph, &real_pw, &params).unwrap(), real_msg);
    }

    /// Property 4: Non-committing — unwrap_key never fails for any password.
    #[test]
    fn unwrap_always_succeeds(
        blob in prop::collection::vec(any::<u8>(), 0..256),
        password in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();

        let result = unwrap_key(&blob, &password, &salt, &params);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap().len(), blob.len());
    }

    /// Property 5: wrap/unwrap roundtrip for various key sizes.
    #[test]
    fn wrap_unwrap_roundtrip(
        key in prop::collection::vec(any::<u8>(), 0..512),
        password in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let params = Argon2Params::low_memory();
        let salt = generate_salt();

        let blob = wrap_key(&key, &password, &salt, &params).unwrap();
        let recovered = unwrap_key(&blob, &password, &salt, &params).unwrap();
        prop_assert_eq!(recovered, key);
    }

    /// Property 6: Different passwords produce different unwrapped keys
    /// (with overwhelming probability).
    #[test]
    fn different_passwords_produce_different_keys(
        key in prop::collection::vec(any::<u8>(), 32..256),
        pw1 in prop::collection::vec(any::<u8>(), 1..32),
        pw2 in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(pw1 != pw2);

        let params = Argon2Params::low_memory();
        let salt = generate_salt();

        let blob = wrap_key(&key, &pw1, &salt, &params).unwrap();
        let recovered1 = unwrap_key(&blob, &pw1, &salt, &params).unwrap();
        let recovered2 = unwrap_key(&blob, &pw2, &salt, &params).unwrap();

        prop_assert_eq!(&recovered1, &key);
        prop_assert_ne!(recovered2, key);
    }
}
