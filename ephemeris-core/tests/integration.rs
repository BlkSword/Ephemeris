//! Integration tests for the full encryption/reputation lifecycle.

use ephemeris_core::*;

#[test]
fn complete_lifecycle() {
    let params = Argon2Params::low_memory();

    // 1. Encrypt a secret message (100 bytes)
    let secret = vec![0x42u8; 100];
    let pw = b"my-strong-password-2024";
    let result = encrypt(&secret, pw, &params);

    // 2. Normal decryption works
    let decrypted = decrypt(&result.eph_file, pw, &params).unwrap();
    assert_eq!(decrypted, secret);

    // 3. Can't tell if password is wrong by looking at errors
    let garbage = decrypt(&result.eph_file, b"wrong-password", &params).unwrap();
    assert_ne!(garbage, secret);
    assert_eq!(garbage.len(), secret.len());

    // 4. Repudiate: claim it was a harmless message (same length: 100 bytes)
    let poem = vec![0x99u8; 100];
    let poem_pw = b"poem-diary-2024";
    let fake_eph = repudiate_eph(&result.eph_file, &poem, poem_pw, &params).unwrap();

    // 5. Fake password decrypts to the poem
    let poem_decrypted = decrypt(&fake_eph, poem_pw, &params).unwrap();
    assert_eq!(poem_decrypted, poem);

    // 6. Original password now produces garbage
    let after_repudiation = decrypt(&fake_eph, pw, &params).unwrap();
    assert_ne!(after_repudiation, secret);
}

#[test]
fn file_format_consistency() {
    let params = Argon2Params::low_memory();
    let msg = b"test message for format consistency check";
    let pw = b"password";

    let result = encrypt(msg, pw, &params);

    let parsed = parse_eph(&result.eph_file).unwrap();

    assert_eq!(parsed.salt, result.salt);
    assert_eq!(parsed.ciphertext.len(), msg.len());
    assert_eq!(parsed.key_blob.len(), msg.len());

    // Verify we can extract and manually decrypt
    let otp_key = unwrap_key(parsed.key_blob, pw, &parsed.salt, &params).unwrap();
    // Manual XOR for verification
    let plaintext: Vec<u8> = parsed.ciphertext.iter()
        .zip(otp_key.iter())
        .map(|(c, k)| c ^ k)
        .collect();
    assert_eq!(plaintext, msg);
}

#[test]
fn key_file_standalone_usage() {
    let params = Argon2Params::low_memory();
    let msg = b"data encrypted with separate key storage";
    let pw = b"secure-password";

    let result = encrypt(msg, pw, &params);

    let (salt, key_blob) = parse_key(&result.key_file).unwrap();
    let parsed_eph = parse_eph(&result.eph_file).unwrap();
    assert_eq!(salt, parsed_eph.salt);
    assert_eq!(key_blob, parsed_eph.key_blob);

    // Verify independent decryption
    let otp_key = unwrap_key(key_blob, pw, &salt, &params).unwrap();
    let decrypted: Vec<u8> = parsed_eph.ciphertext.iter()
        .zip(otp_key.iter())
        .map(|(c, k)| c ^ k)
        .collect();
    assert_eq!(decrypted, msg);
}

#[test]
fn repudiate_multiple_times() {
    let params = Argon2Params::low_memory();
    let real = b"REAL SECRET DATA HERE!!!!!!";
    let pw_real = b"real-pw";

    let result = encrypt(real, pw_real, &params);

    // Repudiate to version 1 (must be same length: 27 bytes)
    let fake1_msg = b"harmless grocery list !!!!!";
    let fake1_pw = b"grocery-pw";
    let fake1 = repudiate_eph(&result.eph_file, fake1_msg, fake1_pw, &params).unwrap();
    assert_eq!(decrypt(&fake1, fake1_pw, &params).unwrap(), fake1_msg);

    // Repudiate again to version 2 (same length: 27 bytes)
    let fake2_msg = b"another boring note...!!!!!";
    let fake2_pw = b"boring-pw";
    let fake2 = repudiate_eph(&fake1, fake2_msg, fake2_pw, &params).unwrap();
    assert_eq!(decrypt(&fake2, fake2_pw, &params).unwrap(), fake2_msg);

    // None of the previous passwords work anymore
    assert_ne!(decrypt(&fake2, pw_real, &params).unwrap(), real);
    assert_ne!(decrypt(&fake2, fake1_pw, &params).unwrap(), fake1_msg);
}

#[test]
fn single_byte_messages() {
    let params = Argon2Params::low_memory();

    for byte in 0..=255u8 {
        let msg = [byte];
        let result = encrypt(&msg, b"pw", &params);
        assert_eq!(decrypt(&result.eph_file, b"pw", &params).unwrap(), msg);

        let fake_msg = [byte.wrapping_add(1)];
        let fake_eph = repudiate_eph(&result.eph_file, &fake_msg, b"fake", &params).unwrap();
        assert_eq!(decrypt(&fake_eph, b"fake", &params).unwrap(), fake_msg);
    }
}

#[test]
fn binary_data_roundtrip() {
    let params = Argon2Params::low_memory();

    let data: Vec<u8> = (0..=255).collect();
    let result = encrypt(&data, b"pw", &params);
    let decrypted = decrypt(&result.eph_file, b"pw", &params).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn argon2_default_params_work() {
    let params = Argon2Params::low_memory();
    let result = encrypt(b"test", b"password123", &params);
    let decrypted = decrypt(&result.eph_file, b"password123", &params).unwrap();
    assert_eq!(decrypted, b"test");
}

#[test]
fn decrypt_malformed_file_returns_err() {
    let result = decrypt(b"not an eph file at all!", b"pw", &Argon2Params::low_memory());
    assert!(result.is_err());
}

#[test]
fn repudiate_length_mismatch_returns_err() {
    let params = Argon2Params::low_memory();
    let result = encrypt(b"hello", b"pw", &params);
    let r = repudiate_eph(&result.eph_file, b"hey", b"fake", &params);
    assert!(r.is_err());
}
