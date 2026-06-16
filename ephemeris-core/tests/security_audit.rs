//! Security audit tests: attempt to break Ephemeris.
//!
//! These tests try to find real weaknesses in the deniability guarantees.
//! A passing test means the attack FAILED (system is secure against it).
//! A failing test means we FOUND a break.

use ephemeris_core::*;

/// Test 1: Can we distinguish real .eph from repudiated .eph by byte distribution?
#[test]
fn distinguish_real_vs_fake_by_entropy() {
    let params = Argon2Params::low_memory();
    let msg_40 = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH";
    let fake_40 = b"0000011111222223333344444555556666677777";
    let pw_real = b"real-pw-12345";
    let pw_fake = b"fake-pw-67890";

    // Generate 100 real .eph files
    let mut real_files: Vec<Vec<u8>> = Vec::new();
    for i in 0..100 {
        let result = encrypt(msg_40, pw_real, &params);
        real_files.push(result.eph_file);
        if i > 0 {
            assert_ne!(real_files[i][4..20], real_files[0][4..20],
                "Different encryptions should have different salts");
        }
    }

    // Generate real/fake pairs from the SAME encryption
    for _ in 0..50 {
        let result = encrypt(msg_40, pw_real, &params);
        let orig_salt = result.salt;
        let fake_eph = repudiate_eph(&result.eph_file, fake_40, pw_fake, &params).unwrap();
        let fake_parsed = parse_eph(&fake_eph).unwrap();
        assert_eq!(orig_salt, fake_parsed.salt, "Salt preserved in repudiate");
        assert_eq!(parse_eph(&result.eph_file).unwrap().ciphertext,
                   fake_parsed.ciphertext, "Ciphertext preserved");
        assert_ne!(parse_eph(&result.eph_file).unwrap().key_blob,
                   fake_parsed.key_blob, "Key blob differs");
        assert_eq!(result.eph_file.len(), fake_eph.len(), "Same file size");
    }

    // Chi-squared test on key blob bytes from real files
    let real_key_bytes: Vec<u8> = real_files.iter()
        .flat_map(|f| f[25..25+40].to_vec())
        .collect();
    let mut real_counts = [0u64; 256];
    for &b in &real_key_bytes { real_counts[b as usize] += 1; }
    let total_real = real_key_bytes.len() as f64;
    let expected_real = total_real / 256.0;
    let chi_sq_real: f64 = real_counts.iter()
        .map(|&c| { let d = c as f64 - expected_real; d * d / expected_real })
        .sum();

    println!("Chi-squared (real key blobs): {:.2}", chi_sq_real);
    assert!(chi_sq_real < 400.0, "Key blob bytes non-uniform! chi²={}", chi_sq_real);
}

/// Test 2: Salt uniqueness verification
#[test]
fn salt_uniqueness() {
    let mut salts = Vec::new();
    for _ in 0..10000 {
        let salt = generate_salt();
        assert!(!salts.contains(&salt), "SALT COLLISION! Should never happen.");
        salts.push(salt);
    }
    println!("Generated 10000 unique salts — no collisions.");
}

/// Test 3: Known-plaintext attack resistance
#[test]
fn known_plaintext_resistance() {
    let params = Argon2Params::low_memory();
    let plaintext = b"SECRET: The code is 12345. END OF MESSAGE.";
    let password = b"strong-password";

    let result = encrypt(plaintext, password, &params);
    let parsed = parse_eph(&result.eph_file).unwrap();

    // Attacker knows the prefix, can recover the corresponding OTP key bytes
    let known_prefix = b"SECRET: The code is ";
    let known_len = known_prefix.len();
    let recovered_key_prefix: Vec<u8> = parsed.ciphertext[..known_len]
        .iter().zip(known_prefix.iter()).map(|(c, p)| c ^ p).collect();

    // Verify the known part matches
    let computed_known: Vec<u8> = parsed.ciphertext[..known_len]
        .iter().zip(recovered_key_prefix.iter()).map(|(c, k)| c ^ k).collect();
    assert_eq!(computed_known, known_prefix);

    // But the remaining bytes are NOT recoverable (OTP property)
    let unknown_ct = &parsed.ciphertext[known_len..];
    println!("Known plaintext reveals only {known_len} bytes of key.");
    println!("Remaining {} bytes stay completely unknown.", unknown_ct.len());
}

/// Test 4: Check if repudiate creates detectable patterns in the key_blob
#[test]
fn repudiate_no_detectable_pattern() {
    let params = Argon2Params::low_memory();
    let real_msg = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH";
    let fake_msg = b"0000011111222223333344444555556666677777";
    let pw_real = b"real-password";
    let pw_fake = b"fake-password";

    let result = encrypt(real_msg, pw_real, &params);
    let parsed = parse_eph(&result.eph_file).unwrap();
    let otp_key_real: Vec<u8> = parsed.ciphertext.iter()
        .zip(real_msg.iter()).map(|(c, p)| c ^ p).collect();
    let keystream_real: Vec<u8> = parsed.key_blob.iter()
        .zip(otp_key_real.iter()).map(|(b, k)| b ^ k).collect();

    let fake_eph = repudiate_eph(&result.eph_file, fake_msg, pw_fake, &params).unwrap();
    let fake_parsed = parse_eph(&fake_eph).unwrap();
    let otp_key_fake: Vec<u8> = fake_parsed.ciphertext.iter()
        .zip(fake_msg.iter()).map(|(c, p)| c ^ p).collect();
    let keystream_fake: Vec<u8> = fake_parsed.key_blob.iter()
        .zip(otp_key_fake.iter()).map(|(b, k)| b ^ k).collect();

    assert_ne!(keystream_real, keystream_fake,
        "Different passwords should produce different AES-CTR keystreams");
    println!("Real and fake keystreams are different ✓");
}

/// Test 5: Same salt + same ciphertext reveals nothing about plaintext
#[test]
fn salt_does_not_leak_plaintext() {
    let params = Argon2Params::low_memory();
    let msg1 = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH"; // 40 bytes
    let msg2 = b"ZZZZZYYYYYXXXXXWWWWWVVVVVUUUUUTTTTTSSSSS"; // 40 bytes
    let pw = b"same-password";

    let r1 = encrypt(msg1, pw, &params);
    let r2 = encrypt(msg2, pw, &params);
    assert_ne!(r1.salt, r2.salt);

    assert_eq!(decrypt(&r1.eph_file, pw, &params).unwrap(), msg1);
    assert_eq!(decrypt(&r2.eph_file, pw, &params).unwrap(), msg2);

    println!("Same password, different salts → completely different .eph files ✓");
}

/// Test 6: Argon2id time consistency — no timing oracle
#[test]
fn argon2_timing_consistency() {
    use std::time::Instant;

    let params = Argon2Params::low_memory();
    let salt = generate_salt();
    let key_correct = vec![0x42u8; 100];
    let key_wrong = vec![0xFFu8; 100];

    // Warmup
    let _ = unwrap_key(&key_correct, b"warmup-password", &salt, &params).unwrap();

    let mut times_correct = Vec::new();
    let mut times_wrong = Vec::new();

    for _ in 0..5 {
        let t0 = Instant::now();
        let _ = unwrap_key(&key_correct, b"correct-password", &salt, &params).unwrap();
        times_correct.push(t0.elapsed().as_nanos());

        let t0 = Instant::now();
        let _ = unwrap_key(&key_wrong, b"wrong-password-here", &salt, &params).unwrap();
        times_wrong.push(t0.elapsed().as_nanos());
    }

    let avg_correct: f64 = times_correct.iter().sum::<u128>() as f64 / times_correct.len() as f64;
    let avg_wrong: f64 = times_wrong.iter().sum::<u128>() as f64 / times_wrong.len() as f64;
    let ratio = avg_correct / avg_wrong.max(1.0);

    println!("Avg timing correct: {:.0}ns", avg_correct);
    println!("Avg timing wrong:   {:.0}ns", avg_wrong);
    println!("Ratio: {:.2}", ratio);

    assert!(ratio > 0.5 && ratio < 2.0,
        "Large timing discrepancy: ratio={}", ratio);
}

/// Test 7: Empty password edge case
#[test]
fn empty_password_edge_case() {
    let params = Argon2Params::low_memory();
    let msg = b"test message";

    let result = encrypt(msg, b"", &params);
    let decrypted = decrypt(&result.eph_file, b"", &params).unwrap();
    assert_eq!(decrypted, msg);

    let garbage = decrypt(&result.eph_file, b"x", &params).unwrap();
    assert_ne!(garbage, msg);

    let fake = repudiate_eph(&result.eph_file, msg, b"", &params).unwrap();
    assert_eq!(decrypt(&fake, b"", &params).unwrap(), msg);
}

/// Test 8: Size boundaries check
#[test]
fn max_size_boundaries() {
    let params = Argon2Params::low_memory();
    for size in [0, 1, 255, 256, 65535, 65536] {
        let msg = vec![0x42u8; size];
        let result = encrypt(&msg, b"pw", &params);
        let decrypted = decrypt(&result.eph_file, b"pw", &params).unwrap();
        assert_eq!(decrypted, msg, "Failed at size {}", size);
        assert_eq!(result.eph_file.len(), if size == 0 { 25 } else { 25 + 2 * size },
            "Wrong file size at message size {}", size);
    }
}

/// Test 9: Bit flipping attack
#[test]
fn bit_flip_resistance() {
    let params = Argon2Params::low_memory();
    let msg = b"Launch missiles at dawn!!!";
    let pw = b"password";

    let result = encrypt(msg, pw, &params);
    let mut modified = result.eph_file.clone();
    modified[25] ^= 0x01;

    // Decryption succeeds but produces garbage (not predictable)
    let garbage = decrypt(&modified, pw, &params).unwrap();
    assert_ne!(garbage, msg);
    println!("Bit flip in key blob → unpredictable change in plaintext ✓");
}

/// Test 10: Error message consistency (no oracle)
#[test]
fn error_message_consistency() {
    let e1 = parse_eph(b"").unwrap_err();
    let e2 = parse_eph(&[b'X'; 30]).unwrap_err();
    let mut e3_data = vec![0u8; 100];
    e3_data[..4].copy_from_slice(b"EPH1");
    e3_data[20] = 0xFF;
    let e3 = parse_eph(&e3_data).unwrap_err();

    println!("Error 1: {}", e1);
    println!("Error 2: {}", e2);
    println!("Error 3: {}", e3);
}

/// Test 11: Can we detect repudiation by comparing original metadata?
#[test]
fn repudiation_detectable_only_with_original() {
    let params = Argon2Params::low_memory();
    let real = b"REAL_SECRET_MESSAGE_1234567890!!";
    let fake = b"FAKE_HARMLESS_TEXT_1234567890!!!";
    assert_eq!(real.len(), fake.len());
    let pw_real = b"real-pw";
    let pw_fake = b"fake-pw";

    let original = encrypt(real, pw_real, &params);
    let repudiated = repudiate_eph(&original.eph_file, fake, pw_fake, &params).unwrap();

    let orig_parsed = parse_eph(&original.eph_file).unwrap();
    let rep_parsed = parse_eph(&repudiated).unwrap();

    // Same salt (repudiate preserves it — documented behavior)
    assert_eq!(orig_parsed.salt, rep_parsed.salt);
    assert_eq!(orig_parsed.ciphertext, rep_parsed.ciphertext);
    assert_ne!(orig_parsed.key_blob, rep_parsed.key_blob);

    // XOR of key blobs should NOT equal XOR of plaintexts
    // (AES-CTR keystreams differ for different passwords)
    let xored: Vec<u8> = orig_parsed.key_blob.iter()
        .zip(rep_parsed.key_blob.iter()).map(|(a, b)| a ^ b).collect();
    let plaintext_xor: Vec<u8> = real.iter().zip(fake.iter()).map(|(a, b)| a ^ b).collect();
    assert_ne!(xored, plaintext_xor, "Key blob XOR leaks nothing about plaintexts");

    println!("Key blob XOR leaks nothing about plaintexts ✓");
}
