//! Ephemeris CLI — `eph` binary entry point.
//!
//! Provides encrypt, decrypt, repudiate, info, and genkey subcommands.
//!
//! Passwords are zeroized from memory after use via the `zeroize` crate.

mod args;

use anyhow::{bail, Context, Result};
use args::{Argon2Options, Command, PasswordOptions};
use clap::Parser;
use ephemeris_core::*;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroize;

fn main() -> Result<()> {
    let cli = args::Cli::parse();
    match cli.command {
        Command::Encrypt(a) => cmd_encrypt(a),
        Command::Decrypt(a) => cmd_decrypt(a),
        Command::Repudiate(a) => cmd_repudiate(a),
        Command::Info(a) => cmd_info(a),
        Command::GenKey(a) => cmd_genkey(a),
    }
    // Zeroize happens inside each command after password use
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a password from the user (prompt or file or argument).
fn read_password(opts: &PasswordOptions, prompt: &str) -> Result<Vec<u8>> {
    if let Some(ref pw) = opts.password {
        return Ok(pw.as_bytes().to_vec());
    }
    if let Some(ref path) = opts.password_file {
        let s = fs::read_to_string(path)
            .with_context(|| format!("failed to read password file: {path}"))?;
        return Ok(s.as_bytes().to_vec());
    }
    // Interactive prompt
    let pw = rpassword::prompt_password(prompt)?;
    Ok(pw.into_bytes())
}

/// Create Argon2Params from CLI options.
fn make_params(opts: &Argon2Options) -> Argon2Params {
    Argon2Params {
        time_cost: opts.time_cost,
        memory_cost: opts.memory_cost,
        parallelism: opts.parallelism,
    }
}

/// Read entire file (or stdin if "-") into a Vec<u8>.
fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read stdin")?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("failed to read input file: {path}"))
    }
}

/// Write bytes to file (or stdout if "-").
fn write_output(path: &str, data: &[u8], force: bool) -> Result<()> {
    if path == "-" {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(data).context("failed to write stdout")?;
        handle.flush().context("failed to flush stdout")?;
        return Ok(());
    }
    if !force && Path::new(path).exists() {
        bail!(
            "output file '{}' already exists. Use --force to overwrite.",
            path
        );
    }
    fs::write(path, data).with_context(|| format!("failed to write output: {path}"))
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_encrypt(a: args::EncryptArgs) -> Result<()> {
    let plaintext = read_input(&a.input)?;
    let mut password = read_password(&a.password, "Encryption password: ")?;
    let params = make_params(&a.argon2);

    let result = encrypt(&plaintext, &password, &params);

    // Zeroize password after use
    password.zeroize();

    write_output(&a.output, &result.eph_file, a.force)?;
    eprintln!(
        "Encrypted {} bytes → '{}' (.eph, {} bytes total)",
        plaintext.len(),
        a.output,
        result.eph_file.len()
    );

    if let Some(ref key_path) = a.key_file {
        write_output(key_path, &result.key_file, a.force)?;
        eprintln!("Key file written to '{}'", key_path);
    }

    Ok(())
}

fn cmd_decrypt(a: args::DecryptArgs) -> Result<()> {
    let eph_data = read_input(&a.input)?;
    let mut password = read_password(&a.password, "Decryption password: ")?;
    let params = make_params(&a.argon2);

    // Validate format first to give a clear error
    let _parsed = parse_eph(&eph_data).context("invalid .eph file")?;

    let plaintext = decrypt(&eph_data, &password, &params)
        .context("failed to decrypt .eph file")?;

    // Zeroize password after use
    password.zeroize();

    write_output(&a.output, &plaintext, a.force)?;
    eprintln!("Decrypted {} bytes → '{}'", plaintext.len(), a.output);

    Ok(())
}

fn cmd_repudiate(a: args::RepudiateArgs) -> Result<()> {
    let eph_data = read_input(&a.input)?;
    let fake_plaintext = read_input(&a.fake_plaintext)?;
    let mut password = read_password(&a.password, "Fake (cover story) password: ")?;
    let params = make_params(&a.argon2);

    // Validate the .eph file
    let parsed = parse_eph(&eph_data).context("invalid .eph file")?;

    if fake_plaintext.len() != parsed.ciphertext.len() {
        bail!(
            "fake plaintext length ({}) must equal original message length ({})",
            fake_plaintext.len(),
            parsed.ciphertext.len()
        );
    }

    let new_eph = repudiate_eph(&eph_data, &fake_plaintext, &password, &params)
        .context("failed to repudiate .eph file")?;

    // Zeroize password after use
    password.zeroize();

    write_output(&a.output, &new_eph, a.force)?;
    eprintln!(
        "Repudiated! '{}' will now decrypt to the fake message under the fake password.",
        a.output
    );
    eprintln!("⚠ The original message is now UNRECOVERABLE from this file.");

    Ok(())
}

fn cmd_info(a: args::InfoArgs) -> Result<()> {
    let data = read_input(&a.file)?;

    // Try .eph format first, then .key
    if let Ok(parsed) = parse_eph(&data) {
        println!("File type:     .eph (Ephemeris combined)");
        println!("File size:     {} bytes", data.len());
        println!("Mode:          OTP (one-time pad)");
        // Salt is shown for debugging; it's already in the file header (not secret)
        println!("Salt:          {}", hex::encode(parsed.salt));
        println!("Key blob len:  {} bytes", parsed.key_blob.len());
        println!("Ciphertext:    {} bytes", parsed.ciphertext.len());
        println!(
            "Overhead:      {} bytes (header + key blob)",
            25 + parsed.key_blob.len()
        );
        return Ok(());
    }

    if let Ok((salt, key_blob)) = parse_key(&data) {
        println!("File type:     .key (Ephemeris standalone key)");
        println!("File size:     {} bytes", data.len());
        println!("Mode:          OTP (one-time pad)");
        println!("Salt:          {}", hex::encode(salt));
        println!("Key blob len:  {} bytes", key_blob.len());
        return Ok(());
    }

    bail!("not a valid .eph or .key file (bad magic or corrupted)");
}

fn cmd_genkey(a: args::GenKeyArgs) -> Result<()> {
    let raw_key = read_input(&a.key_input)?;
    let mut password = read_password(&a.password, "Password for key file: ")?;
    let params = make_params(&a.argon2);

    if raw_key.is_empty() {
        eprintln!("Warning: key is empty. This will produce an empty .key file.");
    }

    let salt = generate_salt();
    let key_blob = wrap_key(&raw_key, &password, &salt, &params)
        .map_err(|e| anyhow::anyhow!("failed to wrap key: {e}"))?;

    // Zeroize password after use
    password.zeroize();

    let key_file = build_key(&salt, &key_blob);

    write_output(&a.output, &key_file, a.force)?;
    eprintln!(
        "Key file written to '{}' ({} bytes key, {} bytes total)",
        a.output,
        raw_key.len(),
        key_file.len()
    );

    Ok(())
}
