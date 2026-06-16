//! Command-line argument definitions for the `eph` CLI using clap derive.

use clap::{Parser, Subcommand, ValueHint};

/// Ephemeris — message-level deniable encryption.
///
/// Encrypt messages with information-theoretic security and
/// plausible deniability. Under duress, you can prove the
/// ciphertext decrypts to a harmless message.
#[derive(Parser, Debug)]
#[command(name = "eph", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a file with deniable encryption
    Encrypt(EncryptArgs),

    /// Decrypt a .eph file
    Decrypt(DecryptArgs),

    /// Repudiate: replace the key so the file decrypts to a harmless message
    Repudiate(RepudiateArgs),

    /// Show metadata about a .eph or .key file
    Info(InfoArgs),

    /// Generate a standalone .key file from a raw OTP key
    GenKey(GenKeyArgs),
}

/// Shared options for all commands that accept a password.
#[derive(Debug, clap::Args)]
pub struct PasswordOptions {
    /// Password (visible in process list — use only for scripting)
    #[arg(short = 'p', long = "password", group = "pw-source")]
    pub password: Option<String>,

    /// Read password from file (first line only)
    #[arg(short = 'P', long = "password-file", group = "pw-source", value_hint = ValueHint::FilePath)]
    pub password_file: Option<String>,
}

/// Shared options for Argon2id parameters.
#[derive(Debug, clap::Args)]
pub struct Argon2Options {
    /// Argon2id time cost (iterations) [default: 2]
    #[arg(short = 't', long = "time-cost", default_value = "2")]
    pub time_cost: u32,

    /// Argon2id memory cost in KiB [default: 19456 (~19 MiB)]
    #[arg(short = 'm', long = "memory-cost", default_value = "19456")]
    pub memory_cost: u32,

    /// Argon2id parallelism (threads) [default: 1]
    #[arg(short = 'j', long = "parallelism", default_value = "1")]
    pub parallelism: u32,
}

#[derive(Debug, clap::Args)]
pub struct EncryptArgs {
    /// Input file (plaintext). Use '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Output .eph file
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    /// Also write a standalone .key file
    #[arg(long = "key-file", value_hint = ValueHint::FilePath)]
    pub key_file: Option<String>,

    #[command(flatten)]
    pub password: PasswordOptions,

    #[command(flatten)]
    pub argon2: Argon2Options,

    /// Overwrite output file if it exists
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct DecryptArgs {
    /// Input .eph file. Use '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Output file (plaintext). Use '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    #[command(flatten)]
    pub password: PasswordOptions,

    #[command(flatten)]
    pub argon2: Argon2Options,

    /// Overwrite output file if it exists
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct RepudiateArgs {
    /// Input .eph file
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Output .eph file (with replaced key)
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    /// Fake plaintext file. Use '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub fake_plaintext: String,

    #[command(flatten)]
    pub password: PasswordOptions,

    #[command(flatten)]
    pub argon2: Argon2Options,

    /// Overwrite output file if it exists
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct InfoArgs {
    /// .eph or .key file to inspect
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: String,
}

#[derive(Debug, clap::Args)]
pub struct GenKeyArgs {
    /// Raw OTP key (hex encoded). Use '-' for stdin (binary).
    #[arg(value_hint = ValueHint::FilePath)]
    pub key_input: String,

    /// Output .key file
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    #[command(flatten)]
    pub password: PasswordOptions,

    #[command(flatten)]
    pub argon2: Argon2Options,

    /// Overwrite output file if it exists
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}
