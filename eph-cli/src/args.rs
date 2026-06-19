//! Command-line argument definitions for the `eph` CLI.

use clap::{Parser, Subcommand, ValueHint};

/// Ephemeris — message-level deniable encryption tool.
///
/// Encrypt messages with information-theoretic security and
/// plausible deniability. Under duress, prove the ciphertext
/// decrypts to a harmless message.
///
/// Examples:
///   eph encrypt secret.txt secret.eph
///   eph encrypt secret.txt secret.eph --armor   # base64 output
///   eph decrypt secret.eph output.txt
///   eph repudiate secret.eph cover.eph fake.txt
///   eph genpass
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

    /// Decrypt a .eph file (or armored text)
    Decrypt(DecryptArgs),

    /// Repudiate: replace key — decrypts to harmless message under fake password
    Repudiate(RepudiateArgs),

    /// Show metadata about a .eph or .key file
    Info(InfoArgs),

    /// Generate a standalone .key file from a raw OTP key
    GenKey(GenKeyArgs),

    /// Generate a strong random password
    GenPass(GenPassArgs),
}

// ---------------------------------------------------------------------------
// Shared options
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub struct PasswordOptions {
    /// Password (visible in process list — use only for scripting)
    #[arg(short = 'p', long = "password", group = "pw-source")]
    pub password: Option<String>,

    /// Read password from file (first line only)
    #[arg(short = 'P', long = "password-file", group = "pw-source", value_hint = ValueHint::FilePath)]
    pub password_file: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct Argon2Options {
    /// Argon2id iterations [default: 2]
    #[arg(short = 't', long = "time-cost", default_value = "2")]
    pub time_cost: u32,

    /// Argon2id memory in KiB [default: 37888 (~37 MiB)]
    #[arg(short = 'm', long = "memory-cost", default_value = "37888")]
    pub memory_cost: u32,

    /// Argon2id parallelism (threads) [default: 1]
    #[arg(short = 'j', long = "parallelism", default_value = "1")]
    pub parallelism: u32,
}

// ---------------------------------------------------------------------------
// Subcommand args
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub struct EncryptArgs {
    /// Input file (plaintext). Use '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Output .eph file. Use '-' for stdout (implies --armor).
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    /// Also write a standalone .key file
    #[arg(long = "key-file", value_hint = ValueHint::FilePath)]
    pub key_file: Option<String>,

    /// Output in base64 armor format (for email/chat sharing)
    #[arg(short = 'a', long = "armor")]
    pub armor: bool,

    /// Securely erase input file after encryption
    #[arg(long = "shred")]
    pub shred: bool,

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
    /// Input .eph file (or armored text). Use '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Output file (plaintext). Use '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath)]
    pub output: String,

    /// Input is base64 armored format
    #[arg(short = 'a', long = "armor")]
    pub armor: bool,

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

    /// Output in base64 armor format
    #[arg(short = 'a', long = "armor")]
    pub armor: bool,

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
    /// Raw OTP key input. Use '-' for stdin (binary).
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

#[derive(Debug, clap::Args)]
pub struct GenPassArgs {
    /// Number of words (Diceware style) [default: 6]
    #[arg(short = 'n', long = "words", default_value = "6")]
    pub words: usize,

    /// Show estimated entropy
    #[arg(short = 'e', long = "entropy")]
    pub show_entropy: bool,
}
