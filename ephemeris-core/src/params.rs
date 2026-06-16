//! Argon2id parameters for key derivation.
//!
//! Default values follow OWASP 2024 recommendations:
//! - time_cost = 2 (iterations)
//! - memory_cost = 19456 KiB (~19 MiB)
//! - parallelism = 1 (threads)
//!
//! These can be adjusted: lower for tests, higher for production.

/// Configuration for the Argon2id key derivation function.
#[derive(Clone, Debug)]
pub struct Argon2Params {
    /// Number of iterations (time cost). OWASP recommends ≥ 2.
    pub time_cost: u32,
    /// Memory usage in kibibytes. OWASP recommends ≥ 19456 (19 MiB).
    pub memory_cost: u32,
    /// Degree of parallelism (threads). OWASP recommends 1.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    /// OWASP 2024 recommended minimum for Argon2id:
    /// memory_cost = 37888 KiB (~37 MiB), time_cost = 1, parallelism = 1.
    /// We use time_cost = 2 for a modest safety margin (~100ms on modern hardware).
    fn default() -> Self {
        Self {
            time_cost: 2,
            memory_cost: 37888, // ~37 MiB (OWASP 2024 minimum)
            parallelism: 1,
        }
    }
}

impl Argon2Params {
    /// Create parameters suitable for testing (low memory, fast).
    pub fn low_memory() -> Self {
        Self {
            time_cost: 1,
            memory_cost: 1024, // 1 MiB
            parallelism: 1,
        }
    }

    /// Create parameters for interactive use (100ms target).
    pub fn interactive() -> Self {
        Self {
            time_cost: 2,
            memory_cost: 19456, // ~19 MiB
            parallelism: 1,
        }
    }

    /// Create parameters for moderate security (500ms target).
    pub fn moderate() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 65536, // 64 MiB
            parallelism: 2,
        }
    }

    /// Derive a 48-byte key from a password and salt using Argon2id.
    ///
    /// Returns `[aes_key: 32 bytes, ctr_nonce: 16 bytes]`.
    pub(crate) fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8; 16],
    ) -> Result<[u8; 48], argon2::Error> {
        let argon2_params = argon2::Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(48),
        )?;
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        );

        let mut output = [0u8; 48];
        argon2.hash_password_into(password, salt, &mut output)?;
        Ok(output)
    }
}
