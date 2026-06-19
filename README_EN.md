# Ephemeris

**Message-level deniable encryption with information-theoretic security.**

Encrypt a message. Under duress, prove it decrypts to something else. No mathematical test can tell which is real.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/ephemeris-core.svg)](https://crates.io/crates/ephemeris-core)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)

*中文版: [README.md](README.md)*

## How It Works

```
┌────────────────────────────────────────────────────┐
│                   ENCRYPTION                        │
│                                                     │
│  1. Generate random OTP key K (len = message len)  │
│  2. C = plaintext ⊕ K                               │
│  3. Wrap K: AES-256-CTR(KDF(password, salt), K)    │
│  4. Store: salt ‖ wrapped_K ‖ C                     │
│                                                     │
│                   REPUDIATION                       │
│                                                     │
│  1. Choose harmless fake message P_fake (same len) │
│  2. K_fake = C ⊕ P_fake                             │
│  3. Wrap K_fake with fake password                  │
│  4. Replace key blob                                │
│                                                     │
│  Fake password → harmless message. Real data gone.  │
└────────────────────────────────────────────────────┘
```

### Why Deniable

- **OTP**: For ciphertext C, ANY plaintext P' of equal length has a unique key K' = C ⊕ P'. Infinitely many valid (key, plaintext) pairs.
- **Non-committing wrapping**: AES-256-CTR without authentication — every password produces "valid" output, no error oracle.
- **No real password needed**: `repudiate` computes the fake key directly from ciphertext.

## Quick Start

### Rust

```bash
cargo add ephemeris-core
```

```rust
use ephemeris_core::*;

let result = encrypt(b"Launch codes: ALPHA-42", b"secret-password", &Argon2Params::default());
let pt = decrypt(&result.eph_file, b"secret-password", &params).unwrap();

// Repudiate — claim it was a diary entry
let fake = repudiate_eph(
    &result.eph_file,
    b"Dear diary: boring day",  // must be same length!
    b"diary-password",
    &params,
).unwrap();
```

### Python

```bash
pip install ephemeris
```

```python
import ephemeris
data = ephemeris.encrypt(b"Launch codes: ALPHA-42", b"secret-password")
plaintext = ephemeris.decrypt(data, b"secret-password")
fake = ephemeris.repudiate_eph(data, b"Dear diary: boring day", b"diary-pw")
```

### CLI

```bash
cargo install eph

# Basic operations
eph encrypt secret.txt secret.eph
eph decrypt secret.eph output.txt
eph repudiate secret.eph cover.eph fake.txt
eph info secret.eph

# Advanced features
eph encrypt secret.txt secret.eph --armor   # base64 armor (email/chat friendly)
eph encrypt secret.txt secret.eph --shred   # securely erase original after encrypt
eph gen-pass -n 6 -e                        # generate strong passphrase (6 words)
eph decrypt msg.asc output.txt              # auto-detect binary or armor format
```

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Deniability** | Information-theoretic: C decrypts to ANY P' of same length |
| **Key wrapping** | Non-committing: all passwords produce valid output |
| **Repudiation** | No real password required |
| **File format** | Byte-identical structure after repudiation |
| **Timing** | Constant-time comparison, no password oracle |
| **Memory safety** | Zero unsafe, keys zeroized after use |

## Cryptographic Primitives

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Encryption | One-Time Pad (XOR) | Key = message length |
| KDF | Argon2id | t=2, m=37888 KiB, p=1 |
| Key wrapping | AES-256-CTR | 128-bit BE counter, NO MAC |
| Salt | OS CSPRNG | 128 bits |
| RNG | getrandom / BCryptGenRandom | OS-level |

## File Format

```
.eph file:                      .key file:
┌──────────────────────┐        ┌──────────────────────┐
│ Magic: "EPH1"   (4B) │        │ Magic: "EPHk"   (4B) │
│ Salt:   random  (16B)│        │ Salt:   random  (16B)│
│ Flags: 0x00      (1B) │        │ Flags: 0x00      (1B) │
│ KeyLen: u32 LE   (4B) │        │ KeyLen: u32 LE   (4B) │
│ KeyBlob          (NB) │        │ KeyBlob          (NB) │
│ Ciphertext       (NB) │        └──────────────────────┘
└──────────────────────┘
      25 + 2N bytes                  25 + N bytes
```

See [`docs/file-format.md`](docs/file-format.md)

## Threat Model

See [`docs/threat-model.md`](docs/threat-model.md)

### Protected

- Cryptographic analysis of `.eph` files
- Password guessing via error oracles (there are none)
- Coercion to reveal password (give the fake one)

### Not Protected

- **Weak passwords** (< 50 bits entropy) can be brute-forced
- **Multiple interrogations** — inconsistent stories are detectable
- **Keyloggers / malware**
- **Physical coercion** (rubber-hose cryptanalysis)
- **Memory forensics** — mitigated by `zeroize`, not eliminated
- **Length leakage** — ciphertext length = plaintext length (OTP inherent)

### Best Practices

1. Repudiate BEFORE coercion
2. Destroy the original after repudiation
3. Use strong passwords (5+ Diceware words)
4. Hide files with innocuous names
5. Pair with full-disk encryption (VeraCrypt)

## Building

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo build --release -p ephemeris-core -p eph
cargo test --workspace --exclude ephemeris-python

# Python bindings
cd ephemeris-python && pip install maturin && maturin develop && pytest
```

## Security Audit

Comprehensive three-dimensional audit completed: cryptographic design review, code vulnerability scan, and practical attack attempts. All findings remediated.

## Comparison

| System | Deniable | Security | Storage | Oracle |
|--------|----------|----------|---------|--------|
| **Ephemeris** | Message-level | Info-theoretic | Single file | No |
| VeraCrypt | Volume-level | Computational | Disk | No |
| Age / GPG | None | Computational | Single file | Yes |

## License

MIT — [LICENSE](LICENSE)

---

⚠ Ephemeris provides cryptographic deniability, not legal protection.
