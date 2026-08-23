# Ephemeris

**Message-level deniable encryption with information-theoretic security.**

Encrypt a message. Under duress, prove it decrypts to something else. Under ideal operational conditions, no mathematical test can tell which plaintext is real.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/ephemeris-core.svg)](https://crates.io/crates/ephemeris-core)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)

*中文版: [README.md](README.md)*

---

## Table of Contents

- [Core Idea](#core-idea)
- [Security Properties](#security-properties)
- [Quick Start](#quick-start)
- [Detailed Usage Guide](#detailed-usage-guide)
- [File Format](#file-format)
- [Threat Model](#threat-model)
- [Performance Optimizations](#performance-optimizations)
- [Building From Source](#building-from-source)
- [Algorithm Provenance and Originality](#algorithm-provenance-and-originality)
- [Security Audit](#security-audit)
- [Comparison](#comparison)
- [License and Disclaimer](#license-and-disclaimer)

---

## Core Idea

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

---

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Deniability** | Information-theoretic at the OTP layer: C decrypts to ANY P' of same length |
| **Key wrapping** | Non-committing: all passwords produce valid output |
| **Repudiation** | No real password required |
| **File format** | Byte-identical structure after repudiation |
| **Timing** | Constant-time comparison, no password oracle |
| **Memory safety** | Zero unsafe, core keys zeroized after use |

> The "information-theoretic" claim applies to the OTP layer. Full-file deniability also depends on password strength, absence of old file copies, and plausible fake messages. See [Threat Model](#threat-model).

---

## Quick Start

### Installation

#### Rust

```bash
cargo add ephemeris-core
```

#### CLI

```bash
cargo install eph
```

or build from source:

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo install --path eph-cli
```

#### Python

```bash
pip install ephemeris
```

### Rust

```rust
use ephemeris_core::*;

let params = Argon2Params::default();

// Encrypt
let result = encrypt(b"Launch codes: ALPHA-42", b"secret-password", &params);

// Decrypt
let pt = decrypt(&result.eph_file, b"secret-password", &params).unwrap();
assert_eq!(pt, b"Launch codes: ALPHA-42");

// Repudiate — claim it was a diary entry (same byte length!)
let fake = repudiate_eph(
    &result.eph_file,
    b"Dear diary: boring day",
    b"diary-password",
    &params,
).unwrap();

let fake_pt = decrypt(&fake, b"diary-password", &params).unwrap();
assert_eq!(fake_pt, b"Dear diary: boring day");
```

### Python

```python
import ephemeris

data = ephemeris.encrypt("发射代码: ALPHA-42".encode("utf-8"), b"secret-password")
plaintext = ephemeris.decrypt(data, b"secret-password")
print(plaintext.decode("utf-8"))

fake_data = ephemeris.repudiate_eph(
    data,
    b"Dear diary: boring day",
    b"diary-pw",
)
assert ephemeris.decrypt(fake_data, b"diary-pw") == b"Dear diary: boring day"
```

### CLI

```bash
# Basic operations
eph encrypt secret.txt secret.eph
eph decrypt secret.eph output.txt
eph repudiate secret.eph cover.eph fake.txt
eph info secret.eph

# Advanced features
eph encrypt secret.txt secret.eph --armor
eph encrypt secret.txt secret.eph --shred
eph gen-pass -n 6 -e
eph decrypt msg.asc output.txt

# Split key/ciphertext + base64 text output
eph encrypt secret.txt --key-file key.b64 --cipher-file cipher.b64 --text
eph decrypt cipher.b64 output.txt --split --key-file key.b64 --text
```

---

## Detailed Usage Guide

### 1. UTF-8 / Chinese Support

Ephemeris processes bytes, not text. Chinese works naturally when encoded as UTF-8.

```bash
printf '中文测试消息 Chinese message' > msg.txt

eph encrypt msg.txt msg.eph -p 'your-password'
eph decrypt msg.eph out.txt -p 'your-password'
```

### 2. Character Ciphertext Instead of Files

Use `--armor` or `--text` for copy/paste friendly ciphertext.

#### stdout / stdin

```bash
# Read plaintext from stdin, output ASCII armor to stdout
printf '中文测试消息 Chinese message' | eph encrypt - - -p 'your-password'
```

Output example:

```text
-----BEGIN EPHEMERIS-----
RVBIMe5vbVeqYAitYIzNXHaCtugAIgAAAPxxNUh1dIUTdSfhDP5Cs3EwseuM/5DD
FjDwalzSQ5Tvb3P8dXtJLyD/vGAXBdKohETZOtTaRD0QJ/Dr6s8Ubh62OrKP
-----END EPHEMERIS-----
```

Decrypt armor to stdout:

```bash
eph decrypt out.asc - -p 'your-password'
```

#### Base64 text files

```bash
eph encrypt msg.txt msg.b64 --text
eph decrypt msg.b64 out.txt --text
```

#### Python base64 string

```python
import base64
import ephemeris

data = ephemeris.encrypt("中文消息".encode("utf-8"), b"password")
cipher_text = base64.b64encode(data).decode("ascii")

plain = ephemeris.decrypt(base64.b64decode(cipher_text), b"password")
print(plain.decode("utf-8"))
```

### 3. Password Input

```bash
# Interactive (default, asks for confirmation)
eph encrypt msg.txt msg.eph

# Command line flag (visible in process list, use with care)
eph encrypt msg.txt msg.eph -p 'your-password'

# Read from file
eph encrypt msg.txt msg.eph -P password.txt
```

> Note: `--password-file` reads the whole file as the password. If the file ends with a newline, that newline is part of the password.

### 4. Argon2 Parameters

Defaults:

| Parameter | Default |
|-----------|---------|
| Algorithm | Argon2id |
| time cost | 2 |
| memory cost | 37888 KiB (~37 MiB) |
| parallelism | 1 |

CLI override:

```bash
eph encrypt msg.txt msg.eph -t 3 -m 65536 -j 2
```

> Argon2 parameters are not currently stored in the `.eph` header. You must use the same parameters for decryption or you will get garbage.

### 5. Repudiation in Detail

```bash
eph repudiate secret.eph cover.eph fake.txt
```

Requirements:

- `fake.txt` must have the **same byte length** as the original ciphertext;
- repudiation creates a new file, it does not modify the original;
- destroy the original file afterwards, otherwise an attacker with the old copy can detect the repudiation.

Check lengths:

```bash
eph info secret.eph
```

Armor output is supported:

```bash
eph repudiate secret.eph cover.asc fake.txt --armor
```

### 6. Split Key and Ciphertext

```bash
eph encrypt msg.txt --key-file key.bin --cipher-file cipher.bin
eph encrypt msg.txt --key-file key.b64 --cipher-file cipher.b64 --text

eph decrypt cipher.b64 out.txt --split --key-file key.b64 --text
eph decrypt cipher.bin out.txt --split --key-file key.bin
```

### 7. Inspect Files

```bash
eph info secret.eph
eph info key.bin
```

### 8. Generate Strong Passwords

```bash
eph gen-pass
eph gen-pass -n 8 -e
```

### 9. Secure Erase

```bash
eph encrypt secret.txt secret.eph --shred
```

> Modern SSDs, journaling filesystems, snapshots, backups and cloud sync may make overwrite-and-delete non-recoverable in practice. Treat `--shred` as best-effort.

### 10. Common Options

| Option | Purpose |
|--------|---------|
| `-p, --password` | Password on command line (visible in process list) |
| `-P, --password-file` | Read password from file |
| `--armor` | Use ASCII armor base64 text |
| `--text` | Use plain base64 text |
| `--key-file` | Write/read standalone key file |
| `--cipher-file` | Write standalone ciphertext file |
| `--split` | Decrypt split cipher + key files |
| `--shred` | Best-effort secure erase of input after encryption |
| `-f, --force` | Overwrite existing output files |
| `-t, --time-cost` | Argon2id iterations |
| `-m, --memory-cost` | Argon2id memory in KiB |
| `-j, --parallelism` | Argon2id parallelism |

---

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

---

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
- **Ciphertext tampering** — no MAC/authentication; flipping ciphertext bits flips plaintext bits
- **Old file copies** — if the attacker kept an older `.eph`, KeyBlob comparison can reveal repudiation

### Best Practices

1. Repudiate BEFORE coercion
2. Destroy the original after repudiation
3. Use strong passwords (5+ Diceware words)
4. Hide files with innocuous names
5. Pair with full-disk encryption (VeraCrypt)

---

## Performance Optimizations

- **Chunked XOR**: OTP encryption/decryption processes data in 8-byte (`u64`) chunks to reduce loop overhead and help the compiler auto-vectorize the hot path.
- **In-place decryption**: `decrypt` reuses the unwrapped OTP key buffer as the plaintext buffer, eliminating one message-length heap allocation.
- **In-place repudiation**: `repudiate` computes the fake key and wraps it in place via `wrap_key_inplace`, avoiding the extra `key.to_vec()` copy.

> Note: overall latency is still dominated by the Argon2id KDF. These optimizations mainly reduce memory usage and peak pressure for large files.

---

## Building From Source

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo build --release -p ephemeris-core -p eph
cargo test --workspace --exclude ephemeris

# Python bindings
cd ephemeris-python && pip install maturin && maturin develop && pytest
```

> Note: the Python crate is named `ephemeris`. To exclude it from workspace tests, use `--exclude ephemeris`, not `--exclude ephemeris-python`.

---

## Algorithm Provenance and Originality

### Conclusion

**The core cryptographic idea is not new, but the project’s engineering implementation has some originality.**

- OTP guarantees that any same-length plaintext can be explained by some key;
- AES-256-CTR without an authentication tag provides non-committing key wrapping;
- Repudiation computes `K_fake = C ⊕ P_fake` directly.

"Deniable encryption" and "non-committing encryption" are long-established concepts, and OTP-based deniable encryption appears in earlier literature.

### Related Public Research

- **Deniable Encryption**
  - Canetti, Dwork, Naor, Ostrovsky, *Deniable Encryption*, CRYPTO 1997.

- **Non-Committing Encryption**
  - Introduced in the context of adaptively secure multi-party computation (Canetti, Feige, Goldreich, Naor, and follow-up work).
  - Allows ciphertexts to be explained as different messages without committing to a single one.

- **Deniable Encryption using One Time Pads**
  - Amrutiya, Baskaran, Iyengar, AICTC '16.
  - Proposes using one-time pads to generate fake messages from ciphertext, closely related to Ephemeris’s approach.

- **Sender/Receiver-Deniable Encryption**
  - Extensive later work in public-key, interactive, and quantum settings.
  - Ephemeris takes a simpler symmetric-password + key-wrap route.

### Ephemeris’s Original Contributions

- Practical single-file `.eph` / `.key` formats;
- Argon2id-derived AES-256-CTR non-committing key wrapping without an auth tag;
- Rust API, CLI, and Python bindings;
- Explicit threat-model discussion of length leakage, repeated interrogation, and old-file-copy attacks.

> This section is based on public literature and web search; it is not legal or patent advice.

---

## Security Audit

Comprehensive three-dimensional audit completed: cryptographic design review, code vulnerability scan, and practical attack attempts. All findings remediated.

---

## Comparison

| System | Deniable | Security | Storage | Oracle |
|--------|----------|----------|---------|--------|
| **Ephemeris** | Message-level | Info-theoretic (OTP layer) | Single file | No |
| VeraCrypt | Volume-level | Computational | Disk | No |
| Age / GPG | None | Computational | Single file | Yes |

---

## License and Disclaimer

MIT — [LICENSE](LICENSE)

⚠ Ephemeris provides cryptographic deniability, not legal protection. Some jurisdictions may restrict the use of deniable encryption tools.
