# Ephemeris Binary File Format Specification

## Version: 1 (OTP mode)

All multi-byte integers are **little-endian**.

---

## `.eph` — Combined File Format

Contains the salt, wrapped key, and ciphertext in a single self-contained file.

```
Offset  Size    Field           Description
------  ----    -----           -----------
0       4       Magic           b"EPH1" (0x45504831)
4       16      Salt            Argon2id salt, 16 random bytes from OS CSPRNG
20      1       Flags           Bit 0: mode (0 = OTP). Bits 1-7: reserved (must be 0)
21      4       KeyBlobLen      u32 LE, length of the encrypted OTP key in bytes
25      N       KeyBlob         AES-256-CTR(KDF(password, salt), otp_key)
25+N    M       Ciphertext      plaintext XOR otp_key
```

**Constraints (OTP mode, Flags bit 0 = 0):**
- `N == M` (key blob length equals ciphertext length)
- Total file size: `25 + N + M = 25 + 2N` bytes
- Minimum file size: 25 bytes (empty message)
- Maximum theoretical size: ~8 GiB (limited by u32 KeyBlobLen)

**Parsing rules:**
1. File must contain at least 25 bytes
2. Magic must match `EPH1`
3. Flags bits 1-7 must be zero
4. File must contain at least `25 + KeyBlobLen` bytes
5. In OTP mode: remaining bytes after key blob must equal `KeyBlobLen`

---

## `.key` — Standalone Key File

Contains only the salt and wrapped key. Allows physical separation of key material from ciphertext for additional deniability.

```
Offset  Size    Field           Description
------  ----    -----           -----------
0       4       Magic           b"EPHk" (0x4550486B)
4       16      Salt            Argon2id salt (matches the corresponding .eph file)
20      1       Flags           Bit 0: mode (0 = OTP). Bits 1-7: reserved (must be 0)
21      4       KeyBlobLen      u32 LE, length of the encrypted OTP key in bytes
25      N       KeyBlob         AES-256-CTR(KDF(password, salt), otp_key)
```

**Constraints:**
- Total file size: `25 + N` bytes
- No ciphertext is stored

**Parsing rules:**
1. File must contain at least 25 bytes
2. Magic must match `EPHk`
3. Flags bits 1-7 must be zero
4. File must contain at least `25 + KeyBlobLen` bytes

**Matching `.key` to `.eph`:**
- Compare the 16-byte salt values. Matching salts indicate the key belongs to that ciphertext.
- There is no cryptographic binding between a `.key` and `.eph` file.

---

## Key Blob Format

The key blob is the output of AES-256-CTR encryption of the OTP key:

```
KEK_seed = Argon2id(password, salt, output_len=48)
aes_key  = KEK_seed[0..32]      # AES-256 key
ctr_nonce = KEK_seed[32..48]    # 128-bit CTR nonce (big-endian counter)

key_blob[i] = otp_key[i] XOR AES256_CTR_block(aes_key, ctr_nonce + i/16)[i % 16]
```

**Properties:**
- No authentication tag (no MAC, no GCM)
- Length(key_blob) == length(otp_key) == length(plaintext)
- Wrong password → garbage otp_key → garbage plaintext, but no error

---

## Cryptographic Parameters (v1)

| Parameter | Value |
|-----------|-------|
| KDF | Argon2id |
| Argon2 version | 0x13 |
| Output length | 48 bytes (32 key + 16 nonce) |
| Default time cost | 2 |
| Default memory cost | 19456 KiB (~19 MiB) |
| Default parallelism | 1 |
| Key wrap cipher | AES-256-CTR |
| CTR counter size | 128 bits, big-endian |
| OTP RNG | OS CSPRNG (getrandom on Linux, BCryptGenRandom on Windows) |

---

## Future Format Versions

### Reserved Flags Bits

Bits 1-7 of the flags byte are reserved. Implementations MUST reject files with reserved bits set. This allows future format extensions while ensuring backward compatibility through rejection.

### Planned Extensions

- **Stream cipher mode (bit 0 = 1)**: Use XChaCha20 with a 32-byte seed + correction factor for shorter key blobs
- **Multi-key mode**: Embed up to 256 key blobs for multi-recipient or multi-cover-story scenarios
- **Authenticated mode (bit 1)**: Optional AEAD tag for non-deniable use cases
