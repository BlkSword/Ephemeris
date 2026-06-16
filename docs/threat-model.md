# Ephemeris Threat Model

## What Ephemeris Protects Against

Ephemeris is designed to provide **plausible deniability** for encrypted messages. Under duress, a user can "prove" that a ciphertext decrypts to a harmless message, while the real message remains hidden.

### Guarantees

1. **Information-theoretic deniability**: For any `.eph` ciphertext C and any plaintext P' of the same length, there exists a unique key K' = C ⊕ P' such that C ⊕ K' = P'. No algorithm — even with unlimited computational power — can determine which key is "real." This is guaranteed by the One-Time Pad construction.

2. **Non-committing key wrapping**: AES-256-CTR without an authentication tag means every password produces a valid-looking decryption. There is no error state to distinguish correct from incorrect passwords. This prevents an attacker from identifying the real password by trial-and-error looking for the one that "doesn't error."

3. **Repudiate without real password**: The `repudiate` function computes `K_fake = C ⊕ P_fake` directly. It never needs the real password, preventing keylogger exposure during coercion.

4. **Indistinguishable file format**: After repudiation, the `.eph` file is byte-for-byte identical in structure to a legitimate file. The fake key blob is AES-CTR-encrypted random data — identical in distribution to a real key blob.

### Attacker Capabilities Assumed

- Full access to the `.eph` file and any `.key` files
- Knowledge of the encryption scheme (Kerckhoffs's principle)
- Ability to demand passwords and verify they "work" (produce plausible output)
- Unlimited computational resources for offline analysis
- Ability to inspect file metadata (size, timestamps)

## What Ephemeris Does NOT Protect Against

### 1. Rubber-Hose Cryptanalysis

Physical coercion, threats of violence, or other extra-cryptographic attacks are outside the scope of any software tool. Ephemeris provides cryptographic deniability — not physical safety.

### 2. Multiple Interrogations

If an attacker can demand decryption multiple times with different fake passwords:
- **First interrogation**: User provides fake_password_1 → plaintext_1. Attacker is satisfied.
- **Second interrogation**: User must provide the SAME fake_password_1 to get the SAME plaintext_1. Changing the story (different fake password → different fake plaintext) immediately reveals deception.
- Ephemeris helps with a SINGLE fake story. It does not help if the attacker interrogates you repeatedly and compares answers.

### 3. Fake Message Plausibility

Ephemeris can make ciphertext decrypt to any message. It cannot make that message **believable**. The user is responsible for providing fake plaintexts that are:
- Semantically appropriate for the context
- Consistent with the user's known behavior and communications
- Free of metadata contradictions (timestamps, file names, etc.)

### 4. Ciphertext Length Leakage

Ciphertext length equals plaintext length (OTP property). An attacker can:
- Learn the exact byte length of the original message
- Compare this with the fake message to check consistency
- Use length as a distinguisher (e.g., "launch codes" might be 20 bytes; "grocery list" might typically be 200+ bytes)

**Best practice**: Choose fake messages of approximately the same natural length as real messages.

### 5. Keyloggers, Malware, and Memory Inspection

- A keylogger can capture the real password as it is typed
- Malware can read the plaintext before encryption or after decryption
- Memory inspection (cold boot, DMA, etc.) can extract keys from RAM
- These attacks bypass encryption entirely and are not addressed by Ephemeris

### 6. Traffic Analysis and Timing

- An attacker observing network traffic can see when `.eph` files are transferred
- File sizes are not padded or obfuscated
- Access patterns (which files are opened, when, how often) are visible to the OS

### 7. Metadata Side Channels

- **File timestamps**: Creation/modification times of `.eph` files may contradict the fake narrative
- **File names**: `launch_codes.eph` is harder to explain than `diary.eph`
- **Disk locations**: Hidden or encrypted-looking file paths attract attention

**Best practice**: Use innocuous file names, disable OS file timestamp updates where possible, and store `.eph` files among normal documents.

### 8. Legal/Regulatory Risk

Some jurisdictions may:
- Compel disclosure of encryption keys by law
- Treat refusal to decrypt as obstruction of justice
- Criminalize the use of deniable encryption tools specifically

Research and comply with local laws. The tool itself is legal to develop and possess (like VeraCrypt), but usage in specific contexts may have legal implications.

## Comparison with Other Approaches

| System | Deniability Type | Security Level | Storage |
|--------|-----------------|----------------|---------|
| **Ephemeris** | Message-level | Information-theoretic | Single file |
| VeraCrypt | Volume-level (hidden volume) | Computational | Disk/container |
| OTR/OTRv4 | Message-level (conversation) | Computational | Ephemeral |
| Signal | None for stored messages | N/A | Server + local |
| TrueCrypt | Volume-level (hidden volume) | Computational | Disk/container |

Ephemeris fills the gap of **message-level, information-theoretic, storable** deniable encryption — a category not well-served by existing tools.

## Operational Recommendations

1. **Repudiate BEFORE coercion**: Have the repudiated `.eph` file ready. Do not wait until under duress to compute it.

2. **Keep fake messages ready**: Prepare plausible cover stories with corresponding fake plaintexts.

3. **Use separate devices**: Perform real encryption on an air-gapped device. Keep only repudiated files on internet-connected devices.

4. **Destroy original keys**: After repudiation, securely erase the original OTP key and real password. The repudiated file IS the file now.

5. **Practice the cover story**: A well-rehearsed fake narrative is more convincing than a hastily invented one.

6. **Use full-disk encryption**: If an attacker sees Ephemeris installed on your system, they may demand decryption of specific files. Full-disk encryption (e.g., VeraCrypt hidden volume) provides an additional layer.
