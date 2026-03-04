# Cryptographic Concepts for Enegma

Additional cryptographic techniques and concepts to consider for the
Enegma project, beyond what is covered in [README-sign.md](README-sign.md),
[README-pq.md](README-pq.md), and [README-revocation.md](README-revocation.md).

## Key Management

### Key Derivation (HKDF / PBKDF2)

Derive wheel settings from a passphrase instead of raw numeric positions.
Users type a memorable password instead of `7 14 22`.

```bash
# Instead of this
enegma-plus.py "HELLO" 7 14 22 --wh "5 12 3" --pb "AN BY CW"

# Allow this
enegma-plus.py "HELLO" --passphrase "correct horse battery staple"
```

The passphrase is run through PBKDF2 or HKDF to derive wheel selection,
positions, and plugboard settings deterministically. Both parties use the
same passphrase.

**Python:** `hashlib.pbkdf2_hmac()` or `cryptography.hazmat.primitives.kdf.hkdf`

### Key Agreement (Diffie-Hellman / X25519)

Two parties establish a shared secret over an insecure channel without
pre-shared codebooks. The shared secret is then used to derive Enegma
settings via HKDF.

```bash
# Alice generates a keypair
enegma-plus.py --dh-keygen --out alice.pub --secret alice.key

# Bob generates a keypair
enegma-plus.py --dh-keygen --out bob.pub --secret bob.key

# Alice encrypts using Bob's public key
enegma-plus.py "HELLO" --dh-encrypt --pub bob.pub --secret alice.key

# Bob decrypts using Alice's public key
enegma-plus.py -d "CIPHERTEXT" --dh-decrypt --pub alice.pub --secret bob.key
```

**Python:** `cryptography.hazmat.primitives.asymmetric.x25519`

### Split Keys (Shamir's Secret Sharing)

Split a codebook encryption key into N shares where any K of them can
reconstruct the original. Useful for organizational recovery — no single
person holds the complete key.

```bash
# Split a codebook key into 5 shares, any 3 can reconstruct
enegma-plus.py --split-key --shares 5 --threshold 3 --in codebook.json

# Reconstruct from 3 shares
enegma-plus.py --reconstruct-key --in share1.json share3.json share5.json
```

## Message Integrity & Authentication

### Authenticated Encryption (Encrypt-then-MAC)

Combine the Enegma cipher with HMAC so that tampering is automatically
detected during decryption, not as a separate verification step.

```bash
# Encrypt with authentication (HMAC appended automatically)
enegma-plus.py "HELLO" 7 14 22 --auth-key secret.key

# Decrypt (fails if ciphertext was tampered with)
enegma-plus.py -d "CIPHERTEXT" 7 14 22 --auth-key secret.key
# ERROR: Authentication failed — message may have been tampered with
```

The MAC key could be derived from the daily key via HKDF, keeping the
interface simple.

### Nonce Management

The per-message key already serves as a nonce (random, never repeated).
Formalizing this with a counter or timestamp prevents accidental reuse:

- **Counter-based:** Append a monotonic counter to each message
- **Timestamp-based:** Include the encryption timestamp, reject replayed messages
- **Random (current):** 3 random positions via `secrets.randbelow(26)` — collision probability is 1/17,576 per daily key

## Traffic Analysis Resistance

### Message Padding

Fixed-length messages prevent an adversary from inferring content by
message length. A short "YES" and a long battle plan would be
indistinguishable on the wire.

```bash
# Pad all messages to 200 characters
enegma-plus.py "YES" 7 14 22 --pad 200

# Output is always exactly 200 characters (plus 3-char key indicator)
```

Padding uses random characters appended after an end-of-message marker.
The decoder strips padding after decryption.

### Dummy Messages

Send decoy messages at regular intervals to hide real communication
patterns. An adversary cannot distinguish real messages from noise.

```bash
# Generate a dummy message using today's codebook
enegma-plus.py --dummy --cb
```

### Steganography

Hide ciphertext inside innocuous-looking data — images, text, or other
files. The ciphertext is embedded in a carrier medium and extracted
before decryption.

This is a large feature and would likely be a separate tool rather than
a flag on `enegma-plus.py`.

## Trust & Identity

### Public Key Infrastructure (PKI)

If signing or key agreement is added, the question becomes: how do you
trust that a public key belongs to who it claims?

Options:
- **Certificate chains:** A trusted authority signs public keys
- **Web of trust:** Users sign each other's keys (PGP model)
- **TOFU (Trust On First Use):** Accept a key the first time, warn if it changes (SSH model)
- **Out-of-band verification:** Compare key fingerprints over a separate channel

### Key Fingerprints

Short hashes of public keys for easy out-of-band verification.

```bash
# Display fingerprint of a public key
enegma-plus.py --fingerprint alice.pub
# SHA-256: 3E:2A:1F:... (truncated)

# "Alice, read me your fingerprint over the phone"
```

## Operational Security

### Side-Channel Resistance

Constant-time operations prevent timing attacks — an adversary measuring
how long encryption takes cannot infer key material. Less critical for
the rotor cipher itself, but important if real cryptographic primitives
(HMAC, Ed25519, AES) are added alongside it.

**Python:** `hmac.compare_digest()` for constant-time comparison.

### Plausible Deniability

Deniable encryption allows decrypting the same ciphertext to different
plaintexts depending on which key is used. Under coercion, the holder
reveals a decoy key that produces an innocuous message.

This is architecturally complex and would require a fundamentally
different encryption scheme (e.g., a deniable encryption container).

### Secure Key Erasure

Zero out keys from memory after use so they cannot be recovered from
a memory dump. Python's garbage collector makes this difficult — the
`secrets` module helps, but true secure erasure requires C-level
memory management.

Practical mitigations:
- Overwrite key variables with zeros before deletion
- Use `mlock` to prevent keys from being swapped to disk
- Keep key material lifetime as short as possible

## Modern Cipher Replacements

If the rotor cipher is ever replaced with a modern primitive for real
security (while keeping the Enegma interface):

| Cipher | Type | Notes |
|--------|------|-------|
| AES-256-GCM | Authenticated encryption | Industry standard, hardware accelerated |
| ChaCha20-Poly1305 | Authenticated encryption | Fast in software, no timing side channels |
| XSalsa20 | Stream cipher | Extended nonce (192-bit) for safer nonce management |

These would slot in as a replacement for the rotor core while preserving
the codebook, key indicator, and CLI interface.

## Priority for Enegma

| Feature | Impact | Complexity | Recommendation |
|---------|--------|------------|----------------|
| Key derivation from passphrase | High | Low | Add first — most usable improvement |
| Message padding | High | Low | Add second — easy win for traffic analysis resistance |
| Authenticated encryption (Encrypt-then-MAC) | High | Medium | Add third — fills a real security gap |
| Key agreement (X25519) | Medium | Medium | Add after signing is implemented |
| Key fingerprints | Medium | Low | Add alongside any public key feature |
| Dummy messages | Medium | Low | Simple to add, useful operationally |
| Split keys | Low | Medium | Niche use case |
| Steganography | Low | High | Separate project |
| Plausible deniability | Low | High | Separate project |
