# Signing Messages with Enegma

## Why Enegma Can't Sign Messages Today

Enegma is a **symmetric cipher** — the same secret key encrypts and decrypts. Anyone who can decrypt a message can also forge one. There is no way to prove authorship or detect tampering.

Digital signatures require **asymmetric cryptography**: a private key that only the signer holds, and a public key that anyone can use to verify.

## Proposed Signing Feature

### Option 1: HMAC (Shared-Secret Integrity)

Use HMAC-SHA256 to produce a message authentication code over the ciphertext.

**How it would work:**
- Sender and recipient share a secret MAC key (could be distributed via codebook)
- After encryption, compute `HMAC-SHA256(mac_key, ciphertext)`
- Append the HMAC tag to the output
- Recipient recomputes the HMAC and compares before decrypting

**CLI sketch:**
```
# Encrypt with HMAC
enegma-plus.py "HELLO WORLD" A B C --hmac-key secret.key

# Decrypt and verify
enegma-plus.py -d "CIPHERTEXT" A B C --hmac-key secret.key
```

**Trade-offs:**
- Simple to implement (Python `hmac` + `hashlib` in stdlib)
- Proves the sender knew the shared secret
- Does **not** provide non-repudiation — either party could have produced the tag
- Detects tampering with ciphertext

---

### Option 2: Digital Signatures (Asymmetric)

Use Ed25519 (or ML-DSA for post-quantum, see [README-pq.md](README-pq.md)) to sign the ciphertext.

**How it would work:**
- Each sender generates a signing keypair (private + public)
- After encryption, sign the ciphertext with the private key
- Output the signature alongside the ciphertext
- Recipient verifies the signature with the sender's public key before decrypting

**CLI sketch:**
```
# Generate signing keypair
enegma-plus.py --sign-keygen --out sender.pub --secret sender.key

# Encrypt and sign
enegma-plus.py "HELLO WORLD" A B C --sign --sign-key sender.key

# Verify signature then decrypt
enegma-plus.py -d "CIPHERTEXT" A B C --verify --sign-pub sender.pub
```

**Trade-offs:**
- Provides **non-repudiation** — only the private key holder could have signed
- Requires key distribution (public keys must be shared)
- Ed25519 is fast and widely supported (`cryptography` library)
- Not post-quantum resistant (use ML-DSA for that)

---

### Option 3: Codebook-Based HMAC

Extend the existing codebook format to include a daily MAC key, keeping the codebook-driven workflow intact.

**Codebook entry:**
```json
"2026-03-04": {
  "wheels": [12, 5, 10],
  "positions": [8, 11, 20],
  "plugboard": "SP HC XU IB NG RJ FK DZ QV AL",
  "hmac_key": "base64-encoded-256-bit-key"
}
```

**How it would work:**
- `make-enegma-plus-codebook.py` generates a random HMAC key per day
- Encryption with `--cb` automatically computes and appends the HMAC tag
- Decryption with `--cb` automatically verifies the tag before decrypting
- If verification fails, the message is rejected

**Trade-offs:**
- Seamless integration with existing codebook workflow
- No extra CLI flags needed when using codebooks
- Integrity protection is automatic
- Still requires secure codebook distribution

---

## Comparison

| Feature | HMAC | Ed25519 | ML-DSA (PQ) |
|---------|------|---------|-------------|
| Detects tampering | Yes | Yes | Yes |
| Proves authorship | Shared secret only | Yes | Yes |
| Non-repudiation | No | Yes | Yes |
| Post-quantum safe | Yes (HMAC-SHA256) | No | Yes |
| Dependencies | stdlib only | `cryptography` | `oqs` |
| Key management | Shared secret | Keypairs | Keypairs |

## Implementation Priority

1. **HMAC** — lowest friction, no new dependencies, fits codebook model
2. **Ed25519** — adds real signatures with minimal complexity
3. **ML-DSA** — full post-quantum signing (see [README-pq.md](README-pq.md))
