# Post-Quantum Features for Enegma

The Enegma cipher is a symmetric substitution cipher — educationally interesting but not quantum-resistant. Post-quantum cryptography (PQC) can be layered on top to modernize key exchange and authentication.

## Possible Additions

### 1. PQ Key Encapsulation (ML-KEM / Kyber)

**Problem:** Currently, daily keys are distributed via pre-shared codebooks (JSON files). If an adversary obtains the codebook, all messages for that period are compromised.

**Solution:** Use ML-KEM (formerly CRYSTALS-Kyber, NIST FIPS 203) to encapsulate the daily/message key material.

**How it would work:**
- Each recipient generates an ML-KEM keypair (public + secret key)
- The sender uses the recipient's public key to encapsulate a shared secret
- The shared secret is used to derive wheel selection, positions, and plugboard settings
- The KEM ciphertext is prepended to the Enegma ciphertext
- The recipient decapsulates with their secret key to recover the Enegma settings

**CLI sketch:**
```
# Generate keypair
enegma-plus.py --pq-keygen --out my.pub --secret my.key

# Encrypt with PQ key encapsulation
enegma-plus.py "HELLO WORLD" --pq-encrypt --pub recipient.pub

# Decrypt
enegma-plus.py -d --pq-decrypt --secret my.key --in message.enc
```

**Benefit:** Eliminates the need for pre-shared codebooks. Secure against quantum adversaries for key exchange.

---

### 2. PQ Digital Signatures (ML-DSA / Dilithium)

**Problem:** There is no way to verify who sent a message or whether it was tampered with. Any party with the shared key can forge messages.

**Solution:** Use ML-DSA (formerly CRYSTALS-Dilithium, NIST FIPS 204) to sign ciphertext.

**How it would work:**
- Each sender generates an ML-DSA signing keypair
- After encryption, the sender signs the ciphertext with their private key
- The signature is appended or output alongside the ciphertext
- The recipient verifies the signature with the sender's public key before decrypting

**CLI sketch:**
```
# Generate signing keypair
enegma-plus.py --pq-sign-keygen --out my-sign.pub --secret my-sign.key

# Encrypt and sign
enegma-plus.py "HELLO WORLD" A B C --pq-sign --sign-key my-sign.key

# Verify and decrypt
enegma-plus.py -d "CIPHERTEXT" A B C --pq-verify --sign-pub sender-sign.pub
```

**Benefit:** Provides message authenticity and integrity. Non-repudiation — only the holder of the signing key could have produced the signature.

---

### 3. Both Combined (Full PQ Upgrade)

Use ML-KEM for key exchange **and** ML-DSA for signatures. This gives:
- **Confidentiality:** Enegma encryption with PQ-protected key distribution
- **Authenticity:** PQ signature proves sender identity
- **Integrity:** Signature detects any tampering with ciphertext
- **Post-quantum security:** Both operations resist quantum attacks

---

## Python Libraries

| Library | Notes |
|---------|-------|
| [`oqs`](https://github.com/open-quantum-safe/liboqs-python) | Bindings to liboqs, supports ML-KEM and ML-DSA |
| [`pqcrypto`](https://pypi.org/project/pqcrypto/) | Pure Python PQC implementations |
| [`cryptography`](https://pypi.org/project/cryptography/) | May add PQC support as NIST standards finalize |

## Important Caveat

The Enegma rotor cipher itself is not cryptographically secure by modern standards — it is vulnerable to known-plaintext attacks (see `bombe.py`). PQ features would protect the **key exchange** and **authentication** layers, but the underlying encryption remains a substitution cipher. For real-world security, replace the Enegma core with AES-256-GCM or ChaCha20-Poly1305.
