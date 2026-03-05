# Enegma-Plus: Known Weaknesses and Attack Vectors

## Keyspace Summary

| Component | Search Space | Effective Bits |
|---|---|---|
| Wheel selection (3 of 16) | 3,360 | ~11.7 |
| Wheel positions (26^3) | 17,576 | ~14.1 |
| Plugboard (10 pairs) | ~150 billion | ~37.2 |
| PRNG seed (2^255 to 2^256) | ~2^256 | ~255 |
| Inner seed (2^255 to 2^256) | ~2^256 | ~255 |
| Per-message key (26^3) | 17,576 | ~14.1 |
| **Combined** | | **~587** |

## Classical Attacks

### 1. Enigma Core is a Polyalphabetic Substitution

The underlying cipher is a 3-wheel Enigma variant with chaining. Without the PRNG overlay, it is vulnerable to the same known-plaintext attacks that broke WWII Enigma: cribs, Banburismus, and bombe-style elimination. Chaining improves diffusion but does not change the algebraic structure.

### 2. PRNG Seed is a Single Point of Failure

The shuffle, frequency padding, PRNG overlay, and EOF marker all derive from three 256-bit seeds. Cracking the seed collapses three protective layers at once, reducing the problem to bare Enigma.

### 3. HKDF is Fast

The PRNG uses HKDF (RFC 5869) with HMAC-SHA256. While this is a standards-compliant construction, it imposes no deliberate cost per evaluation (unlike PBKDF2 or Argon2). An attacker can evaluate candidate seeds at hardware speed.

At approximately 1 billion SHA-256 evaluations per second per GPU, the 2^256 seed space is computationally infeasible to brute-force classically. The seeds are already high-entropy, so key stretching would add cost to legitimate users without meaningful security benefit.

### 4. Known-Plaintext Exposure

If an attacker knows even a few characters of plaintext and their positions, they can recover PRNG stream values at those offsets and work backward through SHA-256 blocks to test candidate seeds.

Common cribs for this system include document headers, repeated phrases ("ARTICLE", "SECTION"), dates, and military conventions.

### 5. ~~EOF Marker as an Oracle~~

**Mitigated.** The EOF marker is now encrypted under `inner_seed` before being embedded in the ciphertext. An attacker who guesses `shuffle_seed` and `eof_seed` but not `inner_seed` computes the wrong encrypted marker and `rfind` fails. Since `inner_seed` is 256-bit and independent, this eliminates the fast rejection oracle.

### 6. Layers are Separable

The PRNG overlay, positional shuffle, and Enigma core operate independently. An attacker who defeats the outer layers (by cracking the seed) faces only the Enigma core, which has roughly 63 bits of key material and is vulnerable to classical cryptanalytic techniques.

## Quantum Attacks

### Grover's Algorithm

Grover's algorithm provides a quadratic speedup on unstructured search:

- The 256-bit PRNG seed becomes effectively **128 bits** under Grover's algorithm
- This is considered **quantum-resistant** (comparable to AES-128 post-quantum security)
- The full ~587-bit combined keyspace reduces to ~293 effective bits
- The seed is no longer the weakest link; other components (wheel selection, positions) are now cheaper targets

### Shor's Algorithm

Shor's algorithm does not apply. The system uses no RSA, elliptic curve, or discrete logarithm primitives.

## Attack Procedure

A practical attack against Enegma-Plus would proceed in phases:

1. **Crack the PRNG seed.** Use Grover's search (quantum) or GPU brute force (classical) over 2^256 candidate seeds. For each candidate:
   - Undo the positional shuffle
   - Check for the EOF marker at the padding boundary (requires `inner_seed` to compute the encrypted marker; without it, this rejection test no longer works)
   - If found, the seed is recovered
2. **Strip the outer layers.** Remove the positional shuffle, frequency padding, and PRNG overlay to expose bare Enigma ciphertext.
3. **Break the Enigma core.** The inner seed (`inner_seed`) adds per-character PRNG-derived wheel offsets directly into the Enigma core. Even after stripping outer layers, the attacker must jointly brute-force the inner seed (~255 bits) and the Enigma key settings (~63 bits).

## Recommendations to Harden

1. **~~Increase seed to 256 bits.~~** Done. Seeds are now 256 bits, giving 128 effective bits under Grover's algorithm.
2. **~~Use a proper KDF.~~** Done. All PRNG functions now use HKDF (RFC 5869) with a fixed application salt and domain-separated `info` parameters, replacing the ad-hoc SHA-256 hash chain.
3. **~~Derive independent keys per layer.~~** Done. Four independent 256-bit seeds (`prng_seed`, `shuffle_seed`, `eof_seed`, `inner_seed`) plus HKDF `info`-level domain separation per function.
4. **~~Integrate the seed into the cipher.~~** Done. A 4th independent seed (`inner_seed`) now generates per-character wheel position offsets via `_generate_wheel_offsets()`, weaving PRNG values directly into the Enigma core. Even with outer layers stripped, the Enigma ciphertext is entangled with the inner seed.
5. **~~Encrypt the EOF marker.~~** Done. The EOF marker is now encrypted under `inner_seed` before embedding, eliminating the fast rejection oracle (see §5 above).
6. **~~Add authentication.~~** Done. An HMAC-SHA256 tag (derived from all seeds via HKDF with `b"enegma-hmac-auth"` domain separation) is appended to every ciphertext when seeds are present. Tampered ciphertext is rejected before any decryption occurs.

## Context

Enegma-Plus is an educational and recreational cipher system. It is not designed for protecting classified or sensitive data. The analysis above is provided to inform users of the system's limitations and to guide future improvements.
