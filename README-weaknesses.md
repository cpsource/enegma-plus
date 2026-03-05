# Enegma-Plus: Known Weaknesses and Attack Vectors

## Keyspace Summary

| Component | Search Space | Effective Bits |
|---|---|---|
| Wheel selection (3 of 16) | 3,360 | ~11.7 |
| Wheel positions (26^3) | 17,576 | ~14.1 |
| Plugboard (10 pairs) | ~150 billion | ~37.2 |
| PRNG seed (2^255 to 2^256) | ~2^256 | ~255 |
| Per-message key (26^3) | 17,576 | ~14.1 |
| **Combined** | | **~332** |

## Classical Attacks

### 1. Enigma Core is a Polyalphabetic Substitution

The underlying cipher is a 3-wheel Enigma variant with chaining. Without the PRNG overlay, it is vulnerable to the same known-plaintext attacks that broke WWII Enigma: cribs, Banburismus, and bombe-style elimination. Chaining improves diffusion but does not change the algebraic structure.

### 2. PRNG Seed is a Single Point of Failure

The shuffle, frequency padding, PRNG overlay, and EOF marker all derive from three 256-bit seeds. Cracking the seed collapses three protective layers at once, reducing the problem to bare Enigma.

### 3. SHA-256 Hash Chain is Fast

The PRNG uses iterated `sha256(previous_block)` with no key stretching. An attacker can evaluate candidate seeds at hardware speed. There is no equivalent of PBKDF2 or Argon2 to impose a cost floor per guess.

At approximately 1 billion SHA-256 evaluations per second per GPU, the 2^256 seed space is computationally infeasible to brute-force classically.

### 4. Known-Plaintext Exposure

If an attacker knows even a few characters of plaintext and their positions, they can recover PRNG stream values at those offsets and work backward through SHA-256 blocks to test candidate seeds.

Common cribs for this system include document headers, repeated phrases ("ARTICLE", "SECTION"), dates, and military conventions.

### 5. EOF Marker as an Oracle

The 8-character EOF marker derived from the seed exists inside every encrypted message. For each candidate seed, the attacker can undo the shuffle and check whether the marker appears at the expected boundary. This turns seed cracking into a fast rejection test without needing any known plaintext.

### 6. Layers are Separable

The PRNG overlay, positional shuffle, and Enigma core operate independently. An attacker who defeats the outer layers (by cracking the seed) faces only the Enigma core, which has roughly 63 bits of key material and is vulnerable to classical cryptanalytic techniques.

## Quantum Attacks

### Grover's Algorithm

Grover's algorithm provides a quadratic speedup on unstructured search:

- The 256-bit PRNG seed becomes effectively **128 bits** under Grover's algorithm
- This is considered **quantum-resistant** (comparable to AES-128 post-quantum security)
- The full ~332-bit combined keyspace reduces to ~166 effective bits
- The seed is no longer the weakest link; other components (wheel selection, positions) are now cheaper targets

### Shor's Algorithm

Shor's algorithm does not apply. The system uses no RSA, elliptic curve, or discrete logarithm primitives.

## Attack Procedure

A practical attack against Enegma-Plus would proceed in phases:

1. **Crack the PRNG seed.** Use Grover's search (quantum) or GPU brute force (classical) over 2^256 candidate seeds. For each candidate:
   - Undo the positional shuffle
   - Check for the EOF marker at the padding boundary
   - If found, the seed is recovered
2. **Strip the outer layers.** Remove the positional shuffle, frequency padding, and PRNG overlay to expose bare Enigma ciphertext.
3. **Break the Enigma core.** Apply known-plaintext bombe-style attacks against the remaining ~63 bits of wheel selection, positions, and plugboard (this step is unchanged). With cribs, much of this space collapses quickly.

## Recommendations to Harden

1. **~~Increase seed to 256 bits.~~** Done. Seeds are now 256 bits, giving 128 effective bits under Grover's algorithm.
2. **Use a proper KDF.** Replace the raw hash chain with HKDF or iterate many rounds to impose a cost floor on brute-force evaluation.
3. **Derive independent keys per layer.** Do not use one seed for shuffle, overlay, and EOF marker. Use domain-separated derivations from a master key.
4. **Integrate the seed into the cipher.** The PRNG overlay is layered on top of Enigma and can be attacked separately. A tighter integration would force an attacker to solve both simultaneously.
5. **Add authentication.** An HMAC or similar construct would detect tampering and prevent an attacker from using decryption attempts as an oracle.

## Context

Enegma-Plus is an educational and recreational cipher system. It is not designed for protecting classified or sensitive data. The analysis above is provided to inform users of the system's limitations and to guide future improvements.
