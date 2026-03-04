# PRNG Stream Overlay

## The Idea

Add a pseudorandom number generator (PRNG) seeded from the codebook as
a second encryption layer. After the Enigma rotor cipher produces
ciphertext, combine each character with the PRNG output to flatten any
residual frequency patterns.

This is essentially layering a **stream cipher** on top of the rotor
cipher.

## How It Works

### Codebook entry with daily seed

```json
"2026-03-04": {
  "wheels": [12, 5, 10],
  "positions": [8, 11, 20],
  "plugboard": "SP HC XU IB NG RJ FK DZ QV AL",
  "prng_seed": 839274610583
}
```

### Encryption

1. Encrypt the message normally through the Enigma rotors
2. Initialize the PRNG with the daily seed
3. For each ciphertext character, generate one PRNG value and add mod 26

```python
import secrets

# After Enigma encryption produces ciphertext
prng = seeded_generator(daily_seed)

output = ""
for c in enigma_ciphertext:
    val = ord(c) - ord('A')
    noise = next(prng) % 26
    fuzzed = (val + noise) % 26
    output += chr(fuzzed + ord('A'))
```

### Decryption

The recipient has the same seed, so they generate the same PRNG stream
and subtract:

```python
prng = seeded_generator(daily_seed)

enigma_ciphertext = ""
for c in received_text:
    val = ord(c) - ord('A')
    noise = next(prng) % 26
    unfuzzed = (val - noise) % 26
    enigma_ciphertext += chr(unfuzzed + ord('A'))

# Then decrypt through Enigma rotors as normal
```

## Why Mod 26, Not XOR

Enigma operates on letters (values 0-25), not bytes (0-255). Bitwise
XOR would require converting to a binary representation first, changing
the message format. Addition mod 26 stays in the letter domain:

```
Enigma output:  H (7)
PRNG value:     19
Combined:       (7 + 19) % 26 = 0 → A

Decryption:     A (0)
Same PRNG:      19
Recovered:      (0 - 19) % 26 = 7 → H
```

Every output letter is equally likely regardless of the Enigma output's
distribution, because adding a uniform random value mod 26 produces a
uniform result.

## Why This Flattens Frequencies

Without the overlay, Enigma ciphertext may retain statistical patterns,
especially in short messages or if the rotor settings are weak. The PRNG
stream adds a uniform offset to each character:

```
P(output = X) = sum over all Y of P(enigma = Y) * P(prng = X - Y mod 26)
```

If the PRNG output is uniformly distributed mod 26, then:

```
P(output = X) = 1/26   for all X
```

This holds regardless of the Enigma output distribution. The frequency
is perfectly flat.

## PRNG Quality

The strength of this layer depends entirely on the PRNG.

### Weak PRNGs (educational / historical interest)

| Generator | Period | Security |
|-----------|--------|----------|
| Linear Congruential (LCG) | 2^32 - 2^64 | Trivially breakable — full state recoverable from a few outputs |
| Linear Feedback Shift Register (LFSR) | 2^n - 1 | Breakable via Berlekamp-Massey algorithm with 2n output bits |
| Polynomial (e.g., x³ + 2x + 1 mod p) | Varies | Depends on polynomial; many are breakable with algebraic techniques |

A weak PRNG still forces an attacker to solve two problems — the rotor
cipher and the PRNG — but a determined adversary can peel off the PRNG
layer first if the generator is weak.

### Strong PRNGs (recommended for real security)

| Generator | Notes |
|-----------|-------|
| `secrets.token_bytes()` | Python CSPRNG, backed by OS entropy. Not seedable — produces different output each time |
| ChaCha20 | Seedable CSPRNG. Given a 256-bit seed, produces a deterministic but cryptographically secure stream |
| AES-CTR | AES in counter mode as a PRNG. Hardware accelerated on modern CPUs |
| HMAC-DRBG | NIST-approved deterministic random bit generator |

For the codebook use case, the PRNG must be **seedable** (both parties
produce the same stream from the same seed). This rules out
`secrets.token_bytes()` and requires a deterministic CSPRNG like
ChaCha20 or AES-CTR.

### Middle ground: polynomial PRNG for the Enigma aesthetic

If the goal is to stay in the spirit of the Enigma era while adding
some stream cipher protection:

```python
def poly_prng(seed, modulus=2**31 - 1):
    """Simple polynomial PRNG: x_{n+1} = (a*x^3 + b*x^2 + c*x + d) mod p"""
    a, b, c, d = 31, 17, 7, 3
    x = seed % modulus
    while True:
        x = (a * x**3 + b * x**2 + c * x + d) % modulus
        yield x
```

This is breakable by a sophisticated adversary but adds meaningful
complexity on top of the rotor cipher for casual analysis.

## Interaction with Existing Features

### Chaining

Chaining and the PRNG overlay are complementary:
- **Chaining** makes each rotor output depend on previous ciphertext
  (diffusion within the Enigma layer)
- **PRNG overlay** adds a uniform noise layer on top (frequency
  flattening)

Both can operate simultaneously. The PRNG is applied after chaining
has already occurred.

### Per-message key indicator

The 3-character encrypted key indicator should also be overlaid with
the PRNG stream (using the first 3 PRNG values). This prevents
frequency analysis of the indicator characters across many messages.

### Plugboard

The frequency-aware plugboard ([README-frequency.md](README-frequency.md))
becomes less critical with a PRNG overlay, since the overlay already
flattens the output distribution. However, a frequency-aware plugboard
still helps in the Enigma layer itself, making the rotor cipher harder
to break independently.

## Security Analysis

### Attacker must break both layers

To recover plaintext, an attacker needs to:
1. Recover the PRNG stream (requires the seed or breaking the PRNG)
2. Break the Enigma rotor cipher (requires key settings)

Neither layer alone reveals plaintext. Even if the attacker breaks the
PRNG, they still face the full Enigma cipher. Even if they break the
Enigma cipher, the PRNG overlay scrambles the output.

### With a strong PRNG, the overlay alone is sufficient

If ChaCha20 or AES-CTR is used, the PRNG overlay is a modern stream
cipher that is independently secure. The Enigma layer becomes defense
in depth — an inner layer that adds complexity but is not relied upon.

### With a weak PRNG, the combination is still stronger than either alone

A weak PRNG can be broken, but the attacker must then also break the
Enigma cipher. The two layers multiply the attacker's work.

## Proposed CLI

```bash
# Encrypt with PRNG overlay (seed provided directly)
enegma-plus.py "HELLO WORLD" 7 14 22 --prng-seed 839274610583

# Decrypt
enegma-plus.py -d "CIPHERTEXT" 7 14 22 --prng-seed 839274610583

# With codebook (seed loaded automatically from daily entry)
enegma-plus.py "HELLO WORLD" --cb

# Choose PRNG type (default: chacha20)
enegma-plus.py "HELLO WORLD" 7 14 22 --prng-seed 839274610583 --prng-type poly
enegma-plus.py "HELLO WORLD" 7 14 22 --prng-seed 839274610583 --prng-type chacha20
```

## Implementation Notes

- The PRNG uses a **SHA-256 hash chain** seeded from a 64-bit daily
  seed. The seed is packed as an 8-byte big-endian integer, then
  repeatedly hashed with SHA-256. Each 32-byte hash block yields 32
  values (each byte mod 26). This is deterministic and cryptographically
  strong — pure Python, no external dependencies.
- The daily seed is generated via `secrets.randbits(64)` in the codebook
  generator and stored as the `prng_seed` field in each daily entry.
- The overlay is applied after Enigma encryption (including the 3-char
  message key indicator) and removed before Enigma decryption (outermost
  layer).
- CLI flag: `--prng-seed <integer>` to provide a seed directly. When
  using `--cb` (codebook mode), the seed is loaded automatically from
  the daily entry if present. A CLI `--prng-seed` overrides the codebook
  seed.
- The PRNG stream is deterministic — both sender and receiver produce
  identical streams from the same seed.
