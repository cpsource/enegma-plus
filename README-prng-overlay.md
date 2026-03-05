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
  "prng_seed": 57896044618658097...,
  "shuffle_seed": 57896044618658097...,
  "eof_seed": 57896044618658097...,
  "inner_seed": 57896044618658097...
}
```

### Encryption

1. Encrypt the message normally through the Enigma rotors
2. Generate a PRNG stream from the daily seed (HKDF, RFC 5869)
3. For each ciphertext character, add the corresponding PRNG value mod 26

```python
import hashlib, hmac

_HKDF_SALT = b"enegma-plus-v2-hkdf"

def sha256_prng(seed, count):
    """Generate count values (0-25) via HKDF (RFC 5869)."""
    ikm = seed.to_bytes(32, 'big')
    prk = hmac.new(_HKDF_SALT, ikm, hashlib.sha256).digest()  # Extract
    # Expand: produce `count` bytes with domain-specific info
    n = (count + 31) // 32
    okm, prev = b"", b""
    for i in range(1, n + 1):
        prev = hmac.new(prk, prev + b"enegma-prng-stream" + bytes([i]), hashlib.sha256).digest()
        okm += prev
    return [b % 26 for b in okm[:count]]

# After Enigma encryption produces ciphertext
stream = sha256_prng(daily_seed, len(enigma_ciphertext))

output = ""
for i, c in enumerate(enigma_ciphertext):
    val = ord(c) - ord('A')
    fuzzed = (val + stream[i]) % 26
    output += chr(fuzzed + ord('A'))
```

### Decryption

The recipient has the same seed, so they generate the same PRNG stream
and subtract:

```python
stream = sha256_prng(daily_seed, len(received_text))

enigma_ciphertext = ""
for i, c in enumerate(received_text):
    val = ord(c) - ord('A')
    unfuzzed = (val - stream[i]) % 26
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

## CLI Usage

```bash
# Encrypt with PRNG overlay (seed provided directly)
enegma-plus.py "HELLO WORLD" 7 14 22 --prng-seed 839274610583

# Decrypt
enegma-plus.py -d "CIPHERTEXT" 7 14 22 --prng-seed 839274610583

# With codebook (seed loaded automatically from daily entry)
enegma-plus.py "HELLO WORLD" --cb
```

## Implementation Notes

- The PRNG uses **HKDF (RFC 5869)** with HMAC-SHA256. Each seed is
  passed through HKDF-Extract (with a fixed application salt) to derive
  a pseudorandom key (PRK), then HKDF-Expand generates output bytes
  using domain-specific `info` parameters. Each output byte mod 26
  gives one value. This is deterministic, standards-compliant, and
  pure Python (stdlib `hmac` + `hashlib`, no external dependencies).
- The daily seeds are generated via `secrets.randbits(256) | (1 << 255)`
  in the codebook generator, ensuring all seeds are in the range
  [2^255, 2^256). Four seeds are stored per daily entry: `prng_seed`,
  `shuffle_seed`, `eof_seed`, and `inner_seed`.
- The overlay is applied after Enigma encryption (including the 3-char
  message key indicator) and removed before Enigma decryption (outermost
  layer).
- CLI flags: `--prng-seed`, `--shuffle-seed`, `--eof-seed`, and
  `--inner-seed` to provide seeds directly. When using `--cb` (codebook
  mode), seeds are loaded automatically from the daily entry if present.
  CLI flags override codebook seeds.
- The PRNG stream is deterministic — both sender and receiver produce
  identical streams from the same seed.

## Inner PRNG-Wheel Integration

In addition to the outer PRNG overlay, an independent 4th seed
(`inner_seed`) integrates PRNG values directly into the Enigma core's
per-character wheel positions.

### How it works

For each alphabetic character, `_generate_wheel_offsets()` produces a
3-tuple of offsets (0-25) from the inner seed's HKDF-derived stream.
These offsets are added to the current wheel positions before passing
them to `encode_char()`:

```python
eff_pos = [(positions[j] + w_off[j]) % 26 for j in range(3)]
```

The actual wheel positions continue to be mutated by `step_wheels()`
normally — the PRNG offsets are purely additive. Since both encode and
decode use the same deterministic PRNG stream, the Enigma involution
property is preserved.

### Why a separate seed

The inner seed is independent of the three outer-layer seeds
(`prng_seed`, `shuffle_seed`, `eof_seed`). This means even if an
attacker cracks the EOF seed via the EOF marker oracle and strips all
outer layers, the Enigma ciphertext is still entangled with the inner
seed. The attacker must jointly brute-force `inner_seed` (~255 bits)
and the Enigma key settings (~63 bits).

### PRNG stream alignment

The indicator (3 alpha chars) uses PRNG offsets starting at index 0.
The message body uses offsets starting at index 3. This ensures the
streams align identically for encode and decode.
