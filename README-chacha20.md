# ChaCha20

## What It Is

ChaCha20 is a stream cipher designed by Daniel Bernstein in 2008 as a
variant of his earlier Salsa20 cipher. It is the standard stream cipher
in TLS 1.3 (as ChaCha20-Poly1305) and is widely used in modern
cryptography.

It takes a 256-bit key, a 96-bit nonce, and a 32-bit block counter,
and produces a stream of pseudorandom bytes. You XOR that stream with
plaintext to encrypt (or with ciphertext to decrypt).

## How It Works

### State matrix

ChaCha20 operates on a 4x4 grid of 32-bit words (512 bits / 64 bytes):

```
cccc cccc cccc cccc    c = constant ("expand 32-byte k")
kkkk kkkk kkkk kkkk    k = key (256 bits = 8 words)
kkkk kkkk kkkk kkkk
bbbb nnnn nnnn nnnn    b = block counter, n = nonce
```

The constants are the ASCII encoding of `"expand 32-byte k"`, split
into four 32-bit little-endian words. This prevents related-key attacks
and ensures no all-zero states.

### Quarter-round

The core mixing operation takes four 32-bit words (a, b, c, d) and
applies:

```
a += b;  d ^= a;  d <<<= 16
c += d;  b ^= c;  b <<<= 12
a += b;  d ^= a;  d <<<= 8
c += d;  b ^= c;  b <<<= 7
```

This uses only three operations: addition, XOR, and bitwise rotation
(ARX construction). No table lookups, no multiplication. This makes it:

- **Constant-time** — no timing side-channels
- **Fast on any CPU** — no need for AES hardware acceleration
- **Simple to implement** — hard to get wrong

### 20 rounds

The quarter-round is applied in alternating patterns:

- **Column rounds**: apply quarter-round to each of the 4 columns
- **Diagonal rounds**: apply quarter-round to each of the 4 diagonals

This alternation is repeated 10 times, giving 20 rounds total. After
all rounds, the final state is added (word-by-word mod 2^32) to the
original state. This addition is critical — without it, the rounds
would be invertible and the cipher would be weaker.

The result is one 64-byte keystream block.

### Stream generation

To produce more keystream, increment the 32-bit block counter and
repeat. This gives 2^32 blocks x 64 bytes = 256 GB of keystream per
key+nonce pair.

## Why It Matters for enegma-plus

The PRNG overlay needs a **seedable CSPRNG** — given the same seed,
both sender and receiver must produce the identical pseudorandom stream.
ChaCha20 is ideal for this:

- Deterministic from key (seed) + nonce
- Cryptographically secure — no known attacks
- Fast in software without hardware acceleration

## What enegma-plus Actually Uses

Instead of ChaCha20, enegma-plus uses **HKDF (RFC 5869)** with
HMAC-SHA256 as its PRNG (`sha256_prng` in `enegma-plus.py`). Each
256-bit seed is passed through HKDF-Extract (with a fixed application
salt) to derive a pseudorandom key, then HKDF-Expand generates output
bytes using domain-specific `info` parameters. Each byte mod 26 gives
one value.

This achieves the same goal — a deterministic, cryptographically strong
stream from a seed — using a standards-compliant construction without
external dependencies.

### Comparison

| | ChaCha20 | HKDF (HMAC-SHA256) |
|---|---|---|
| Speed | ~3x faster | Slower (HMAC does 2 SHA-256 per block) |
| Dependencies | Needs `cryptography` library | Pure Python stdlib (`hmac` + `hashlib`) |
| Output per block | 64 bytes | 32 bytes |
| Security | Purpose-built stream cipher | Standards-compliant KDF (RFC 5869) |
| Domain separation | Manual (different nonces) | Built-in via `info` parameter |
| Constant-time | Yes (by design) | Depends on implementation |

Both are cryptographically strong and deterministic from a seed. The
HKDF approach was chosen to keep enegma-plus dependency-free while
using a well-analyzed, standards-compliant construction.

### Switching to ChaCha20

If actual ChaCha20 is desired, swap in the `cryptography` library:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import struct

def chacha20_prng(seed, count):
    """Generate count values (0-25) from a ChaCha20 stream."""
    # Derive a 256-bit key from the 256-bit seed
    key = seed.to_bytes(32, 'big')
    nonce = b'\x00' * 16  # fixed nonce (one stream per seed)
    cipher = Cipher(algorithms.ChaCha20(key, nonce))
    encryptor = cipher.encryptor()
    # Generate enough random bytes
    raw = encryptor.update(b'\x00' * count)
    return [b % 26 for b in raw]
```

This is a drop-in replacement for `sha256_prng` — same interface, same
deterministic behavior, but using ChaCha20 internally.

## References

- Daniel Bernstein, [ChaCha, a variant of Salsa20](https://cr.yp.to/chacha/chacha-20080128.pdf) (2008)
- RFC 8439: [ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
