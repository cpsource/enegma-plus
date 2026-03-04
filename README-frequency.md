# Frequency-Aware Plugboard

## The Problem

Even with chaining, short messages may not fully diffuse letter frequencies
through the ciphertext. English text has a very uneven frequency distribution:

| Rank | Letters | Approx. frequency |
|------|---------|-------------------|
| High | E T A O I N S H R D | 6-13% each |
| Mid | L U C M W F G Y P B | 1.5-4% each |
| Low | V K J X Q Z | < 1% each |

If these frequencies leak into the ciphertext, an attacker can use
statistical analysis to recover plaintext — the same attack that broke
the original Enigma.

## Current Behavior

The codebook generator (`make-enegma-plus-codebook.py`) pairs letters
randomly for the plugboard. This means high-frequency letters are just
as likely to be paired with other high-frequency letters as with low-frequency
ones, doing nothing to flatten the distribution.

Example random pairing:
```
ET AO IN SH — high paired with high (no flattening)
```

## Proposed: Frequency-Biased Plugboard

Pair high-frequency letters with low-frequency letters to flatten the
distribution entering the rotors.

### Strategy 1: Deterministic Pairing (Simple)

Always pair by inverse frequency rank:

```
E↔Z  T↔Q  A↔X  O↔J  I↔K  N↔V  S↔B  H↔P  R↔Y  D↔G
```

**Pro:** Maximum frequency flattening — the most common letter (E, ~13%)
swaps with the rarest (Z, <0.1%).

**Con:** Completely predictable. An attacker who knows the strategy can
guess all 10 pairs immediately, reducing the effective plugboard key
space to 1.

### Strategy 2: Frequency-Biased Random (Recommended)

Divide letters into a high-frequency group and a low-frequency group,
then randomly pair across groups:

```
High group: E T A O I N S H R D L U  (top 12)
Low group:  C M W F G Y P B V K J X Q Z  (bottom 14)
```

For each of the 10 plugboard pairs:
1. Pick a random letter from the high group
2. Pick a random letter from the low group
3. Pair them
4. Remove both from their groups

```python
import secrets

HIGH = list("ETAOINSHRDLU")
LOW  = list("CMWFGYPBVKJXQZ")

pairs = []
for _ in range(10):
    h = HIGH.pop(secrets.randbelow(len(HIGH)))
    l = LOW.pop(secrets.randbelow(len(LOW)))
    pairs.append(f"{h}{l}")
```

This produces pairings like:
```
AV TK EJ OX NP SZ HG DW IB RC  — high paired with low (flattened)
```

**Pro:** Every pair crosses the frequency divide, flattening the
distribution. The specific pairings are still random, preserving
unpredictability.

**Con:** An attacker who knows the strategy knows that each pair
contains one high and one low letter. This reduces the search space
compared to fully random pairing, but still leaves significant
uncertainty in which specific letters are paired.

### Strategy 3: Weighted Random (Most Flexible)

Assign a probability weight that biases toward cross-frequency pairing
without enforcing it. Higher weight = more likely to pair across groups.

```python
# 80% chance of cross-frequency pairing, 20% chance of random
if secrets.randbelow(100) < 80:
    # pair high with low
else:
    # pair randomly from remaining
```

**Pro:** Unpredictable — an attacker cannot be certain which strategy
was used for any given pair.

**Con:** Less consistent flattening than Strategy 2.

## How Much Does It Help?

### With chaining (long messages)

Chaining already disrupts frequency analysis by making each character's
encryption depend on all previous ciphertext. For messages longer than
~50 characters, chaining provides strong frequency diffusion on its own.
The plugboard adds incremental benefit.

### With chaining (short messages)

For messages under ~20 characters, chaining has not had enough characters
to fully diffuse. A frequency-aware plugboard significantly helps here
by flattening the input distribution before the rotors see it.

### Without chaining (standard engine)

The standard engine has no chaining — each position is an independent
substitution. Frequency-aware plugboard pairing would be very beneficial,
but the standard engine does not support plugboards.

### Quantified example

English text "ATTACK AT DAWN" letter frequencies:
```
A: 4/12 = 33%    T: 3/12 = 25%    C,D,K,N,W: 1/12 each
```

With random plugboard (e.g., A↔B):
- A and B swap, but A is still 33% of input — now B is 33%
- Frequency spike just moves to a different letter

With frequency-aware plugboard (e.g., A↔Z):
- A (33%) swaps with Z (0%) — post-plugboard, Z is 33% and A is 0%
- The rotor now sees Z at 33% instead of A — but the spike persists

**Key insight:** The plugboard alone cannot flatten frequencies — it only
swaps which letters carry the frequency. The real benefit comes from
combining the plugboard with rotor stepping and chaining, which then
scrambles the redistributed frequencies further. The plugboard ensures
the rotors don't always see the same high-frequency letters in the same
positions.

## Impact on Codebook Generator

The change would modify `make-enegma-plus-codebook.py`:

```bash
# Current: fully random plugboard
python3 make-enegma-plus-codebook.py --year 2026

# Proposed: frequency-biased plugboard
python3 make-enegma-plus-codebook.py --year 2026 --freq-plugboard

# Proposed: choose bias strength
python3 make-enegma-plus-codebook.py --year 2026 --freq-plugboard --bias 80
```

The `--freq-plugboard` flag switches from fully random pairing to
frequency-biased pairing (Strategy 2 by default). The `--bias` flag
sets the cross-frequency probability for Strategy 3 (default 100 =
always cross-frequency, i.e., Strategy 2).

## Recommendation

Use **Strategy 2** (frequency-biased random) as the default for codebook
generation. It provides consistent frequency flattening while preserving
enough randomness to resist an attacker who knows the strategy. The
trade-off in reduced plugboard search space is worth the improved
resistance to frequency analysis, especially for short messages.

For maximum security against a sophisticated attacker who might deduce
the pairing strategy, use **Strategy 3** with a bias of 70-80%.
