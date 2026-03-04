# Enegma

A 3-wheel Enigma-style cipher engine in Python, available in two variants:
a standard version faithful to the original Enigma design, and an enhanced
"plus" version with modern improvements.

## Files

| File | Description |
|------|-------------|
| `enegma.py` | Standard Enigma-style engine |
| `enegma-plus.py` | Enhanced engine with chaining, plugboard, message key, and text prep |
| `bombe.py` | Crib-based brute force cracker (works with standard engine) |
| `make-enegma-plus-codebook.py` | Generate yearly codebooks with daily keys |
| `wheels.json` | CSPRNG-generated rotor wirings and reflector (16 wheels) |
| `Makefile` | `make test` runs the test suite for enegma-plus.py |

## Standard Engine (`enegma.py`)

Faithful to the original Enigma design. Self-reciprocal — encoding with the
same settings decodes the message. No separate decode step needed.

### Usage

```bash
# Encode
python3 enegma.py "HELLOWORLD" 0 0 0

# Decode (same command — self-reciprocal)
python3 enegma.py "JRDWWKROOD" 0 0 0

# File I/O
python3 enegma.py --in plain.txt --out cipher.txt 7 14 22
```

### Arguments

```
python3 enegma.py <text> W1 W2 W3 [--in FILE] [--out FILE]

  text    Text to encode/decode
  W1-W3   Starting positions for each wheel (0-25)
  --in    Read input from file instead of command line
  --out   Write output to file instead of stdout
```

## Enhanced Engine (`enegma-plus.py`)

Adds five improvements over the standard engine.

### Usage

```bash
# Encode (handles punctuation, numbers, and spaces automatically)
# W1 W2 W3 are the daily key — a random per-message key is generated automatically
python3 enegma-plus.py "Attack at 0300, sector 5." 7 14 22

# Encoding the same message twice produces different ciphertext each time
python3 enegma-plus.py "HELLO" 7 14 22   # → SRNNXOOANF...
python3 enegma-plus.py "HELLO" 7 14 22   # → EQQKQAZGFQ... (different)

# Decode (requires -d flag, same daily key)
python3 enegma-plus.py "SRNNXOOANF..." 7 14 22 -d

# Select wheels from the kit (16 available, pick 3 in any order)
python3 enegma-plus.py "HELLO WORLD" 7 14 22 --wh "5 12 3"
python3 enegma-plus.py "CIPHERTEXT" 7 14 22 -d --wh "5 12 3"

# With plugboard
python3 enegma-plus.py "HELLO WORLD" 7 14 22 --pb "AN BY CW DI EQ"

# Decode with plugboard
python3 enegma-plus.py "XYZABC..." 7 14 22 -d --pb "AN BY CW DI EQ"

# All options combined
python3 enegma-plus.py "Attack at dawn." 7 14 22 --wh "16 8 11" --pb "AN BY CW"
python3 enegma-plus.py "CIPHERTEXT" 7 14 22 -d --wh "16 8 11" --pb "AN BY CW"

# File I/O
python3 enegma-plus.py --in plain.txt --out cipher.txt 7 14 22 --wh "5 12 3" --pb "AN BY"
python3 enegma-plus.py --in cipher.txt --out plain.txt 7 14 22 -d --wh "5 12 3" --pb "AN BY"
```

### Arguments

```
python3 enegma-plus.py <text> W1 W2 W3 [-d] [--in FILE] [--out FILE] [--pb PAIRS] [--wh WHEELS]

  text    Text to encode/decode
  W1-W3   Daily key: starting positions for each wheel (0-25)
  -d      Decode mode (required for decoding)
  --in    Read input from file
  --out   Write output to file
  --pb    Plugboard letter pairs (e.g. "AN BY CW DI EQ FL GT HX KP MZ")
  --wh    Select 3 wheels from the kit by number (e.g. "5 12 3"). Default: "1 2 3"
  --cb    Use a codebook for daily key (see Codebooks below)
  --date  Override today's date for codebook lookup (YYYY-MM-DD)
```

## Codebooks

A codebook contains a unique daily key for every day of the year. Both
sender and receiver must have the same codebook. This replaces the need
to manually specify wheel selection, positions, and plugboard on the
command line.

### Generating a codebook

```bash
python3 make-enegma-plus-codebook.py --year 2026
```

This creates `enegma-plus-codebook-2026.json` with 365 (or 366) entries,
one per day. Each daily key is generated via CSPRNG and contains:

- **wheels** — 3 wheels selected from the kit of 16 (no repeats)
- **positions** — 3 starting positions (0-25)
- **plugboard** — 10 letter pairs

Example entry:
```json
"2026-01-01": {
  "wheels": [12, 5, 10],
  "positions": [8, 11, 20],
  "plugboard": "SP HC XU IB NG RJ FK DZ QV AL"
}
```

### Using a codebook

```bash
# Auto-detect codebook for current year (looks for enegma-plus-codebook-YYYY.json)
python3 enegma-plus.py "Attack at dawn." --cb
python3 enegma-plus.py "CIPHERTEXT" --cb -d

# Specify codebook path explicitly
python3 enegma-plus.py "Hello World" --cb enegma-plus-codebook-2026.json

# Use a different date's key (e.g. to decode a message from yesterday)
python3 enegma-plus.py "CIPHERTEXT" --cb -d --date 2026-03-03
```

When `--cb` is used, the engine automatically loads the wheel selection,
starting positions, and plugboard for the current date (or the date
specified with `--date`). No need to provide W1, W2, W3, `--wh`, or
`--pb` on the command line.

### Codebook not found

If the codebook file is missing or has no entry for the requested date,
the engine prints a warning and falls back to command-line settings:

```bash
# Codebook missing — falls back to manual settings
python3 enegma-plus.py "Hello" 7 14 22 --cb nonexistent.json
# WARNING: Codebook not found: nonexistent.json
# Falling back to command-line settings.

# Codebook missing, no manual settings — error
python3 enegma-plus.py "Hello" --cb nonexistent.json
# ERROR: No codebook found. Provide W1 W2 W3 on command line.
```

### Security notes

- Distribute codebooks securely — anyone with the codebook can decrypt
  all traffic for the year
- Generate a new codebook each year
- The per-message key (CSPRNG-generated, encrypted in the first 3
  characters) means that even with the same daily key, each message
  produces unique ciphertext
- Destroy expired codebooks

## Bombe Cracker (`bombe.py`)

Brute-force attack using a known-plaintext crib. Tests all 17,576 rotor
combinations against the standard engine.

```bash
# Crack with a crib at the start of the message
python3 bombe.py "JRDWWKROOD" "HELLO"

# Crib at a specific position
python3 bombe.py "JRDWWKROOD" "WORLD" 5
```

## Testing

```bash
make test
```

Runs 16 tests covering: round-trip encode/decode, random message keys,
plugboard, German text preparation, chaining avalanche, long messages,
file I/O, input validation, message key format, wheel selection,
wheel ordering, wrong-wheel rejection, invalid wheel errors, and
verification that all 16 wheels are functional.

## Differences: Standard vs Plus

| Feature | Standard (`enegma.py`) | Plus (`enegma-plus.py`) |
|---------|----------------------|------------------------|
| **Self-reciprocal** | Yes — same settings encode and decode | No — requires `-d` flag to decode |
| **Wheel kit** | Fixed 3 wheels | 16 wheels in kit, choose any 3 in any order via `--wh` |
| **Per-message key** | None — W1/W2/W3 directly encrypt the message | Yes — random key generated via CSPRNG, encrypted at the daily key positions and prepended to ciphertext |
| **Chaining** | None — each position is an independent substitution | Yes — each character's encryption depends on previous ciphertext, creating an avalanche effect |
| **Plugboard** | None | Optional via `--pb` — swaps letter pairs before and after rotor processing |
| **Text preparation** | Letters only, non-alpha characters pass through unchanged | Converts spaces, punctuation, and numbers to codes before encryption |
| **Frequency analysis resistance** | Weak — output frequencies mirror input frequencies at each rotor state | Stronger — chaining disrupts position-independent frequency analysis |
| **Error tolerance** | High — a garbled character only affects itself | Low — a garbled character corrupts all subsequent decryption |

### Per-message key indicator

Each encryption generates a fresh random message key (3 rotor positions)
using Python's `secrets` module (CSPRNG). This means encrypting the same
plaintext twice with the same daily key produces different ciphertext
each time.

The message key is communicated to the recipient by encrypting it at the
daily key positions and prepending it to the ciphertext. This follows the
post-1940 German procedure:

**Encoding:**
1. Generate 3 random positions (message key) via CSPRNG
2. Set rotors to W1, W2, W3 (daily key from command line)
3. Encrypt the 3-letter message key → first 3 characters of output
4. Reset rotors to the message key positions
5. Encrypt the message body → remaining characters of output

**Decoding:**
1. Set rotors to W1, W2, W3 (daily key)
2. Decrypt first 3 characters → recover the message key
3. Reset rotors to the recovered message key positions
4. Decrypt the remaining ciphertext

The daily key (W1, W2, W3, wheel selection via --wh, and optionally --pb)
is shared between sender and receiver. Only the per-message key changes
with each message.

### Chaining explained

In the standard engine, changing one plaintext character only changes one
ciphertext character. In the plus engine, each character's encryption uses
the previous ciphertext character as an offset, so changing one character
avalanches through the entire remaining ciphertext:

```
Standard:  ATTACKATDAWN → JRDWWKROOD...
           XTTACKATDAWN → YRDWWKROOD...  (only first char differs)

Plus:      ATTACKATDAWN → BMZZYIXYBVCI
           XTTACKATDAWN → GPVLWWOUNHDQ  (everything differs)
```

### Text preparation

The plus engine converts non-alphabetic characters to letter codes before
encryption and restores them on decoding. Codes use a `QQ` prefix to avoid
ambiguity with normal text (QQ virtually never appears in natural language):

| Character | Code |
|-----------|------|
| Space | `QQX` |
| `.` | `QQJ` |
| `,` | `QQZ` |
| `?` | `QQF` |
| `(` | `QQK` |
| `)` | `QQR` |
| `:` | `QQD` |
| `;` | `QQS` |
| `'` | `QQA` |
| `-` | `QQH` |

Numbers are spelled out in German:

| Digit | Code |
|-------|------|
| 0 | `NULL` |
| 1 | `EINS` |
| 2 | `ZWO` |
| 3 | `DREI` |
| 4 | `VIER` |
| 5 | `FUENF` |
| 6 | `SECHS` |
| 7 | `SIEBEN` |
| 8 | `ACHT` |
| 9 | `NEUN` |

Decoded output is uppercase since letter case is not preserved by the cipher.

### Plugboard

The plugboard swaps pairs of letters before the signal enters the rotors and
again after it exits. Each letter can appear in at most one pair. Unpaired
letters pass through unchanged. The same `--pb` setting must be used for
both encoding and decoding.

### Wheel kit

The wheel kit contains 16 rotors in `wheels.json`, numbered 1-16. The `--wh`
flag selects which 3 to use and in what order. Wheel order matters — wheels
5-12-3 produces different ciphertext than 3-12-5.

With 16 wheels choosing 3 in order, that's 16 x 15 x 14 = 3,360 possible
wheel arrangements, before considering starting positions (x 26³ = 17,576)
or plugboard settings. This gives a base key space of ~59 million
configurations from wheel selection and positions alone.

Wheels can be reused in different positions (e.g., `--wh "5 5 5"`) though
using distinct wheels is stronger.

## Wheel Configuration

All 16 rotors and the reflector are defined in `wheels.json`. Each rotor is a
permutation of 0-25 generated using a cryptographically secure random number
generator (`secrets` module). The reflector is an involution (R(R(x)) = x)
with fixed points, allowing letters to encrypt to themselves — a fix for
a known weakness in the original Enigma design where a letter could never
encrypt to itself.
