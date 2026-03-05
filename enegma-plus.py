#!/usr/bin/env python3
"""Enegma - A 3-wheel Enigma-style cipher engine with chaining."""

import argparse
import datetime
import hashlib
import json
import os
import secrets
import struct
import sys


def sha256_prng(seed, count):
    """Generate `count` values (0-25) from a SHA-256 hash chain CSPRNG.

    Uses HKDF-like expansion: each 32-byte hash block yields 32 values mod 26.
    Deterministic from the seed — both sender and receiver produce the same stream.
    """
    values = []
    block = seed.to_bytes(32, 'big')  # 32-byte (256-bit) seed
    while len(values) < count:
        block = hashlib.sha256(block).digest()
        for byte in block:
            values.append(byte % 26)
            if len(values) >= count:
                break
    return values


def _generate_wheel_offsets(seed, count):
    """Generate per-character wheel position offsets from inner seed.
    Returns list of count 3-tuples: [(w1_off, w2_off, w3_off), ...]
    """
    raw = sha256_prng(seed, count * 3)
    return [(raw[i*3], raw[i*3+1], raw[i*3+2]) for i in range(count)]


def apply_prng_overlay(text, seed):
    """Add PRNG stream mod 26 to each alphabetic character."""
    stream = sha256_prng(seed, sum(1 for c in text if c.isalpha()))
    result = []
    idx = 0
    for c in text:
        if c.isalpha():
            val = ord(c.upper()) - ord('A')
            fuzzed = (val + stream[idx]) % 26
            result.append(chr(fuzzed + ord('A')))
            idx += 1
        else:
            result.append(c)
    return ''.join(result)


def remove_prng_overlay(text, seed):
    """Subtract PRNG stream mod 26 from each alphabetic character."""
    stream = sha256_prng(seed, sum(1 for c in text if c.isalpha()))
    result = []
    idx = 0
    for c in text:
        if c.isalpha():
            val = ord(c.upper()) - ord('A')
            unfuzzed = (val - stream[idx]) % 26
            result.append(chr(unfuzzed + ord('A')))
            idx += 1
        else:
            result.append(c)
    return ''.join(result)



def _sha256_prng_stream(seed):
    """Infinite SHA-256 hash chain yielding raw bytes."""
    block = seed.to_bytes(32, 'big')
    while True:
        block = hashlib.sha256(block).digest()
        yield from block


def _randbelow_from_stream(n, stream):
    """Rejection-sampled uniform random integer in [0, n) from byte stream."""
    if n <= 1:
        return 0
    if n <= 256:
        limit = 256 - (256 % n)
        while True:
            b = next(stream)
            if b < limit:
                return b % n
    else:
        limit = 65536 - (65536 % n)
        while True:
            val = (next(stream) << 8) | next(stream)
            if val < limit:
                return val % n


def apply_positional_permutation(text, seed):
    """Fisher-Yates shuffle: move each character to a pseudorandom position."""
    n = len(text)
    if n <= 1:
        return text
    stream = _sha256_prng_stream(seed)
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = _randbelow_from_stream(i + 1, stream)
        perm[i], perm[j] = perm[j], perm[i]
    output = [''] * n
    for i, c in enumerate(text):
        output[perm[i]] = c
    return ''.join(output)


def remove_positional_permutation(text, seed):
    """Inverse Fisher-Yates: restore each character to its original position."""
    n = len(text)
    if n <= 1:
        return text
    stream = _sha256_prng_stream(seed)
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = _randbelow_from_stream(i + 1, stream)
        perm[i], perm[j] = perm[j], perm[i]
    output = [''] * n
    for i in range(n):
        output[i] = text[perm[i]]
    return ''.join(output)


def _eof_marker(seed):
    """Derive an 8-char EOF marker from seed via domain separation."""
    domain = seed.to_bytes(32, 'big') + b"eof-marker"
    digest = hashlib.sha256(domain).digest()
    return ''.join(chr((b % 26) + ord('A')) for b in digest[:8])


def add_frequency_padding(text, prng_seed):
    """Append EOF marker and pad to perfectly uniform letter frequency."""
    from collections import Counter
    marker = _eof_marker(prng_seed)
    data = text + marker
    counts = Counter(data)
    max_count = max(counts.get(chr(i + ord('A')), 0) for i in range(26))
    padding = []
    for i in range(26):
        letter = chr(i + ord('A'))
        need = max_count - counts.get(letter, 0)
        padding.extend([letter] * need)
    return data + ''.join(padding)


def remove_frequency_padding(text, prng_seed):
    """Find EOF marker and strip it plus all padding after it."""
    marker = _eof_marker(prng_seed)
    idx = text.rfind(marker)
    if idx == -1:
        raise ValueError("Wrong seed or corrupted ciphertext, can't decrypt")
    return text[:idx]


DIGITS = {
    '0': 'NULL', '1': 'EINS', '2': 'ZWO', '3': 'DREI', '4': 'VIER',
    '5': 'FUENF', '6': 'SECHS', '7': 'SIEBEN', '8': 'ACHT', '9': 'NEUN',
}

PUNCT = {
    ' ': 'QQX',
    '.': 'QQJ',
    ',': 'QQZ',
    '?': 'QQF',
    '(': 'QQK',
    ')': 'QQR',
    ':': 'QQD',
    ';': 'QQS',
    "'": 'QQA',
    '-': 'QQH',
}

# Reverse mappings for decode (longest match first)
REVERSE_SUBS = {}
for k, v in sorted(list(PUNCT.items()) + [(d, w) for d, w in DIGITS.items()],
                    key=lambda x: -len(x[1])):
    REVERSE_SUBS[v] = k


def prepare_text(text):
    """Convert plaintext to Enigma-compatible form: letters only, uppercase."""
    result = []
    for c in text:
        if c.isalpha():
            result.append(c.upper())
        elif c in DIGITS:
            result.append(DIGITS[c])
        elif c in PUNCT:
            result.append(PUNCT[c])
    return ''.join(result)


def restore_text(text):
    """Attempt to reverse German abbreviations back to punctuation/numbers."""
    result = []
    i = 0
    while i < len(text):
        matched = False
        # Try longest substitutions first
        for abbr, original in REVERSE_SUBS.items():
            if text[i:i+len(abbr)] == abbr:
                result.append(original)
                i += len(abbr)
                matched = True
                break
        if not matched:
            result.append(text[i])
            i += 1
    return ''.join(result)


def load_wheels(path="wheels.json", wheel_select=None):
    """Load wheels from JSON. wheel_select is a list of 3 wheel numbers (1-16).
    Defaults to [1, 2, 3] if not specified."""
    with open(path) as f:
        data = json.load(f)
    if wheel_select is None:
        wheel_select = [1, 2, 3]
    if len(wheel_select) != 3:
        raise ValueError("Must select exactly 3 wheels")
    wheels = []
    for n in wheel_select:
        key = f"wheel{n}"
        if key not in data:
            raise ValueError(f"Wheel {n} not found in {path}")
        wheels.append(data[key])
    return wheels[0], wheels[1], wheels[2], data["reflector"]


def make_reverse(wheel):
    rev = [0] * len(wheel)
    for i, v in enumerate(wheel):
        rev[v] = i
    return rev


def make_plugboard(pairs_str):
    """Build a plugboard mapping from a string like 'AN BY CW'."""
    pb = list(range(26))
    if not pairs_str:
        return pb
    for pair in pairs_str.upper().split():
        if len(pair) != 2 or not pair.isalpha():
            raise ValueError(f"Invalid plugboard pair: '{pair}'")
        a, b = ord(pair[0]) - ord('A'), ord(pair[1]) - ord('A')
        if pb[a] != a or pb[b] != b:
            raise ValueError(f"Letter used twice in plugboard: '{pair}'")
        pb[a] = b
        pb[b] = a
    return pb


def step_wheels(positions, wheel_sizes):
    """Advance wheels like an odometer. Wheel 1 steps every character,
    wheel 2 steps when wheel 1 wraps, wheel 3 steps when wheel 2 wraps."""
    positions[0] = (positions[0] + 1) % wheel_sizes[0]
    if positions[0] == 0:
        positions[1] = (positions[1] + 1) % wheel_sizes[1]
        if positions[1] == 0:
            positions[2] = (positions[2] + 1) % wheel_sizes[2]


def encode_char(c, wheels, reverses, reflector, positions, plugboard, chain_offset=0, decoding=False):
    if not c.isascii() or not c.isalpha():
        return c

    upper = c.isupper()
    index = ord(c.upper()) - ord('A')
    size = 26

    # Chaining: encode adds offset before core, decode subtracts after core
    if not decoding:
        index = (index + chain_offset) % size

    # Plugboard in
    index = plugboard[index]

    # Forward through wheels 1 -> 2 -> 3
    for i in range(3):
        index = (index + positions[i]) % size
        index = wheels[i][index]
        index = (index - positions[i]) % size

    # Reflector
    index = reflector[index]

    # Reverse through wheels 3 -> 2 -> 1
    for i in range(2, -1, -1):
        index = (index + positions[i]) % size
        index = reverses[i][index]
        index = (index - positions[i]) % size

    # Plugboard out (same mapping — it's symmetric)
    index = plugboard[index]

    if decoding:
        index = (index - chain_offset) % size

    result = chr(index + ord('A'))
    return result.lower() if not upper else result


def _load_args(wheels_path="wheels.json", plugboard_str=None, wheel_select=None):
    """Load wheels and plugboard for testing."""
    wheel1, wheel2, wheel3, reflector = load_wheels(wheels_path, wheel_select)
    wheels = [wheel1, wheel2, wheel3]
    reverses = [make_reverse(w) for w in wheels]
    plugboard = make_plugboard(plugboard_str)
    return wheels, reverses, reflector, plugboard


def _enegma_raw(text, positions, wheels, reverses, reflector, plugboard,
                mode="encode", inner_seed=None, prng_char_offset=0):
    """Low-level encrypt/decrypt without text preparation or message key handling."""
    wheel_sizes = [len(w) for w in wheels]
    output = []
    chain_offset = 0

    # Pre-generate wheel offsets if inner seed is set
    if inner_seed is not None:
        alpha_count = sum(1 for c in text if c.isalpha())
        wheel_offsets = _generate_wheel_offsets(inner_seed, prng_char_offset + alpha_count)
    else:
        wheel_offsets = None

    alpha_idx = 0
    for c in text:
        if c.isalpha():
            step_wheels(positions, wheel_sizes)
            if wheel_offsets is not None:
                w_off = wheel_offsets[prng_char_offset + alpha_idx]
                eff_pos = [(positions[j] + w_off[j]) % 26 for j in range(3)]
            else:
                eff_pos = positions
            out_c = encode_char(c, wheels, reverses, reflector, eff_pos, plugboard, chain_offset, decoding=(mode == "decode"))
            output.append(out_c)
            if mode == "encode":
                chain_offset = ord(out_c.upper()) - ord('A')
            else:
                chain_offset = ord(c.upper()) - ord('A')
            alpha_idx += 1
        else:
            out_c = encode_char(c, wheels, reverses, reflector, positions, plugboard, chain_offset, decoding=(mode == "decode"))
            output.append(out_c)
    return "".join(output)


def _trace(msg, trace=False):
    """Print a trace message to stderr if tracing is enabled."""
    if trace:
        print(f"  [TRACE] {msg}", file=sys.stderr)


def enegma(text, w1, w2, w3, wheels_path="wheels.json", mode="encode", plugboard_str=None, wheel_select=None, trace=False, prng_seed=None, shuffle_seed=None, eof_seed=None, inner_seed=None):
    """Encode or decode text with per-message key indicator.

    Encode: generates a random message key, encrypts it at the daily key
    positions (W1,W2,W3), then encrypts the message at the message key
    positions. Output = 3-char encrypted indicator + ciphertext.

    Decode: decrypts the first 3 characters to recover the message key,
    then decrypts the remaining ciphertext at those positions.
    """
    wheel1, wheel2, wheel3, reflector = load_wheels(wheels_path, wheel_select)
    wheels = [wheel1, wheel2, wheel3]
    reverses = [make_reverse(w) for w in wheels]
    plugboard = make_plugboard(plugboard_str)

    ws = wheel_select or [1, 2, 3]
    _trace(f"Mode: {mode.upper()}", trace)
    _trace(f"Wheels file: {wheels_path}", trace)
    _trace(f"Wheels: {ws[0]}, {ws[1]}, {ws[2]}", trace)
    _trace(f"Daily key positions: {w1}, {w2}, {w3}", trace)
    _trace(f"Plugboard: {plugboard_str or '(none)'}", trace)

    if mode == "encode":
        prepared = prepare_text(text)
        _trace(f"Input text: {text}", trace)
        _trace(f"Prepared text: {prepared}", trace)
        text = prepared

        # Generate random per-message key
        mk = [secrets.randbelow(26) for _ in range(3)]
        mk_letters = ''.join(chr(p + ord('A')) for p in mk)
        _trace(f"Message key (plaintext): {mk_letters} (positions {mk[0]}, {mk[1]}, {mk[2]})", trace)

        # Encrypt the message key at daily key positions (no chaining for indicator)
        indicator_pos = [w1, w2, w3]
        enc_indicator = _enegma_raw(mk_letters, indicator_pos, wheels, reverses, reflector, plugboard, mode="encode", inner_seed=inner_seed, prng_char_offset=0)
        _trace(f"Message key (encrypted): {enc_indicator}", trace)

        # Encrypt the message body at the message key positions
        body_pos = list(mk)
        enc_body = _enegma_raw(text, body_pos, wheels, reverses, reflector, plugboard, mode="encode", inner_seed=inner_seed, prng_char_offset=3)
        _trace(f"Encrypted body: {enc_body}", trace)
        full_output = enc_indicator + enc_body
        _trace(f"Full output: {full_output} ({len(enc_indicator)} indicator + {len(enc_body)} body = {len(full_output)} chars)", trace)

        if prng_seed is not None:
            if shuffle_seed is None or eof_seed is None:
                raise ValueError("shuffle_seed and eof_seed are required when prng_seed is set")
            full_output = apply_prng_overlay(full_output, prng_seed)
            _trace(f"After PRNG overlay: {full_output}", trace)
            full_output = add_frequency_padding(full_output, eof_seed)
            _trace(f"After EOF+padding: {full_output} ({len(full_output)} chars)", trace)
            full_output = apply_positional_permutation(full_output, shuffle_seed)
            _trace(f"After positional shuffle: {full_output}", trace)

        return full_output

    else:
        _trace(f"Input ciphertext: {text} ({len(text)} chars)", trace)

        if prng_seed is not None:
            if shuffle_seed is None or eof_seed is None:
                raise ValueError("shuffle_seed and eof_seed are required when prng_seed is set")
            text = remove_positional_permutation(text, shuffle_seed)
            _trace(f"After removing positional shuffle: {text}", trace)
            text = remove_frequency_padding(text, eof_seed)
            _trace(f"After removing EOF+padding: {text} ({len(text)} chars)", trace)
            text = remove_prng_overlay(text, prng_seed)
            _trace(f"After removing PRNG overlay: {text}", trace)

        # Split indicator (first 3 chars) from body
        enc_indicator = text[:3]
        enc_body = text[3:]
        _trace(f"Encrypted indicator: {enc_indicator}", trace)
        _trace(f"Encrypted body: {enc_body} ({len(enc_body)} chars)", trace)

        # Decrypt indicator at daily key positions to recover message key
        indicator_pos = [w1, w2, w3]
        mk_letters = _enegma_raw(enc_indicator, indicator_pos, wheels, reverses, reflector, plugboard, mode="decode", inner_seed=inner_seed, prng_char_offset=0)

        # Convert message key letters to positions
        mk = [ord(c) - ord('A') for c in mk_letters.upper()]
        _trace(f"Message key (decrypted): {mk_letters} (positions {mk[0]}, {mk[1]}, {mk[2]})", trace)

        # Decrypt body at message key positions
        body_pos = list(mk)
        plaintext = _enegma_raw(enc_body, body_pos, wheels, reverses, reflector, plugboard, mode="decode", inner_seed=inner_seed, prng_char_offset=3)
        _trace(f"Decrypted (raw): {plaintext}", trace)

        result = restore_text(plaintext)
        _trace(f"Decrypted (restored): {result}", trace)

        return result


def load_codebook_key(codebook_path, date_str=None):
    """Load today's key from a codebook file. Returns (w1, w2, w3, plugboard_str, wheel_select) or None."""
    if date_str is None:
        date_str = datetime.date.today().isoformat()
    with open(codebook_path) as f:
        codebook = json.load(f)
    day = codebook.get("days", {}).get(date_str)
    if day is None:
        return None, date_str
    return {
        "w1": day["positions"][0],
        "w2": day["positions"][1],
        "w3": day["positions"][2],
        "plugboard": day["plugboard"],
        "wheels": day["wheels"],
        "prng_seed": day.get("prng_seed"),
        "shuffle_seed": day.get("shuffle_seed"),
        "eof_seed": day.get("eof_seed"),
        "inner_seed": day.get("inner_seed"),
    }, date_str


def find_codebook():
    """Search for a codebook file for the current year."""
    year = datetime.date.today().year
    filename = f"enegma-plus-codebook-{year}.json"
    if os.path.exists(filename):
        return filename
    return None


def format_ciphertext(text):
    """Format ciphertext into 5-char blocks, 10 blocks per line."""
    blocks = [text[i:i+5] for i in range(0, len(text), 5)]
    lines = []
    for i in range(0, len(blocks), 10):
        lines.append(' '.join(blocks[i:i+10]))
    return '\n'.join(lines)


def strip_ciphertext_format(text):
    """Remove whitespace from formatted ciphertext."""
    return ''.join(text.split())


def main():
    parser = argparse.ArgumentParser(description="Enegma cipher engine")
    parser.add_argument("text", nargs="?", help="Text to encode/decode")
    parser.add_argument("w1", nargs="?", type=int, help="Wheel 1 starting position")
    parser.add_argument("w2", nargs="?", type=int, help="Wheel 2 starting position")
    parser.add_argument("w3", nargs="?", type=int, help="Wheel 3 starting position")
    parser.add_argument("-d", action="store_true", help="Decode mode")
    parser.add_argument("--in", dest="infile", help="Input file")
    parser.add_argument("--out", dest="outfile", help="Output file")
    parser.add_argument("--pb", dest="plugboard", help="Plugboard pairs (e.g. 'AN BY CW DI EQ FL GT HX KP MZ')")
    parser.add_argument("--wh", dest="wheels", help="Select 3 wheels from kit by number (e.g. '5 12 3')")
    parser.add_argument("--cb", dest="codebook", nargs="?", const="auto",
                        help="Use codebook for daily key. Optionally specify path (default: auto-detect)")
    parser.add_argument("--date", dest="date", help="Date to use with codebook (YYYY-MM-DD, default: today)")
    parser.add_argument("--trace", action="store_true", help="Print detailed trace of encoding/decoding steps")
    parser.add_argument("--wf", dest="wheels_file", default="wheels.json", help="Path to wheels JSON file (default: wheels.json)")
    parser.add_argument("--prng-seed", dest="prng_seed", type=int, default=None, help="PRNG seed for stream overlay (integer)")
    parser.add_argument("--shuffle-seed", dest="shuffle_seed", type=int, default=None, help="Shuffle seed for positional permutation (integer)")
    parser.add_argument("--eof-seed", dest="eof_seed", type=int, default=None, help="EOF seed for frequency padding (integer)")
    parser.add_argument("--inner-seed", dest="inner_seed", type=int, default=None, help="Inner seed for PRNG-cipher integration (integer)")
    args = parser.parse_args()

    mode = "decode" if args.d else "encode"

    # When --in is used, argparse may consume the first number as text.
    # Detect and shift: if text looks like an int and --in is provided, treat it as w1.
    if args.infile and args.text is not None and args.w3 is None:
        try:
            shifted_w1 = int(args.text)
            args.text = None
            args.w1, args.w2, args.w3 = shifted_w1, args.w1, args.w2
        except ValueError:
            pass

    w1, w2, w3 = args.w1, args.w2, args.w3
    plugboard_str = args.plugboard
    wheel_select = [int(x) for x in args.wheels.split()] if args.wheels else None
    prng_seed = args.prng_seed
    shuffle_seed = args.shuffle_seed
    eof_seed = args.eof_seed
    inner_seed = args.inner_seed

    if args.codebook is not None:
        # Codebook mode
        if args.codebook == "auto":
            cb_path = find_codebook()
            if cb_path is None:
                year = datetime.date.today().year
                print(f"WARNING: No codebook found for {year} (expected enegma-plus-codebook-{year}.json)", file=sys.stderr)
                print("Falling back to command-line settings.", file=sys.stderr)
                if w1 is None or w2 is None or w3 is None:
                    parser.error("No codebook found. Provide W1 W2 W3 on command line.")
            else:
                key, date_str = load_codebook_key(cb_path, args.date)
                if key is None:
                    print(f"WARNING: No key found for {date_str} in {cb_path}", file=sys.stderr)
                    print("Falling back to command-line settings.", file=sys.stderr)
                    if w1 is None or w2 is None or w3 is None:
                        parser.error(f"No codebook key for {date_str}. Provide W1 W2 W3 on command line.")
                else:
                    w1, w2, w3 = key["w1"], key["w2"], key["w3"]
                    plugboard_str = key["plugboard"]
                    wheel_select = key["wheels"]
                    if prng_seed is None and key.get("prng_seed") is not None:
                        prng_seed = key["prng_seed"]
                    if shuffle_seed is None and key.get("shuffle_seed") is not None:
                        shuffle_seed = key["shuffle_seed"]
                    if eof_seed is None and key.get("eof_seed") is not None:
                        eof_seed = key["eof_seed"]
                    if inner_seed is None and key.get("inner_seed") is not None:
                        inner_seed = key["inner_seed"]
                    print(f"Using codebook key for {date_str}", file=sys.stderr)
        else:
            # Explicit codebook path
            if not os.path.exists(args.codebook):
                print(f"WARNING: Codebook not found: {args.codebook}", file=sys.stderr)
                print("Falling back to command-line settings.", file=sys.stderr)
                if w1 is None or w2 is None or w3 is None:
                    parser.error(f"Codebook not found. Provide W1 W2 W3 on command line.")
            else:
                key, date_str = load_codebook_key(args.codebook, args.date)
                if key is None:
                    print(f"WARNING: No key found for {date_str} in {args.codebook}", file=sys.stderr)
                    print("Falling back to command-line settings.", file=sys.stderr)
                    if w1 is None or w2 is None or w3 is None:
                        parser.error(f"No codebook key for {date_str}. Provide W1 W2 W3 on command line.")
                else:
                    w1, w2, w3 = key["w1"], key["w2"], key["w3"]
                    plugboard_str = key["plugboard"]
                    wheel_select = key["wheels"]
                    if prng_seed is None and key.get("prng_seed") is not None:
                        prng_seed = key["prng_seed"]
                    if shuffle_seed is None and key.get("shuffle_seed") is not None:
                        shuffle_seed = key["shuffle_seed"]
                    if eof_seed is None and key.get("eof_seed") is not None:
                        eof_seed = key["eof_seed"]
                    if inner_seed is None and key.get("inner_seed") is not None:
                        inner_seed = key["inner_seed"]
                    print(f"Using codebook key for {date_str}", file=sys.stderr)

    if w1 is None or w2 is None or w3 is None:
        parser.error("Provide W1 W2 W3 on command line, or use --cb for codebook mode.")

    if prng_seed is not None and not (0 <= prng_seed <= 2**256 - 1):
        parser.error("PRNG seed must be between 0 and 2^256-1")

    if shuffle_seed is not None and not (0 <= shuffle_seed <= 2**256 - 1):
        parser.error("Shuffle seed must be between 0 and 2^256-1")

    if eof_seed is not None and not (0 <= eof_seed <= 2**256 - 1):
        parser.error("EOF seed must be between 0 and 2^256-1")

    if inner_seed is not None and not (0 <= inner_seed <= 2**256 - 1):
        parser.error("Inner seed must be between 0 and 2^256-1")

    if args.infile:
        with open(args.infile) as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        parser.error("Provide text as argument or use --in <infile>")

    if mode == "decode":
        text = strip_ciphertext_format(text)

    try:
        result = enegma(text, w1, w2, w3, wheels_path=args.wheels_file, mode=mode, plugboard_str=plugboard_str, wheel_select=wheel_select, trace=args.trace, prng_seed=prng_seed, shuffle_seed=shuffle_seed, eof_seed=eof_seed, inner_seed=inner_seed)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if mode == "encode":
        result = format_ciphertext(result)

    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
