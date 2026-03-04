#!/usr/bin/env python3
"""Enegma - A 3-wheel Enigma-style cipher engine with chaining."""

import argparse
import json
import secrets
import sys


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


def _enegma_raw(text, positions, wheels, reverses, reflector, plugboard, mode="encode"):
    """Low-level encrypt/decrypt without text preparation or message key handling."""
    wheel_sizes = [len(w) for w in wheels]
    output = []
    chain_offset = 0
    for c in text:
        if c.isalpha():
            step_wheels(positions, wheel_sizes)
        out_c = encode_char(c, wheels, reverses, reflector, positions, plugboard, chain_offset, decoding=(mode == "decode"))
        output.append(out_c)
        if c.isalpha():
            if mode == "encode":
                chain_offset = ord(out_c.upper()) - ord('A')
            else:
                chain_offset = ord(c.upper()) - ord('A')
    return "".join(output)


def enegma(text, w1, w2, w3, wheels_path="wheels.json", mode="encode", plugboard_str=None, wheel_select=None):
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

    if mode == "encode":
        text = prepare_text(text)

        # Generate random per-message key
        mk = [secrets.randbelow(26) for _ in range(3)]
        mk_letters = ''.join(chr(p + ord('A')) for p in mk)

        # Encrypt the message key at daily key positions (no chaining for indicator)
        indicator_pos = [w1, w2, w3]
        enc_indicator = _enegma_raw(mk_letters, indicator_pos, wheels, reverses, reflector, plugboard, mode="encode")

        # Encrypt the message body at the message key positions
        body_pos = list(mk)
        enc_body = _enegma_raw(text, body_pos, wheels, reverses, reflector, plugboard, mode="encode")

        return enc_indicator + enc_body

    else:
        # Split indicator (first 3 chars) from body
        enc_indicator = text[:3]
        enc_body = text[3:]

        # Decrypt indicator at daily key positions to recover message key
        indicator_pos = [w1, w2, w3]
        mk_letters = _enegma_raw(enc_indicator, indicator_pos, wheels, reverses, reflector, plugboard, mode="decode")

        # Convert message key letters to positions
        mk = [ord(c) - ord('A') for c in mk_letters.upper()]

        # Decrypt body at message key positions
        body_pos = list(mk)
        plaintext = _enegma_raw(enc_body, body_pos, wheels, reverses, reflector, plugboard, mode="decode")

        return restore_text(plaintext)


def main():
    parser = argparse.ArgumentParser(description="Enegma cipher engine")
    parser.add_argument("text", nargs="?", help="Text to encode/decode")
    parser.add_argument("w1", type=int, help="Wheel 1 starting position")
    parser.add_argument("w2", type=int, help="Wheel 2 starting position")
    parser.add_argument("w3", type=int, help="Wheel 3 starting position")
    parser.add_argument("-d", action="store_true", help="Decode mode")
    parser.add_argument("--in", dest="infile", help="Input file")
    parser.add_argument("--out", dest="outfile", help="Output file")
    parser.add_argument("--pb", dest="plugboard", help="Plugboard pairs (e.g. 'AN BY CW DI EQ FL GT HX KP MZ')")
    parser.add_argument("--wh", dest="wheels", help="Select 3 wheels from kit by number (e.g. '5 12 3')")
    args = parser.parse_args()

    mode = "decode" if args.d else "encode"
    wheel_select = [int(x) for x in args.wheels.split()] if args.wheels else None

    if args.infile:
        with open(args.infile) as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        parser.error("Provide text as argument or use --in <infile>")

    result = enegma(text, args.w1, args.w2, args.w3, mode=mode, plugboard_str=args.plugboard, wheel_select=wheel_select)

    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
