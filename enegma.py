#!/usr/bin/env python3
"""Enegma - A 3-wheel Enigma-style cipher engine with chaining."""

import json
import sys


def load_wheels(path="wheels.json"):
    with open(path) as f:
        data = json.load(f)
    return data["wheel1"], data["wheel2"], data["wheel3"], data["reflector"]


def make_reverse(wheel):
    rev = [0] * len(wheel)
    for i, v in enumerate(wheel):
        rev[v] = i
    return rev


def step_wheels(positions, wheel_sizes):
    """Advance wheels like an odometer. Wheel 1 steps every character,
    wheel 2 steps when wheel 1 wraps, wheel 3 steps when wheel 2 wraps."""
    positions[0] = (positions[0] + 1) % wheel_sizes[0]
    if positions[0] == 0:
        positions[1] = (positions[1] + 1) % wheel_sizes[1]
        if positions[1] == 0:
            positions[2] = (positions[2] + 1) % wheel_sizes[2]


def encode_char(c, wheels, reverses, reflector, positions, chain_offset=0, decoding=False):
    if not c.isascii() or not c.isalpha():
        return c

    upper = c.isupper()
    index = ord(c.upper()) - ord('A')
    size = 26

    # Chaining: encode adds offset before core, decode subtracts after core
    if not decoding:
        index = (index + chain_offset) % size

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

    if decoding:
        index = (index - chain_offset) % size

    result = chr(index + ord('A'))
    return result.lower() if not upper else result


def enegma(text, w1, w2, w3, wheels_path="wheels.json", mode="encode"):
    """Encode or decode text. Mode must be 'encode' or 'decode'."""
    wheel1, wheel2, wheel3, reflector = load_wheels(wheels_path)
    wheels = [wheel1, wheel2, wheel3]
    reverses = [make_reverse(w) for w in wheels]
    positions = [w1, w2, w3]
    wheel_sizes = [len(w) for w in wheels]

    output = []
    chain_offset = 0
    for c in text:
        if c.isalpha():
            step_wheels(positions, wheel_sizes)
        out_c = encode_char(c, wheels, reverses, reflector, positions, chain_offset, decoding=(mode == "decode"))
        output.append(out_c)
        if c.isalpha():
            if mode == "encode":
                # Next offset comes from ciphertext output
                chain_offset = ord(out_c.upper()) - ord('A')
            else:
                # Next offset comes from ciphertext input
                chain_offset = ord(c.upper()) - ord('A')

    return "".join(output)


def main():
    if len(sys.argv) < 5 or len(sys.argv) > 6:
        print(f"Usage: {sys.argv[0]} <text> W1 W2 W3 [d]", file=sys.stderr)
        print(f"  text  - ASCII text to encode/decode", file=sys.stderr)
        print(f"  W1-W3 - Starting positions for each wheel (integers)", file=sys.stderr)
        print(f"  d     - Add 'd' to decode (default: encode)", file=sys.stderr)
        sys.exit(1)

    text = sys.argv[1]
    w1, w2, w3 = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    mode = "decode" if len(sys.argv) == 6 and sys.argv[5].lower() == "d" else "encode"

    result = enegma(text, w1, w2, w3, mode=mode)
    print(result)


if __name__ == "__main__":
    main()
