#!/usr/bin/env python3
"""Enegma - A 3-wheel Enigma-style cipher engine (standard)."""

import argparse
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


def encode_char(c, wheels, reverses, reflector, positions):
    if not c.isascii() or not c.isalpha():
        return c

    upper = c.isupper()
    index = ord(c.upper()) - ord('A')
    size = 26

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

    result = chr(index + ord('A'))
    return result.lower() if not upper else result


def enegma(text, w1, w2, w3, wheels_path="wheels.json", mode="encode"):
    """Encode or decode text. Self-reciprocal: same settings encode and decode."""
    wheel1, wheel2, wheel3, reflector = load_wheels(wheels_path)
    wheels = [wheel1, wheel2, wheel3]
    reverses = [make_reverse(w) for w in wheels]
    positions = [w1, w2, w3]
    wheel_sizes = [len(w) for w in wheels]

    output = []
    for c in text:
        if c.isalpha():
            step_wheels(positions, wheel_sizes)
        output.append(encode_char(c, wheels, reverses, reflector, positions))

    return "".join(output)


def main():
    parser = argparse.ArgumentParser(description="Enegma cipher engine (standard)")
    parser.add_argument("text", nargs="?", help="Text to encode/decode")
    parser.add_argument("w1", type=int, help="Wheel 1 starting position")
    parser.add_argument("w2", type=int, help="Wheel 2 starting position")
    parser.add_argument("w3", type=int, help="Wheel 3 starting position")
    parser.add_argument("--in", dest="infile", help="Input file")
    parser.add_argument("--out", dest="outfile", help="Output file")
    args = parser.parse_args()

    if args.infile:
        with open(args.infile) as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        parser.error("Provide text as argument or use --in <infile>")

    result = enegma(text, args.w1, args.w2, args.w3)

    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
