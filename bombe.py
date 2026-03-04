#!/usr/bin/env python3
"""Bombe - Crib-based brute force attack on the Enegma engine."""

import sys
from enegma import enegma, load_wheels


def bombe(ciphertext, crib, crib_pos=0, wheels_path="wheels.json"):
    """Try all 26^3 rotor positions and return settings where the crib matches.

    Args:
        ciphertext: The encrypted text.
        crib: Known plaintext fragment.
        crib_pos: Position in the plaintext where the crib appears.
        wheels_path: Path to the wheels JSON file.
    """
    # Preload wheels to avoid re-reading JSON 17,576 times
    wheel1, wheel2, wheel3, reflector = load_wheels(wheels_path)

    results = []
    total = 26 ** 3

    for w1 in range(26):
        for w2 in range(26):
            for w3 in range(26):
                # Decrypt the ciphertext with these settings
                plaintext = enegma(ciphertext, w1, w2, w3, wheels_path, mode="decode")

                # Check if the crib appears at the expected position
                fragment = plaintext[crib_pos:crib_pos + len(crib)]
                if fragment.upper() == crib.upper():
                    results.append((w1, w2, w3, plaintext))

    return results


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <ciphertext> <crib> [crib_position]", file=sys.stderr)
        print(f"  ciphertext    - The encrypted text", file=sys.stderr)
        print(f"  crib          - Known plaintext fragment", file=sys.stderr)
        print(f"  crib_position - Where the crib appears in plaintext (default: 0)", file=sys.stderr)
        sys.exit(1)

    ciphertext = sys.argv[1]
    crib = sys.argv[2]
    crib_pos = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    print(f"Ciphertext: {ciphertext}")
    print(f"Crib: '{crib}' at position {crib_pos}")
    print(f"Testing 17,576 rotor combinations...\n")

    results = bombe(ciphertext, crib, crib_pos)

    if results:
        print(f"Found {len(results)} possible setting(s):\n")
        for w1, w2, w3, plaintext in results:
            print(f"  W1={w1:2d}  W2={w2:2d}  W3={w3:2d}  ->  {plaintext}")
    else:
        print("No matching settings found.")


if __name__ == "__main__":
    main()
