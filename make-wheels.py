#!/usr/bin/env python3
"""Generate a new wheels.json file with CSPRNG-generated rotors and reflector."""

import argparse
import json
import secrets


def make_wheel(size=26):
    """Generate a random permutation of 0..size-1 using CSPRNG."""
    perm = list(range(size))
    for i in range(size - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def make_reflector(size=26, num_fixed=4):
    """Generate a random involution with fixed points using CSPRNG."""
    indices = list(range(size))
    fixed = set()
    while len(fixed) < num_fixed:
        fixed.add(secrets.choice(indices))
    remaining = [i for i in range(size) if i not in fixed]
    for i in range(len(remaining) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        remaining[i], remaining[j] = remaining[j], remaining[i]
    ref = list(range(size))
    for k in range(0, len(remaining), 2):
        a, b = remaining[k], remaining[k + 1]
        ref[a] = b
        ref[b] = a
    return ref


def main():
    parser = argparse.ArgumentParser(description="Generate a new wheels.json file")
    parser.add_argument("--out", default="wheels.json", help="Output file path (default: wheels.json)")
    parser.add_argument("--wheels", type=int, default=16, help="Number of wheels to generate (default: 16)")
    parser.add_argument("--fixed", type=int, default=4, help="Number of reflector fixed points (default: 4)")
    args = parser.parse_args()

    if args.wheels < 3:
        parser.error("Need at least 3 wheels")
    if args.fixed < 0 or args.fixed > 26:
        parser.error("Fixed points must be 0-26")
    if args.fixed % 2 != 0:
        parser.error("Fixed points must be even (remaining letters are paired)")

    data = {}
    for i in range(1, args.wheels + 1):
        w = make_wheel()
        assert sorted(w) == list(range(26))
        data[f"wheel{i}"] = w

    ref = make_reflector(26, args.fixed)
    assert all(ref[ref[i]] == i for i in range(26))
    data["reflector"] = ref

    with open(args.out, "w") as f:
        json.dump(data, f, indent=2)

    fp = [chr(i + ord('A')) for i in range(26) if ref[i] == i]
    print(f"Generated {args.out}")
    print(f"  {args.wheels} wheels (permutations of 0-25)")
    print(f"  Reflector with {len(fp)} fixed points: {' '.join(fp)}")


if __name__ == "__main__":
    main()
