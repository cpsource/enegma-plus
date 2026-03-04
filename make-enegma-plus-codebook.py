#!/usr/bin/env python3
"""Generate a yearly codebook for enegma-plus: daily keys for every day of the year."""

import argparse
import calendar
import json
import secrets


def generate_daily_key():
    """Generate a random daily key: wheel selection, starting positions, and plugboard."""
    # Select 3 wheels from kit of 16 (no repeats)
    available = list(range(1, 17))
    wheel_select = []
    for _ in range(3):
        choice = secrets.choice(available)
        available.remove(choice)
        wheel_select.append(choice)

    # Random starting positions (0-25 each)
    positions = [secrets.randbelow(26) for _ in range(3)]

    # Generate 10 plugboard pairs (20 letters paired, 6 unpaired)
    letters = list(range(26))
    # Shuffle with CSPRNG
    for i in range(25, 0, -1):
        j = secrets.randbelow(i + 1)
        letters[i], letters[j] = letters[j], letters[i]
    pairs = []
    for i in range(0, 20, 2):
        a = chr(letters[i] + ord('A'))
        b = chr(letters[i + 1] + ord('A'))
        pairs.append(f"{a}{b}")
    plugboard = " ".join(pairs)

    return {
        "wheels": wheel_select,
        "positions": positions,
        "plugboard": plugboard,
    }


def generate_codebook(year):
    """Generate daily keys for every day of the given year."""
    codebook = {
        "year": year,
        "days": {},
    }

    for month in range(1, 13):
        days_in_month = calendar.monthrange(year, month)[1]
        for day in range(1, days_in_month + 1):
            date_str = f"{year}-{month:02d}-{day:02d}"
            codebook["days"][date_str] = generate_daily_key()

    return codebook


def main():
    parser = argparse.ArgumentParser(description="Generate enegma-plus yearly codebook")
    parser.add_argument("--year", type=int, required=True, help="Year for the codebook")
    args = parser.parse_args()

    codebook = generate_codebook(args.year)
    filename = f"enegma-plus-codebook-{args.year}.json"

    with open(filename, "w") as f:
        json.dump(codebook, f, indent=2)

    num_days = len(codebook["days"])
    print(f"Generated {filename} with {num_days} daily keys")


if __name__ == "__main__":
    main()
