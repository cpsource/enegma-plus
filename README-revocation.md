# Codebook Revocation

Currently, codebooks are static JSON files covering a full year with no
revocation mechanism. If a codebook is compromised, all 365 days of keys
are exposed. This document outlines approaches to handle codebook revocation.

## The Problem

- A yearly codebook contains every daily key for the entire year
- If an adversary obtains the codebook, they can decrypt all past and future
  messages for that year
- There is no way to invalidate a compromised codebook
- There is no way to verify a codebook is authentic (not tampered with)

## Approaches

### 1. Codebook Versioning

Add a `version` field to the codebook. If compromised, issue a replacement
with a higher version. The engine rejects codebooks below a minimum version.

```json
{
  "version": 2,
  "period": "2026-Q1",
  "keys": {
    "2026-01-01": { "wheels": [12, 5, 10], "positions": [8, 11, 20], "plugboard": "..." }
  }
}
```

The engine stores or receives a minimum accepted version. Any codebook with
a lower version is rejected with an error.

**Pro:** Simple to implement.
**Con:** Requires a way to distribute the minimum version out-of-band.

### 2. Shorter Codebook Periods

Generate monthly or weekly codebooks instead of yearly. A compromise only
exposes a limited window, and the next codebook is already different.

```bash
# Monthly codebooks
python3 make-enegma-plus-codebook.py --year 2026 --month 3
# Creates enegma-plus-codebook-2026-03.json (31 entries)

# Weekly codebooks
python3 make-enegma-plus-codebook.py --year 2026 --week 10
# Creates enegma-plus-codebook-2026-W10.json (7 entries)
```

**Pro:** Limits blast radius naturally — a compromised March codebook
doesn't affect April.
**Con:** More frequent distribution burden.

### 3. Key Revocation List

Maintain a `revoked.json` file listing compromised codebook serials or
date ranges. The engine checks this list before using a codebook entry.

```json
{
  "revoked_serials": [1],
  "revoked_dates": ["2026-03-01", "2026-03-02", "2026-03-03"]
}
```

The engine refuses to use any codebook entry matching a revoked serial
or date. The operator must provide a replacement codebook for those dates.

**Pro:** Granular — can revoke specific days or entire codebooks.
**Con:** The revocation list itself must be distributed securely.

### 4. Hash Chain / Forward Secrecy

Derive each day's key by hashing the previous day's key with the codebook
entry, so that compromising one day does not expose future days:

```
day_key = HKDF(previous_day_key || codebook_entry_for_today)
```

The chain is seeded with a secret known only to authorized parties. Revoking
the seed invalidates all future derived keys. Past keys cannot be derived
forward without the seed.

**Pro:** Compromising one day doesn't expose future days.
**Con:** More complex; loses random-access to arbitrary dates (must derive
keys sequentially from the seed).

### 5. Signed Codebooks

Sign codebooks with Ed25519 or ML-DSA (see [README-sign.md](README-sign.md)
and [README-pq.md](README-pq.md)). The engine verifies the signature before
use. Revocation means issuing a new signed codebook — the old one can be
blacklisted by serial number.

```json
{
  "version": 2,
  "signature": "base64-encoded-signature",
  "signing_key_id": "sender-2026",
  "keys": { }
}
```

**Pro:** Detects tampered codebooks; ties into planned signing work.
**Con:** Does not prevent use of a copied-but-validly-signed codebook
(must combine with versioning or revocation list).

## Recommended Approach

Combine **versioning + shorter periods + signing** for practical security:

1. **Monthly codebooks** — limits compromise window to at most 30 days
2. **Version/serial numbers** — engine rejects outdated codebooks
3. **Digital signatures** — engine rejects unsigned or tampered codebooks
4. **Optional revocation list** — for revoking specific dates mid-period

### Proposed codebook format

```json
{
  "version": 3,
  "period": "2026-03",
  "generated": "2026-02-25T00:00:00Z",
  "signing_key_id": "ops-2026",
  "signature": "base64-encoded-signature",
  "keys": {
    "2026-03-01": {
      "wheels": [12, 5, 10],
      "positions": [8, 11, 20],
      "plugboard": "SP HC XU IB NG RJ FK DZ QV AL"
    }
  }
}
```

### Proposed CLI changes

```bash
# Generate a monthly codebook (signed)
python3 make-enegma-plus-codebook.py --year 2026 --month 3 --sign-key ops.key

# Use with signature verification
python3 enegma-plus.py "HELLO" --cb --sign-pub ops.pub

# Reject if codebook version is below minimum
python3 enegma-plus.py "HELLO" --cb --min-version 3

# Check against revocation list
python3 enegma-plus.py "HELLO" --cb --revoked revoked.json
```

## Operational Procedures

1. **Routine rotation:** Generate and distribute next month's codebook
   before the current one expires
2. **Compromise response:** Generate a new codebook with a higher version
   number, distribute it, and add the compromised serial to the revocation
   list
3. **Verification:** Always use `--sign-pub` in production to reject
   unsigned or tampered codebooks
4. **Destruction:** Securely delete expired codebooks from all endpoints
