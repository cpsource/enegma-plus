# Known Cribs in the Original Enigma

## Punctuation and Formatting

The Enigma machine only handled letters A-Z. All punctuation, numbers, and
spaces had to be spelled out using standard abbreviations:

| Symbol | Crib | Origin |
|--------|------|--------|
| Space | `X` | Word separator |
| Period (.) | `X` | Same as space; double `XX` ended sentences |
| Comma (,) | `ZZ` | |
| Question mark (?) | `FRAQ` | *Fragezeichen* |
| Open parenthesis | `KL` | *Klammer* |
| Close parenthesis | `KLAM` | *Klammer* |

Numbers were spelled out: `EINS`, `ZWO`, `DREI`, `NULL`, etc.

## Predictable Message Content

Operators followed rigid formats that produced known plaintext:

- **WETTERBERICHT** — Weather reports began with this word daily
- **HEIL HITLER** — Common sign-off, often at the end of messages
- **NULL NULL** — Midnight (0000) appeared frequently in time references
- **KEINE BESONDEREN EREIGNISSE** — "Nothing to report," sent routinely

## Structural Weaknesses Exploited as Cribs

- **X at regular intervals** — Word separators created predictable patterns
  in the ciphertext, especially in formulaic messages
- **Repeated message keys** — Before 1940, the 3-letter message key was
  encrypted twice at the start of each message (e.g., `ABCABC`). Positions
  1&4, 2&5, 3&6 always encrypted the same letter, giving Marian Rejewski
  the patterns needed to deduce rotor wiring
- **No self-encryption** — A letter could never encrypt to itself. This let
  codebreakers slide a suspected crib along the ciphertext and eliminate any
  position where a plaintext letter aligned with the same ciphertext letter
- **Daily key reuse** — All operators on a network shared the same daily
  settings, producing thousands of messages under identical keys each day

## How Cribs Were Used

1. Analysts guessed a word likely present in the message (the crib)
2. They slid the crib along the ciphertext looking for valid positions
   (no letter could encrypt to itself, so any overlap eliminated that position)
3. Valid crib positions were fed into the Bombe, which tested rotor settings
   to find which ones produced the crib at that position
4. Once settings were found, the entire day's traffic could be decrypted
