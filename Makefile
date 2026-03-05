PYTHON = python3

.PHONY: test
test:
	@echo "=== Test 1: Basic encode/decode round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode'); \
dec = ep.enegma(enc, 0, 0, 0, mode='decode'); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 2: Different ciphertexts each encryption (random message key) ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
e1 = ep.enegma('HELLO', 5, 5, 5, mode='encode'); \
e2 = ep.enegma('HELLO', 5, 5, 5, mode='encode'); \
assert e1 != e2, 'FAIL: identical ciphertexts'; \
d1 = ep.enegma(e1, 5, 5, 5, mode='decode'); \
d2 = ep.enegma(e2, 5, 5, 5, mode='decode'); \
assert d1 == d2 == 'HELLO', f'FAIL: got {d1}, {d2}'; \
print('PASS')"

	@echo "=== Test 3: Plugboard encode/decode ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('ATTACK AT DAWN', 7, 14, 22, mode='encode', plugboard_str='AN BY CW DI EQ'); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', plugboard_str='AN BY CW DI EQ'); \
assert dec == 'ATTACK AT DAWN', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 4: German text preparation (punctuation and numbers) ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'Attack at 0300, sector 5.'; \
enc = ep.enegma(text, 13, 7, 21, mode='encode'); \
dec = ep.enegma(enc, 13, 7, 21, mode='decode'); \
assert dec == text.upper(), f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 5: All punctuation types ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = \"Report (urgent): 7 tanks; 23 soldiers? Yes.\"; \
enc = ep.enegma(text, 3, 18, 9, mode='encode'); \
dec = ep.enegma(enc, 3, 18, 9, mode='decode'); \
assert dec == text.upper(), f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 6: Chaining avalanche effect ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
e1 = ep._enegma_raw('ATTACKATDAWN', [0,0,0], *ep._load_args()); \
e2 = ep._enegma_raw('XTTACKATDAWN', [0,0,0], *ep._load_args()); \
diffs = sum(1 for a, b in zip(e1[1:], e2[1:]) if a != b); \
assert diffs >= 8, f'FAIL: only {diffs} chars differ'; \
print(f'PASS ({diffs}/11 chars differ after first position)')"

	@echo "=== Test 7: Long message round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG' * 10; \
enc = ep.enegma(text, 25, 25, 25, mode='encode'); \
dec = ep.enegma(enc, 25, 25, 25, mode='decode'); \
assert dec == text.upper(), f'FAIL: mismatch at length {len(text)}'; \
print(f'PASS ({len(text)} chars)')"

	@echo "=== Test 8: File I/O ==="
	@echo "Hello, World 12345." > /tmp/enegma_test_in.txt
	@$(PYTHON) enegma-plus.py --in /tmp/enegma_test_in.txt --out /tmp/enegma_test_enc.txt 10 20 5
	@$(PYTHON) enegma-plus.py --in /tmp/enegma_test_enc.txt --out /tmp/enegma_test_dec.txt 10 20 5 -d
	@$(PYTHON) -c "\
expected = 'HELLO, WORLD 12345.'; \
actual = open('/tmp/enegma_test_dec.txt').read(); \
assert actual == expected, f'FAIL: got {repr(actual)}'; \
print('PASS')"
	@rm -f /tmp/enegma_test_in.txt /tmp/enegma_test_enc.txt /tmp/enegma_test_dec.txt

	@echo "=== Test 9: Invalid plugboard (duplicate letter) ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\ntry:\n ep.enegma('TEST', 0, 0, 0, mode='encode', plugboard_str='AB AC')\n print('FAIL: should have raised ValueError')\nexcept ValueError:\n print('PASS')\")"

	@echo "=== Test 10: Message key is 3 chars prepended ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('A', 0, 0, 0, mode='encode'); \
assert len(enc) == 4, f'FAIL: expected 4 chars (3 indicator + 1 body), got {len(enc)}'; \
print('PASS')"

	@echo "=== Test 11: Wheel selection round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', wheel_select=[5, 12, 3]); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', wheel_select=[5, 12, 3]); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 12: Different wheel order produces different ciphertext ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
e1 = ep._enegma_raw('HELLO', [0,0,0], *ep._load_args(wheel_select=[1,2,3])); \
e2 = ep._enegma_raw('HELLO', [0,0,0], *ep._load_args(wheel_select=[3,2,1])); \
assert e1 != e2, f'FAIL: same ciphertext with different wheel order'; \
print('PASS')"

	@echo "=== Test 13: Wrong wheel selection fails to decode ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('ATTACK AT DAWN', 7, 14, 22, mode='encode', wheel_select=[5, 12, 3]); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', wheel_select=[1, 2, 3]); \
assert dec != 'ATTACK AT DAWN', f'FAIL: wrong wheels decoded correctly'; \
print('PASS')"

	@echo "=== Test 14: Invalid wheel number raises error ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\ntry:\n ep.enegma('TEST', 0, 0, 0, mode='encode', wheel_select=[1, 2, 99])\n print('FAIL: should have raised ValueError')\nexcept ValueError:\n print('PASS')\")"

	@echo "=== Test 15: Wheel selection with plugboard ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 3, 18, 9, mode='encode', plugboard_str='AN BY', wheel_select=[16, 8, 11]); \
dec = ep.enegma(enc, 3, 18, 9, mode='decode', plugboard_str='AN BY', wheel_select=[16, 8, 11]); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 16: All 16 wheels are usable ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nfor i in range(1, 17):\n ws = [i, (i%16)+1, ((i+1)%16)+1]\n enc = ep.enegma('TEST', 0, 0, 0, mode='encode', wheel_select=ws)\n dec = ep.enegma(enc, 0, 0, 0, mode='decode', wheel_select=ws)\n assert dec == 'TEST', f'FAIL: wheel {i}'\nprint('PASS (all 16 wheels verified)')\")"

	@echo "=== Test 17: PRNG overlay round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 18: PRNG overlay changes ciphertext ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
import secrets; \
mk = [0, 0, 0]; \
wheels, reverses, reflector, plugboard = ep._load_args(); \
body = ep._enegma_raw('HELLO', list(mk), wheels, reverses, reflector, plugboard, mode='encode'); \
with_prng = ep.apply_prng_overlay(body, 12345); \
assert body != with_prng, f'FAIL: PRNG overlay did not change ciphertext'; \
print('PASS')"

	@echo "=== Test 19: Wrong PRNG seed fails to decode ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nenc = ep.enegma('ATTACK AT DAWN', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111)\ntry:\n dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=99999, shuffle_seed=67890, eof_seed=11111)\n assert dec != 'ATTACK AT DAWN', 'FAIL: wrong seed decoded correctly'\nexcept ValueError:\n pass\nprint('PASS')\")"

	@echo "=== Test 20: PRNG overlay with plugboard and wheel selection ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 3, 18, 9, mode='encode', plugboard_str='AN BY', wheel_select=[16, 8, 11], prng_seed=42, shuffle_seed=43, eof_seed=44); \
dec = ep.enegma(enc, 3, 18, 9, mode='decode', plugboard_str='AN BY', wheel_select=[16, 8, 11], prng_seed=42, shuffle_seed=43, eof_seed=44); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 21: PRNG overlay flattens frequency ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
from collections import Counter; \
ep = import_module('enegma-plus'); \
text = 'A' * 100; \
enc = ep.enegma(text, 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
counts = Counter(enc); \
total = len(enc); \
max_freq = max(counts.values()) / total; \
assert max_freq <= 0.15, f'FAIL: max frequency {max_freq:.2%} exceeds 15%'; \
print(f'PASS (max frequency: {max_freq:.2%})')"

	@echo "=== Test 22: PRNG overlay via codebook round-trip ==="
	@$(PYTHON) -c "\
import json, tempfile, os; \
from importlib import import_module; \
ep = import_module('enegma-plus'); \
cb = {'year': 9999, 'days': {'9999-01-01': {'wheels': [1,2,3], 'positions': [7,14,22], 'plugboard': 'AN BY', 'prng_seed': 77777, 'shuffle_seed': 88888, 'eof_seed': 99999}}}; \
f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False); \
json.dump(cb, f); f.close(); \
key, _ = ep.load_codebook_key(f.name, '9999-01-01'); \
assert key['prng_seed'] == 77777, f'FAIL: prng_seed not loaded from codebook'; \
assert key['shuffle_seed'] == 88888, f'FAIL: shuffle_seed not loaded from codebook'; \
assert key['eof_seed'] == 99999, f'FAIL: eof_seed not loaded from codebook'; \
enc = ep.enegma('HELLO WORLD', key['w1'], key['w2'], key['w3'], mode='encode', plugboard_str=key['plugboard'], wheel_select=key['wheels'], prng_seed=key['prng_seed'], shuffle_seed=key['shuffle_seed'], eof_seed=key['eof_seed']); \
dec = ep.enegma(enc, key['w1'], key['w2'], key['w3'], mode='decode', plugboard_str=key['plugboard'], wheel_select=key['wheels'], prng_seed=key['prng_seed'], shuffle_seed=key['shuffle_seed'], eof_seed=key['eof_seed']); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
os.unlink(f.name); \
print('PASS')"

	@echo "=== Test 23: Shuffle round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=54321, shuffle_seed=11111, eof_seed=22222); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=54321, shuffle_seed=11111, eof_seed=22222); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 24: Shuffle changes character positions ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'ABCDEFGHIJ'; \
shuffled = ep.apply_positional_permutation(text, 12345); \
assert shuffled != text, f'FAIL: shuffle did not change positions'; \
assert len(shuffled) == len(text), f'FAIL: length changed'; \
print(f'PASS (original={text}, shuffled={shuffled})')"

	@echo "=== Test 25: Shuffle preserves character set ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'; \
shuffled = ep.apply_positional_permutation(text, 99999); \
assert sorted(shuffled) == sorted(text), f'FAIL: character set not preserved'; \
print('PASS')"

	@echo "=== Test 26: Long message round-trip with shuffle ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG ' * 12; \
enc = ep.enegma(text, 25, 25, 25, mode='encode', prng_seed=777, shuffle_seed=888, eof_seed=999); \
dec = ep.enegma(enc, 25, 25, 25, mode='decode', prng_seed=777, shuffle_seed=888, eof_seed=999); \
assert dec == text.upper(), f'FAIL: mismatch at length {len(text)}'; \
print(f'PASS ({len(text)} chars)')"

	@echo "=== Test 27: Shuffle + plugboard + wheel selection combined ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('ATTACK AT DAWN', 3, 18, 9, mode='encode', plugboard_str='AN BY CW', wheel_select=[16, 8, 11], prng_seed=31337, shuffle_seed=31338, eof_seed=31339); \
dec = ep.enegma(enc, 3, 18, 9, mode='decode', plugboard_str='AN BY CW', wheel_select=[16, 8, 11], prng_seed=31337, shuffle_seed=31338, eof_seed=31339); \
assert dec == 'ATTACK AT DAWN', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 28: Padding round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 29: Padded output has perfectly flat frequency ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
from collections import Counter; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
counts = Counter(enc); \
freqs = [counts.get(chr(i + ord('A')), 0) for i in range(26)]; \
assert len(set(freqs)) == 1, f'FAIL: frequencies not uniform: {freqs}'; \
print(f'PASS (all 26 letters appear {freqs[0]} times)')"

	@echo "=== Test 30: Padded output is longer than unpadded ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'HELLO'; \
body = ep._enegma_raw(ep.prepare_text(text), [0,0,0], *ep._load_args(), mode='encode'); \
unpadded_len = len(body) + 3; \
enc = ep.enegma(text, 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111); \
assert len(enc) > unpadded_len, f'FAIL: padded ({len(enc)}) not longer than unpadded ({unpadded_len})'; \
print(f'PASS (padded={len(enc)}, unpadded={unpadded_len})')"

	@echo "=== Test 31: Wrong seed fails to strip padding ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nenc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111)\ntry:\n dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=99999)\n print('FAIL: should have raised ValueError')\nexcept ValueError:\n print('PASS')\")"

	@echo "=== Test 32: Long message round-trip with padding + shuffle ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
text = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG ' * 12; \
enc = ep.enegma(text, 25, 25, 25, mode='encode', prng_seed=777, shuffle_seed=888, eof_seed=999); \
dec = ep.enegma(enc, 25, 25, 25, mode='decode', prng_seed=777, shuffle_seed=888, eof_seed=999); \
assert dec == text.upper(), f'FAIL: mismatch at length {len(text)}'; \
print(f'PASS ({len(text)} chars)')"

	@echo "=== Test 33: Formatted output has correct block structure ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
ct = ep.format_ciphertext('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); \
blocks = ct.split('\n')[0].split(' '); \
assert all(len(b) == 5 for b in blocks[:-1]), f'FAIL: blocks not 5 chars: {blocks}'; \
assert len(blocks) <= 10, f'FAIL: more than 10 blocks per line'; \
print(f'PASS (first line: {ct.split(chr(10))[0]})')"

	@echo "=== Test 34: Round-trip through formatted output ==="
	@$(PYTHON) -c "\
import subprocess, sys; \
enc = subprocess.run([sys.executable, 'enegma-plus.py', 'HELLO WORLD', '0', '0', '0'], capture_output=True, text=True).stdout.strip(); \
assert ' ' in enc, f'FAIL: output not block-formatted: {enc}'; \
dec = subprocess.run([sys.executable, 'enegma-plus.py', enc, '0', '0', '0', '-d'], capture_output=True, text=True).stdout.strip(); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 35: File I/O round-trip with formatted ciphertext ==="
	@echo "Testing file round-trip with blocks." > /tmp/enegma_test35_in.txt
	@$(PYTHON) enegma-plus.py --in /tmp/enegma_test35_in.txt --out /tmp/enegma_test35_enc.txt 5 10 15
	@$(PYTHON) -c "\
ct = open('/tmp/enegma_test35_enc.txt').read(); \
assert ' ' in ct, f'FAIL: file output not block-formatted'; \
print(f'PASS (formatted output verified)')"
	@$(PYTHON) enegma-plus.py --in /tmp/enegma_test35_enc.txt --out /tmp/enegma_test35_dec.txt 5 10 15 -d
	@$(PYTHON) -c "\
expected = 'TESTING FILE ROUND-TRIP WITH BLOCKS.'; \
actual = open('/tmp/enegma_test35_dec.txt').read(); \
assert actual == expected, f'FAIL: got {repr(actual)}'; \
print('PASS')"
	@rm -f /tmp/enegma_test35_in.txt /tmp/enegma_test35_enc.txt /tmp/enegma_test35_dec.txt

	@echo "=== Test 36: Different shuffle_seed produces different shuffle ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc1 = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=11111, eof_seed=33333); \
enc2 = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=22222, eof_seed=33333); \
assert enc1 != enc2, 'FAIL: different shuffle_seed produced same output'; \
print('PASS')"

	@echo "=== Test 37: Different eof_seed fails to decode ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nenc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111)\ntry:\n dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=22222)\n print('FAIL: should have raised ValueError')\nexcept ValueError:\n print('PASS')\")"

	@echo "=== Test 38: 256-bit seed round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
seed = (1 << 200) + 12345; \
enc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode', prng_seed=seed, shuffle_seed=seed+1, eof_seed=seed+2); \
dec = ep.enegma(enc, 0, 0, 0, mode='decode', prng_seed=seed, shuffle_seed=seed+1, eof_seed=seed+2); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 39: Inner seed round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=99999); \
dec = ep.enegma(enc, 0, 0, 0, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=99999); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 40: Inner seed changes ciphertext ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc1 = ep.enegma('HELLO', 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=100); \
enc2 = ep.enegma('HELLO', 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=200); \
assert enc1 != enc2, 'FAIL: different inner_seed produced same output'; \
print('PASS')"

	@echo "=== Test 41: Wrong inner seed fails to decode ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nenc = ep.enegma('ATTACK AT DAWN', 7, 14, 22, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=99999)\ntry:\n dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=88888)\n assert dec != 'ATTACK AT DAWN', 'FAIL: wrong inner_seed decoded correctly'\nexcept ValueError:\n pass\nprint('PASS')\")"

	@echo "=== Test 42: 256-bit inner seed round-trip ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
seed = (1 << 200) + 54321; \
enc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode', prng_seed=seed, shuffle_seed=seed+1, eof_seed=seed+2, inner_seed=seed+3); \
dec = ep.enegma(enc, 0, 0, 0, mode='decode', prng_seed=seed, shuffle_seed=seed+1, eof_seed=seed+2, inner_seed=seed+3); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 43: Wrong inner_seed raises ValueError from encrypted marker ==="
	@$(PYTHON) -c "exec(\"from importlib import import_module\nep = import_module('enegma-plus')\nenc = ep.enegma('HELLO WORLD', 0, 0, 0, mode='encode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=99999)\ntry:\n ep.enegma(enc, 0, 0, 0, mode='decode', prng_seed=12345, shuffle_seed=67890, eof_seed=11111, inner_seed=77777)\n print('FAIL: should have raised ValueError')\nexcept ValueError:\n print('PASS')\")"

	@echo "=== Test 44: HMAC detects tampered ciphertext ==="
	@$(PYTHON) -c "\
import subprocess, sys; \
enc = subprocess.run([sys.executable, 'enegma-plus.py', 'HELLO WORLD', '0', '0', '0', \
    '--prng-seed', '12345', '--shuffle-seed', '67890', '--eof-seed', '11111', '--inner-seed', '99999'], \
    capture_output=True, text=True).stdout.strip(); \
lines = enc.split('\n'); \
first = lines[0]; \
tampered_char = 'B' if first[0] != 'B' else 'A'; \
lines[0] = tampered_char + first[1:]; \
tampered = '\n'.join(lines); \
r = subprocess.run([sys.executable, 'enegma-plus.py', tampered, '0', '0', '0', '-d', \
    '--prng-seed', '12345', '--shuffle-seed', '67890', '--eof-seed', '11111', '--inner-seed', '99999'], \
    capture_output=True, text=True); \
assert r.returncode != 0 and 'HMAC' in r.stderr, f'FAIL: tampered not detected: {r.stderr}'; \
print('PASS')"

	@echo "=== Test 45: HMAC tag present in CLI output ==="
	@$(PYTHON) -c "\
import subprocess, sys; \
r = subprocess.run([sys.executable, 'enegma-plus.py', 'HELLO', '0', '0', '0', \
    '--prng-seed', '12345', '--shuffle-seed', '67890', '--eof-seed', '11111'], \
    capture_output=True, text=True); \
lines = r.stdout.strip().split('\n'); \
tag_line = lines[-1]; \
assert len(tag_line) == 64 and tag_line.isalpha(), f'FAIL: last line is not 64-char HMAC tag: {repr(tag_line)}'; \
print('PASS')"

	@echo "=== Test 46: Wrong seed fails HMAC verification ==="
	@$(PYTHON) -c "\
import subprocess, sys; \
enc = subprocess.run([sys.executable, 'enegma-plus.py', 'HELLO WORLD', '0', '0', '0', \
    '--prng-seed', '12345', '--shuffle-seed', '67890', '--eof-seed', '11111'], \
    capture_output=True, text=True).stdout.strip(); \
r = subprocess.run([sys.executable, 'enegma-plus.py', enc, '0', '0', '0', '-d', \
    '--prng-seed', '99999', '--shuffle-seed', '67890', '--eof-seed', '11111'], \
    capture_output=True, text=True); \
assert r.returncode != 0 and 'HMAC' in r.stderr, f'FAIL: wrong seed not detected: {r.stderr}'; \
print('PASS')"

	@echo ""
	@echo "All tests passed."
