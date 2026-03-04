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
enc = ep.enegma('HELLO WORLD', 7, 14, 22, mode='encode', prng_seed=12345); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=12345); \
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
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('ATTACK AT DAWN', 7, 14, 22, mode='encode', prng_seed=12345); \
dec = ep.enegma(enc, 7, 14, 22, mode='decode', prng_seed=99999); \
assert dec != 'ATTACK AT DAWN', f'FAIL: wrong seed decoded correctly'; \
print('PASS')"

	@echo "=== Test 20: PRNG overlay with plugboard and wheel selection ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
ep = import_module('enegma-plus'); \
enc = ep.enegma('HELLO WORLD', 3, 18, 9, mode='encode', plugboard_str='AN BY', wheel_select=[16, 8, 11], prng_seed=42); \
dec = ep.enegma(enc, 3, 18, 9, mode='decode', plugboard_str='AN BY', wheel_select=[16, 8, 11], prng_seed=42); \
assert dec == 'HELLO WORLD', f'FAIL: got {dec}'; \
print('PASS')"

	@echo "=== Test 21: PRNG overlay flattens frequency ==="
	@$(PYTHON) -c "\
from importlib import import_module; \
from collections import Counter; \
ep = import_module('enegma-plus'); \
text = 'A' * 100; \
enc = ep.enegma(text, 0, 0, 0, mode='encode', prng_seed=12345); \
counts = Counter(enc); \
total = len(enc); \
max_freq = max(counts.values()) / total; \
assert max_freq <= 0.15, f'FAIL: max frequency {max_freq:.2%} exceeds 15%'; \
print(f'PASS (max frequency: {max_freq:.2%})')"

	@echo ""
	@echo "All tests passed."
