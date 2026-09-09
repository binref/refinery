from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import deobfuscate_within
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.scramble import JsScrambleStringDecoder, ScrambleCipher


class TestScrambleStringDecoder(TestJsDeobfuscator):

    def test_cipher_decode_known_values(self):
        cipher = ScrambleCipher(
            '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6',
            'fec5863b88643968ecff0c2c8afecbaf',
        )
        self.assertEqual(
            cipher.decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg='),
            'https://api.github.com',
        )
        self.assertEqual(
            cipher.decode('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s='),
            'python-requests/2.31.0',
        )

    def test_decode_substitution(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var ua = decode('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            var ua = 'python-requests/2.31.0';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_non_scramble_class_not_touched(self):
        source = inspect.cleandoc(
            """
            class Foo {
              constructor(x) { this.value = x; }
              decode(y) { return y + this.value; }
            }
            var f = new Foo('hello');
            var r = f.decode('world');
            """
        )
        expected = inspect.cleandoc(
            """
            class Foo {
              constructor(x) {
                this.value = x;
              }
              decode(y) {
                return y + this.value;
              }
            }
            var f = new Foo('hello');
            var r = f.decode('world');
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_global_this_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            var exportName = 'fc2edea72';
            globalThis[exportName] = decode;
            var url = fc2edea72('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var ua = fc2edea72('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            var ua = 'python-requests/2.31.0';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_global_dot_access_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            global.decode = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    @unittest.expectedFailure
    def test_a_decoder_install_through_a_host_conditional_alias_keeps_its_base_throw(self):
        """
        `global.decode = decode` reads `global` before it writes, so in a host that lacks `global` —
        a browser — the installation raises a `ReferenceError`. Here the decoder is reached only
        through the bare `decode(...)` calls the pass substitutes, so the installation is redundant
        infrastructure the pass removes; removing it drops that throw, and the output prints the URL
        where the input refused to run. Keeping the throw without keeping the whole cipher machinery
        needs the redundant install rewritten to a base-read residue, which only a base that cannot
        resolve calls for, and which belongs with the host-existence work. The pass strikes the whole
        statement instead, so `global.decode` is gone from what it writes.
        """
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            global.decode = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            """
        )
        self.assertIn('global.decode', self._run_transformer(source, JsScrambleStringDecoder))

    _CIPHER_CLASS = inspect.cleandoc(
        """
        class Scramble {
          constructor(pw, salt) {
            this.masterKey = pb(pw, salt, ITERATIONS, 32, 'sha256');
            this.rounds = ROUNDS;
          }
          decode(input) {
            return decrypt(input, this.masterKey, this.rounds);
          }
        }
        var instance = new Scramble('2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6', 'fec5863b88643968ecff0c2c8afecbaf');
        function decode(x) {
          return instance.decode(x);
        }
        console.log(decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg='));
        """
    )
    """
    One program in the shape this pass recognizes, with the two repetition counts left open. It is
    written the way the synthesizer writes it, so a run that recognizes nothing returns it verbatim.
    """

    def _cipher(self, iterations: str, rounds: str) -> str:
        return self._CIPHER_CLASS.replace('ITERATIONS', iterations).replace('ROUNDS', rounds)

    def _deobfuscate_bounded(self, source: str) -> str:
        """
        The deobfuscation of *source*, run in a child process so that a count spent as work rather
        than refused fails the test instead of hanging it. Both counts buy work directly: an
        iteration count inside one `hashlib.pbkdf2_hmac` call that nothing here can interrupt, a
        round count as a loop per decoded string.
        """
        deobfuscated = deobfuscate_within(source, seconds=30)
        if deobfuscated is None:
            self.fail('recognizing the cipher did not terminate')
        return deobfuscated

    def _declines(self, iterations: str, rounds: str):
        source = self._cipher(iterations, rounds)
        self.assertEqual(source, self._deobfuscate_bounded(source))

    def test_counts_the_pass_can_honour_decode_the_class(self):
        """
        The control the refusals below are read against: the same program with counts this pass can
        honour is recognized and decoded, so a refusal is a decision about the counts and not the
        shape.
        """
        source = self._cipher('200000', '3')
        self.assertEqual(
            "console.log('https://api.github.com');", self._deobfuscate_bounded(source))

    def test_an_iteration_count_past_the_bound_is_not_this_cipher(self):
        self._declines('1e12', '3')

    def test_a_round_count_past_the_bound_is_not_this_cipher(self):
        self._declines('200000', '1e12')

    def test_a_zero_iteration_count_is_not_this_cipher(self):
        """
        `crypto.pbkdf2Sync` rejects an iteration count below one with a `RangeError`, so a
        constructor naming zero describes a class no engine builds and a key no derivation
        produces.
        """
        self._declines('0', '3')

    def test_a_zero_round_count_is_not_this_cipher(self):
        self._declines('200000', '0')

    def test_a_count_that_is_not_a_literal_is_not_this_cipher(self):
        """
        The counts decide the key, so a count this pass cannot read is a key it cannot derive.
        Falling back on a default would not fail loudly; it would print a plausible string that the
        program never produces.
        """
        self._declines('200000', 'n')

    def test_global_string_key_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            globalThis['fc2edea72'] = decode;
            var url = fc2edea72('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)


class TestTheInstallationOfADecoderIsKeptWhereACallStillReachesIt(TestJsDeobfuscator):
    """
    The pass deletes the cipher machinery once nothing outside it names any of the machinery, and a
    call whose argument it could not read is exactly what leaves something naming it. Both rows put
    such a call beside a statement installing the decoder under a second name, so the installation
    is what the surviving call reaches the decoder through.
    """

    _MACHINERY = inspect.cleandoc(
        """
        class Scramble {
          constructor(pw, salt) {
            this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
            this.rounds = 3;
          }
          decode(input) { return decrypt(input, this.masterKey, this.rounds); }
        }
        var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
        var salt = 'fec5863b88643968ecff0c2c8afecbaf';
        var instance = new Scramble(key, salt);
        function decode(x) { return instance.decode(x); }
        """
    )

    def _decode(self, tail: str) -> str:
        return self._run_transformer(
            F'{self._MACHINERY}\n{inspect.cleandoc(tail)}', JsScrambleStringDecoder)

    def test_an_installation_on_an_object_a_declaration_holds_is_not_a_global_installation(self):
        """
        `self` is declared here, so `self.d = decode` writes a property of an ordinary object rather
        than installing a global, and `self.d(payload)` reads that property back. The machinery
        stays whole because that call still names it; the call the pass could read is answered all
        the same.
        """
        tail = """
            var self = {};
            self.d = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var other = self.d(payload);
            """
        expected = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) {
                return decrypt(input, this.masterKey, this.rounds);
              }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) {
              return instance.decode(x);
            }
            var self = {};
            self.d = decode;
            var url = 'https://api.github.com';
            var other = self.d(payload);
            """
        )
        self.assertEqual(self._decode(tail), expected)

    @unittest.expectedFailure
    def test_an_installation_on_the_global_object_is_kept_where_a_call_reads_the_name(self):
        """
        `window.d = decode` really does install the decoder as the global `d`, which `d(payload)`
        goes on to call, so the installation and the machinery behind it have to stay: the output
        the pass writes today throws `ReferenceError` where the input decoded.

        `nothing_still_names` asks the model about every identifier the removal would take away,
        and the model records this installation against the global it mints as the member
        expression rather than as an identifier, so the read through the installed name is a
        reference that question never reaches.
        """
        tail = """
            window.d = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var other = d(payload);
            """
        self.assertIn('function decode(x)', self._decode(tail))
