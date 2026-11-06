from __future__ import annotations

import inspect

from test import backlog
from test.lib.scripts.js.analysis.differential import deobfuscate_within
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import printed

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.scramble import JsScrambleStringDecoder, ScrambleCipher
from refinery.lib.scripts.js.options import DeobfuscationOptions


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

    @backlog
    def test_a_cipher_whose_key_derivation_and_decryption_the_file_does_not_define_is_left_alone(self):
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
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), printed(source))

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

    @backlog
    def test_a_cipher_the_file_does_not_define_installed_under_a_computed_global_name_is_left_alone(self):
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
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), printed(source))

    @backlog
    def test_a_cipher_the_file_does_not_define_installed_on_global_is_left_alone(self):
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
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), printed(source))

    @backlog
    def test_a_decoder_install_through_a_host_conditional_alias_keeps_its_base_throw(self):
        """
        In a browser, which has no `global`, the statement `global.decode = decode` throws a
        `ReferenceError`, so it has to stay in the output.
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

    @backlog
    def test_a_cipher_the_file_does_not_define_installed_on_global_in_node_is_left_alone(self):
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
        self.assertEqual(
            self._run_transformer(
                source, JsScrambleStringDecoder, DeobfuscationOptions(environment=HostEnvironment.node)),
            printed(source),
        )

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
        deobfuscated = deobfuscate_within(source, seconds=30)
        if deobfuscated is None:
            self.fail('recognizing the cipher did not terminate')
        return deobfuscated

    _ENCODED = 'hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg='

    def _assert_not_decoded(self, source: str):
        deobfuscated = self._deobfuscate_bounded(source)
        machinery, _, _ = source.partition('function decode(x) {')
        self.assertIn(machinery, deobfuscated)
        self.assertIn(F"decode('{self._ENCODED}')", deobfuscated)

    def _declines(self, iterations: str, rounds: str):
        self._assert_not_decoded(self._cipher(iterations, rounds))

    @backlog
    def test_counts_the_pass_can_honour_decode_no_cipher_the_file_does_not_define(self):
        self._declines('200000', '3')

    def test_an_iteration_count_past_the_bound_is_not_this_cipher(self):
        self._declines('1e12', '3')

    def test_a_round_count_past_the_bound_is_not_this_cipher(self):
        self._declines('200000', '1e12')

    def test_a_zero_iteration_count_is_not_this_cipher(self):
        """
        Node's `crypto.pbkdf2Sync` throws a `RangeError` for an iteration count below one, so a
        count of zero derives no key.
        """
        self._declines('0', '3')

    def test_a_zero_round_count_is_not_this_cipher(self):
        self._declines('200000', '0')

    def test_a_count_that_is_not_a_literal_is_not_this_cipher(self):
        self._declines('200000', 'n')

    _A_CIPHER_CLASS_WITH_A_FIELD = {
        'a field holding the round count': inspect.cleandoc(
            """
            class Scramble {
              rounds = 4;
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
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
        ),
        'a field shadowing the decode method': inspect.cleandoc(
            """
            class Scramble {
              decode = input => input;
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
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
        ),
        'a field without an initializer shadowing the decode method': inspect.cleandoc(
            """
            class Scramble {
              decode;
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
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
        ),
    }
    """
    The program of `test_counts_the_pass_can_honour_decode_no_cipher_the_file_does_not_define` with
    a field written without `static` in the class. The field puts a property on every instance, so
    `instance.decode` or `this.rounds` may be the field's value rather than what the methods of the
    class say.
    """

    def test_a_class_with_a_field_is_not_this_cipher(self):
        for label, source in self._A_CIPHER_CLASS_WITH_A_FIELD.items():
            with self.subTest(label):
                self._assert_not_decoded(source)

    @backlog
    def test_a_cipher_the_file_does_not_define_installed_under_a_global_string_key_is_left_alone(self):
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
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), printed(source))


class TestTheInstallationOfADecoderIsKeptWhereACallStillReachesIt(TestJsDeobfuscator):

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

    @backlog
    def test_a_cipher_the_file_does_not_define_installed_on_an_object_a_declaration_holds_is_left_alone(self):
        tail = """
            var self = {};
            self.d = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var other = self.d(payload);
            """
        self.assertEqual(self._decode(tail), printed(F'{self._MACHINERY}\n{inspect.cleandoc(tail)}'))

    def test_a_decoder_put_on_a_declared_object_stays_while_a_call_reads_it_back(self):
        tail = """
            var self = {};
            self.d = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var other = self.d(payload);
            """
        machinery_kept_and_the_literal_call_decoded = inspect.cleandoc(
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
        left_alone = printed(F'{self._MACHINERY}\n{inspect.cleandoc(tail)}')
        self.assertIn(self._decode(tail), (machinery_kept_and_the_literal_call_decoded, left_alone))

    @backlog
    def test_an_installation_on_the_global_object_is_kept_where_a_call_reads_the_name(self):
        tail = """
            window.d = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var other = d(payload);
            """
        self.assertIn('function decode(x)', self._decode(tail))
