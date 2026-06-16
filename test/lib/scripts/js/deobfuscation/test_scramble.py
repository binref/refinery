from __future__ import annotations

import inspect

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
