from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1ConstantFolding,
    Ps1TypeCasts,
)


class TestPs1CharIntFolding(TestPs1):

    def test_char_int_literal(self):
        result = self._deobfuscate('[Char][int]83')
        self.assertEqual(result.strip(), "'S'")

    def test_char_literal_regression(self):
        result = self._deobfuscate('[Char]65')
        self.assertEqual(result.strip(), "'A'")

    def test_char_int_concat(self):
        result = self._deobfuscate_iterative('([Char][int]72 + [Char][int]105)')
        self.assertEqual(result.strip(), "'Hi'")

    def test_char_int_negative_not_folded(self):
        result = self._deobfuscate('[Char][int](-65)')
        self.assertNotIn("'", result)

    def test_int_identity_cast_stripped(self):
        result = self._deobfuscate('[int]42')
        self.assertEqual(result.strip(), '42')

    def test_int_cast_string(self):
        result = self._deobfuscate("[int]'27'")
        self.assertIn('27', result)
        self.assertNotIn("'", result)

    def test_int_cast_from_array_index(self):
        result = self._deobfuscate("$x = [int](('10', '20', '30')[2])")
        self.assertIn('30', result)
        self.assertNotIn("'30'", result)

    def test_array_literal_index_scalar(self):
        result = self._deobfuscate("$x = ('hello', 'world', 'foo')[2]")
        self.assertIn('foo', result)
        self.assertNotIn('hello', result)

    def test_array_literal_index_nested(self):
        result = self._deobfuscate(
            "$x = ('a', 'b', 'c', 'd')[[int](('3', '1', '0')[2])]")
        self.assertNotIn("'b'", result)
        self.assertNotIn("'c'", result)
        self.assertNotIn("'d'", result)

    def test_char_int_multi_concat(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]116 + [Char][int]111 + [Char][int]112)')
        self.assertEqual(result.strip(), "'Stop'")

    def test_char_int_partial_with_variable(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]$x + [Char][int]112)')
        # $x is undefined -> $null -> [int]0 -> [char]0, which is a NUL character (not empty), so
        # the folded result is the three-character string "S\0p".
        self.assertIn("S`0p", result)


class TestPs1TypeCastExtra(TestPs1):

    def test_typecast_char(self):
        data = '[char]120'
        result = self._deobfuscate(data)
        self.assertIn('x', result)

    def test_typecast_char_hex(self):
        data = '[char]0x41'
        result = self._deobfuscate(data)
        self.assertIn('A', result)

    def test_typecast_string_strip(self):
        data = '[string]"foo"'
        result = self._deobfuscate(data)
        self.assertIn('foo', result)
        self.assertNotIn('[string]', result)

    def test_typecast_char_array(self):
        data = '[char[]](72,101,108,108,111)'
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_as_char_cast(self):
        result = self._deobfuscate('(45 -As [Char])')
        self.assertIn("'-'", result)
        self.assertNotIn('-As', result)

    def test_type_cast_string_to_type_expression(self):
        result = self._deobfuscate("[Type]'Convert'")
        self.assertIn('[Convert]', result)
        self.assertNotIn("'Convert'", result)

    def test_useless_string_cast(self):
        result = self._deobfuscate('''$snug.replAce(("M0I"),[strIng]"'")''')
        self.assertIn("'", result)
        self.assertNotIn('[strIng]', result)

    def test_char_cast_in_bmp_folds(self):
        self.assertEqual("'A'", self._apply('[char]65', Ps1TypeCasts))

    def test_char_cast_rejects_above_bmp(self):
        # `[char]` is a UTF-16 code unit; a code point above U+FFFF is rejected, not folded.
        result = self._apply('[char]65536', Ps1TypeCasts)
        self.assertNotIn(chr(65536), result)

    def test_char_zero_is_nul_character(self):
        # [char]0 is a NUL character, not an empty string: 'a'+[char]0+'b' is the 3-character
        # string "a\0b". Verified against PowerShell (.Length == 3, char codes 97, 0, 98); the NUL
        # is simply not rendered on the console, and is emitted as the `0 escape.
        result = self._apply("'a' + [char]0 + 'b'", Ps1TypeCasts, Ps1ConstantFolding)
        self.assertEqual(result, '"a`0b"')
