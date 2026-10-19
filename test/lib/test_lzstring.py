"""
Decompression of the lz-string format: the strings an obfuscator compressed with the library come
back as the library returns them.
"""
from __future__ import annotations

from test import TestBase

from refinery.lib.lzstring import decompress_from_utf16

#: The strings of a small program, compressed by the library an obfuscator inserted into its output.
STRINGS_OF_A_PROGRAM = '\u0C62\u2C37\u4C27\u6062\u0590\u6420\u75A1\u4E20\u5A60\u2B23\u6C60\u1DC4\x8D\u582E\u34B4\u0490\u202B\u4021\u0820 '


class TestDecompressFromUTF16(TestBase):

    def test_the_strings_of_a_program_come_back_in_order(self):
        self.assertEqual(decompress_from_utf16(STRINGS_OF_A_PROGRAM), 'Fizz|Buzz|push|join|log|FizzBuzz: ')

    def test_the_empty_string_decompresses_to_null(self):
        self.assertIsNone(decompress_from_utf16(''))

    def test_a_stream_naming_an_entry_the_dictionary_does_not_hold_decompresses_to_null(self):
        self.assertIsNone(decompress_from_utf16('\u4e00\u4e01\u4e02'))

    def test_a_first_code_the_library_has_no_case_for_raises(self):
        with self.assertRaises(ValueError):
            decompress_from_utf16('\u6020\u4000\u4000')

    def test_an_output_longer_than_the_limit_raises(self):
        with self.assertRaises(ValueError):
            decompress_from_utf16(STRINGS_OF_A_PROGRAM, 20)

    def test_an_output_within_the_limit_comes_back(self):
        self.assertEqual(decompress_from_utf16(STRINGS_OF_A_PROGRAM, 34), 'Fizz|Buzz|push|join|log|FizzBuzz: ')
