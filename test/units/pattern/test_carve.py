#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from .. import TestUnitBase


class TestCarve(TestUnitBase):

    def test_extract_base64(self):
        unit = self.load('b64', longest=True, take=1)
        data = B'%s-(VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==),%s' % (
            self.generate_random_buffer(11),
            self.generate_random_buffer(12)
        )
        self.assertEqual(unit(data), b'VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==')

    def test_extract_hex_01(self):
        unit = self.load('hex', whitespace=True, longest=True, take=1)
        data = (
            B'7937e4492b014445eede1b00006dd0bd05e55720849807014e5a120807c723e9\n'
            B'0400156bebd8d58deb76fc69ab284811c57a289ea374ea79d76c67edf154784c\n'
            B'748bf9e24ff68b23a75aaf24b09ce15ee28d53f53547bb412773d87d2430a105\n'
            B'ac21670811a40c5972fbcf02708e5bc893220c9f730c20d37dcf0e8a3ffa9c8f\n'
            B'90001a0a895a000494804e470d04452000001000000a9aaaa00e2f0000000900\n'
            B'80201ce9000004859730000009017352474200aec700ec400000ec4010000d95\n'
            B'b09c9e6adb6a1da556b9d5ef7331111414040524848020939fb91042c8440399\n'
            B'f0f492e798e4c3de1663ff799edbfb7f673d9bfb7e7bdf7da6b5d6b5dac53aff\n'
        )
        self.assertEqual(unit(data), data.replace(b'\n', B''))

    def test_extract_hex_02(self):
        unit = self.load('hex', min=8)
        self.assertEqual(
            unit(B'This is a mixed case hex string:42C56Ffe7da9c37481f26aFE1a06252f!'),
            B'42C56Ffe7da9c37481f26aFE1a06252f'
        )

    def test_extract_unicode_b64(self):
        data = bytes.fromhex(
            '65 00 2E 63 63 74 6F 72 00 00 00 17 41 00 62 00 6F 00 72 00 74 00 69 00 6E 00 67 00 2E 00 2E 00'
            '2E 00 00 C0 17 31 F9 49 00 77 00 42 00 79 00 41 00 47 00 55 00 41 00 63 00 51 00 42 00 31 00 41'
            '00 47 00 6B 00 41 00 63 00 67 00 42 00 6C 00 41 00 48 00 4D 00 41 00 49 00 41 00 41 00 74 00 41'
            '00 46 00 59 00 41 00 5A 00 51 00 42 00 79 00 41 00 48 00 4D 00 41 00 61 00 51 00 42 00 76 00 41'
            '00 47 00 34 00 41 00 49 00 41 00 41 00 79 00 41 00 41 00 30 00 41 00 43 00 67 00 41 00 3d 00'
        )
        unit = self.load('-ult1', 'b64')
        result = unit(data)
        result = base64.b64decode(result, validate=True).decode('utf-16LE')
        self.assertEqual('#requires -Version 2\r\n', result)
