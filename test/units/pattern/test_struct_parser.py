import struct

from .. import TestUnitBase


class TestStructParser(TestUnitBase):

    def test_parse_simple_int(self):
        data = struct.pack('<I', 0x12345678)
        unit = self.load('I', '{#}')
        result = next(data | unit)
        self.assertEqual(bytes(result), data)

    def test_parse_named_fields(self):
        name_bytes = b'hello'
        data = struct.pack('<I', 42) + name_bytes + b'\x00'
        unit = self.load('I{name:a}', '{name}')
        result = next(data | unit)
        self.assertEqual(bytes(result), name_bytes)

    def test_parse_two_ints(self):
        data = struct.pack('<II', 0xDEADBEEF, 0xCAFEBABE)
        unit = self.load('II')
        result = list(data | unit)
        self.assertEqual(len(result), 1)

    def test_parse_multi_mode(self):
        data = struct.pack('<HHH', 1, 2, 3)
        unit = self.load('H', multi=True)
        result = list(data | unit)
        self.assertEqual(len(result), 3)

    def test_parse_null_terminated_string(self):
        data = b'hello\x00rest'
        unit = self.load('{name:a}', '{name}')
        result = next(data | unit)
        self.assertEqual(bytes(result), b'hello')
