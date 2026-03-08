from ... import TestUnitBase


class TestScrypt(TestUnitBase):

    def test_rfc7914_vector_1(self):
        unit = self.load(64, b'', memorycost=16, blocksize=1, parallelism=1)
        result = b'' | unit | bytes
        self.assertEqual(len(result), 64)
        self.assertEqual(result.hex(),
            '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442'
            'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906')

    def test_rfc7914_vector_2(self):
        unit = self.load(64, b'NaCl', memorycost=1024, blocksize=8, parallelism=16)
        result = b'password' | unit | bytes
        self.assertEqual(result.hex(),
            'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
            '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')

    def test_output_length(self):
        for size in (16, 32, 64, 128):
            unit = self.load(size, b'salt', memorycost=16, blocksize=1, parallelism=1)
            result = b'password' | unit | bytes
            self.assertEqual(len(result), size)

    def test_deterministic(self):
        unit = self.load(32, b'somesalt', memorycost=16, blocksize=1, parallelism=1)
        r1 = b'mypassword' | unit | bytes
        r2 = b'mypassword' | unit | bytes
        self.assertEqual(r1, r2)

    def test_different_salts(self):
        u1 = self.load(32, b'salt1', memorycost=16, blocksize=1, parallelism=1)
        u2 = self.load(32, b'salt2', memorycost=16, blocksize=1, parallelism=1)
        r1 = b'password' | u1 | bytes
        r2 = b'password' | u2 | bytes
        self.assertNotEqual(r1, r2)

    def test_different_passwords(self):
        unit = self.load(32, b'salt', memorycost=16, blocksize=1, parallelism=1)
        r1 = b'password1' | unit | bytes
        r2 = b'password2' | unit | bytes
        self.assertNotEqual(r1, r2)
