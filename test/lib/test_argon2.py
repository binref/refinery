import pytest
import unittest

from refinery.lib.fast.argon2 import (
    ARGON2D,
    ARGON2I,
    ARGON2ID,
    argon2hash,
)


@pytest.mark.cythonized
class TestArgon2RFC9106(unittest.TestCase):
    """
    RFC 9106 test vectors with the reference parameters.
    """

    PASSWORD = bytes([0x01] * 32)
    SALT = bytes([0x02] * 16)
    SECRET = bytes([0x03] * 8)
    AD = bytes([0x04] * 12)

    TIME_COST = 3
    MEMORY_COST = 32
    PARALLELISM = 4
    TAG_LENGTH = 32

    def _run(self, variant: int) -> bytes:
        return argon2hash(
            password=self.PASSWORD,
            salt=self.SALT,
            time_cost=self.TIME_COST,
            memory_cost=self.MEMORY_COST,
            parallelism=self.PARALLELISM,
            tag_length=self.TAG_LENGTH,
            variant=variant,
            secret=self.SECRET,
            associated_data=self.AD,
        )

    def test_argon2d(self):
        tag = self._run(ARGON2D)
        expected = bytes.fromhex(
            '51 2b 39 1b 6f 11 62 97'
            '53 71 d3 09 19 73 42 94'
            'f8 68 e3 be 39 84 f3 c1'
            'a1 3a 4d b9 fa be 4a cb'.replace(' ', '')
        )
        self.assertEqual(tag, expected)

    def test_argon2i(self):
        tag = self._run(ARGON2I)
        expected = bytes.fromhex(
            'c8 14 d9 d1 dc 7f 37 aa'
            '13 f0 d7 7f 24 94 bd a1'
            'c8 de 6b 01 6d d3 88 d2'
            '99 52 a4 c4 67 2b 6c e8'.replace(' ', '')
        )
        self.assertEqual(tag, expected)

    def test_argon2id(self):
        tag = self._run(ARGON2ID)
        expected = bytes.fromhex(
            '0d 64 0d f5 8d 78 76 6c'
            '08 c0 37 a3 4a 8b 53 c9'
            'd0 1e f0 45 2d 75 b6 5e'
            'b5 25 20 e9 6b 01 e6 59'.replace(' ', '')
        )
        self.assertEqual(tag, expected)


@pytest.mark.cythonized
class TestArgon2Validation(unittest.TestCase):
    """Test parameter validation."""

    def test_invalid_variant(self):
        with self.assertRaises(ValueError):
            argon2hash(b'pass', b'salt', 1, 32, 1, 32, variant=99)

    def test_time_cost_too_low(self):
        with self.assertRaises(ValueError):
            argon2hash(b'pass', b'salt', 0, 32, 1, 32)

    def test_parallelism_too_low(self):
        with self.assertRaises(ValueError):
            argon2hash(b'pass', b'salt', 1, 32, 0, 32)

    def test_tag_length_too_short(self):
        with self.assertRaises(ValueError):
            argon2hash(b'pass', b'salt', 1, 32, 1, 3)


@pytest.mark.cythonized
class TestArgon2Basic(unittest.TestCase):
    def test_deterministic(self):
        hashes = set()
        for _ in range(12):
            hashes.add(argon2hash(password=b'password', salt=b'saltsalt', time_cost=1, memory_cost=16, parallelism=1, tag_length=32))
        self.assertEqual(len(hashes), 1)

    def test_different_passwords_differ(self):
        a = argon2hash(password=b'alpha', salt=b'saltsalt', time_cost=1, memory_cost=16, parallelism=1, tag_length=32)
        b = argon2hash(password=b'bravo', salt=b'saltsalt', time_cost=1, memory_cost=16, parallelism=1, tag_length=32)
        self.assertNotEqual(a, b)

    def test_tag_length_respected(self):
        for n in (4, 16, 32, 64, 128):
            tag = argon2hash(password=b'test', salt=b'saltsalt', time_cost=1, memory_cost=16, parallelism=1, tag_length=n)
            self.assertEqual(len(tag), n)
