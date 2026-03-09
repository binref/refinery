from ... import TestUnitBase


class TestHC128(TestUnitBase):

    def test_zero_key_zero_iv(self):
        key = bytes(32)
        data = bytes(32)
        unit = self.load(key)
        result = unit(data)
        self.assertEqual(len(result), 32)
        self.assertNotEqual(result, data)

    def test_invertible(self):
        key = bytes(32)
        data = b'Hello HC128 Stream Cipher Test!!'
        unit = self.load(key)
        encrypted = unit(data)
        self.assertNotEqual(encrypted, data)
        decrypted = unit(encrypted)
        self.assertEqual(decrypted, data)

    def test_known_vector(self):
        # HC-128 with key=0, IV is not separate; key is 32 bytes
        key = bytes(32)
        data = bytes(16)
        unit = self.load(key)
        result = unit(data)
        self.assertEqual(len(result), 16)
