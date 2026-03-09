import base64

from ... import TestUnitBase


class TestSecStr(TestUnitBase):

    def test_roundtrip_default_key(self):
        unit = self.load()
        plaintext = b'MySecretPassword'
        self.assertEqual(plaintext | -unit | unit | bytes, plaintext)

    def test_roundtrip_custom_key(self):
        key = bytes(range(1, 17))
        unit = self.load(key)
        plaintext = b'TestPassword123'
        self.assertEqual(plaintext | -unit | unit | bytes, plaintext)

    def test_output_is_base64(self):
        unit = self.load()
        encrypted = b'test' | -unit | bytes
        try:
            base64.b64decode(encrypted)
        except Exception:
            self.fail('secstr output is not valid base64')

    def test_handles_valid_header(self):
        from refinery.units.crypto.cipher.secstr import secstr
        unit = self.load()
        encrypted = b'hello' | -unit | bytes
        self.assertTrue(secstr.handles(encrypted))

    def test_handles_rejects_invalid(self):
        from refinery.units.crypto.cipher.secstr import secstr
        self.assertFalse(secstr.handles(b'not a secure string'))
