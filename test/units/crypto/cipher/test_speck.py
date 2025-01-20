from ... import TestUnitBase


class TestSpeck(TestUnitBase):

    def test_invertible(self):
        data = self.generate_random_buffer(256)
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            for key_size in (12, 16):
                encrypter = -self.load(range(key_size), mode=mode, block_size=8)
                decrypter = self.load(range(key_size), mode=mode, block_size=8)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')

            for key_size in (16, 24, 32):
                encrypter = -self.load(range(key_size), mode=mode, block_size=16)
                decrypter = self.load(range(key_size), mode=mode, block_size=16)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')

    def test_speck_64_96(self):
        plaintext = b"\x65\x61\x6e\x73\x20\x46\x61\x74"
        key = b"\x00\x01\x02\x03\x08\x09\x0a\x0b\x10\x11\x12\x13"
        cipher = b"\x6c\x94\x75\x41\xec\x52\x79\x9f"
        unit = self.load(key=key, padding='raw', block_size=8)
        self.assertEqual(plaintext | -unit | bytes, cipher)

    def test_speck_64_128(self):
        plaintext = b"\x2d\x43\x75\x74\x74\x65\x72\x3b"
        key = b"\x00\x01\x02\x03\x08\x09\x0a\x0b\x10\x11\x12\x13\x18\x19\x1a\x1b"
        cipher = b"\x8b\x02\x4e\x45\x48\xa5\x6f\x8c"
        unit = self.load(key=key, padding='raw', block_size=8)
        self.assertEqual(plaintext | -unit | bytes, cipher)

    def test_speck_128_128(self):
        plaintext = b"\x20\x6d\x61\x64\x65\x20\x69\x74\x20\x65\x71\x75\x69\x76\x61\x6c"
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        cipher = b"\x18\x0d\x57\x5c\xdf\xfe\x60\x78\x65\x32\x78\x79\x51\x98\x5d\xa6"
        unit = self.load(key=key, padding='raw' ,block_size=16)
        self.assertEqual(plaintext | -unit | bytes, cipher)

    def test_speck_128_192(self):
        plaintext = b"\x65\x6e\x74\x20\x74\x6f\x20\x43\x68\x69\x65\x66\x20\x48\x61\x72"
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
        cipher = b"\x86\x18\x3c\xe0\x5d\x18\xbc\xf9\x66\x55\x13\x13\x3a\xcf\xe4\x1b"
        unit = self.load(key=key, padding='raw', block_size=16)
        self.assertEqual(plaintext | -unit | bytes, cipher)

    def test_speck_128_256(self):
        plaintext = b"\x70\x6f\x6f\x6e\x65\x72\x2e\x20\x49\x6e\x20\x74\x68\x6f\x73\x65"
        key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        cipher = b"\x43\x8f\x18\x9c\x8d\xb4\xee\x4e\x3e\xf5\xc0\x05\x04\x01\x09\x41"
        unit = self.load(key=key, padding='raw', block_size=16)
        self.assertEqual(plaintext | -unit | bytes, cipher)
