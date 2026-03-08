from ... import TestUnitBase

from refinery.lib.simon import (
    simon_decrypt16,
    simon_decrypt24,
    simon_decrypt32,
    simon_decrypt48,
    simon_decrypt64,
    simon_encrypt16,
    simon_encrypt24,
    simon_encrypt32,
    simon_encrypt48,
    simon_encrypt64,
    simon_key_schedule_032_064,
    simon_key_schedule_048_072,
    simon_key_schedule_048_096,
    simon_key_schedule_064_096,
    simon_key_schedule_064_128,
    simon_key_schedule_096_096,
    simon_key_schedule_096_144,
    simon_key_schedule_128_128,
    simon_key_schedule_128_192,
    simon_key_schedule_128_256,
)


class TestSimon(TestUnitBase):

    def test_invertible(self):
        data = self.generate_random_buffer(256)
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            for key_size in (12, 16):
                encrypter = self.load(range(key_size), mode=mode, block_size=8, reverse=True)
                decrypter = self.load(range(key_size), mode=mode, block_size=8)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode} block_size=8 key_size={key_size}')

            for key_size in (16, 24, 32):
                encrypter = self.load(range(key_size), mode=mode, block_size=16, reverse=True)
                decrypter = self.load(range(key_size), mode=mode, block_size=16)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode} block_size=16 key_size={key_size}')

            for key_size in (8,):
                encrypter = self.load(range(key_size), mode=mode, block_size=4, reverse=True)
                decrypter = self.load(range(key_size), mode=mode, block_size=4)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode} block_size=4 key_size={key_size}')

            for key_size in (9, 12):
                encrypter = self.load(range(key_size), mode=mode, block_size=6, reverse=True)
                decrypter = self.load(range(key_size), mode=mode, block_size=6)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode} block_size=6 key_size={key_size}')

            for key_size in (12, 18):
                encrypter = self.load(range(key_size), mode=mode, block_size=12, reverse=True)
                decrypter = self.load(range(key_size), mode=mode, block_size=12)
                self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode} block_size=12 key_size={key_size}')

    def test_invertible_simon_64_96(self):
        data = self.generate_random_buffer(8)
        key = b'\x00\x01\x02\x03\x08\x09\x0a\x0b\x10\x11\x12\x13'
        enc = self.load(key=key, padding='raw', block_size=8, reverse=True)
        dec = self.load(key=key, padding='raw', block_size=8)
        self.assertEqual(data | enc | dec | bytes, data)

    def test_invertible_simon_64_128(self):
        data = self.generate_random_buffer(8)
        key = b'\x00\x01\x02\x03\x08\x09\x0a\x0b\x10\x11\x12\x13\x18\x19\x1a\x1b'
        enc = self.load(key=key, padding='raw', block_size=8, reverse=True)
        dec = self.load(key=key, padding='raw', block_size=8)
        self.assertEqual(data | enc | dec | bytes, data)

    def test_invertible_simon_128_128(self):
        data = self.generate_random_buffer(16)
        key = bytes(range(0x10))
        enc = self.load(key=key, padding='raw', block_size=16, reverse=True)
        dec = self.load(key=key, padding='raw', block_size=16)
        self.assertEqual(data | enc | dec | bytes, data)

    def test_invertible_simon_128_192(self):
        data = self.generate_random_buffer(16)
        key = bytes(range(0x18))
        enc = self.load(key=key, padding='raw', block_size=16, reverse=True)
        dec = self.load(key=key, padding='raw', block_size=16)
        self.assertEqual(data | enc | dec | bytes, data)

    def test_invertible_simon_128_256(self):
        data = self.generate_random_buffer(16)
        key = bytes(range(0x20))
        enc = self.load(key=key, padding='raw', block_size=16, reverse=True)
        dec = self.load(key=key, padding='raw', block_size=16)
        self.assertEqual(data | enc | dec | bytes, data)

    def test_invertible_ecb(self):
        data = self.generate_random_buffer(16)
        key = bytes(range(16))
        enc = self.load(key, padding='raw', block_size=16, reverse=True)
        dec = self.load(key, padding='raw', block_size=16)
        self.assertEqual(data, bytes(data | enc | dec))

    def test_invertible_ctr_mode(self):
        data = self.generate_random_buffer(100)
        key = bytes(range(16))
        iv = bytes(range(16))
        enc = self.load(key, iv=iv, mode='CTR', raw=True, block_size=16, reverse=True)
        dec = self.load(key, iv=iv, mode='CTR', raw=True, block_size=16)
        self.assertEqual(data, bytes(data | enc | dec))

    def test_known_vector_064_096(self):
        key = bytes(range(12))
        pt = bytes(range(8))
        rk = simon_key_schedule_064_096(key)
        ct = simon_encrypt32(pt, rk, 42)
        self.assertEqual(ct.hex(), '19b1c4c6aeb97982')
        self.assertEqual(simon_decrypt32(ct, rk, 42), pt)

    def test_known_vector_064_128(self):
        key = bytes(range(16))
        pt = bytes(range(8))
        rk = simon_key_schedule_064_128(key)
        ct = simon_encrypt32(pt, rk, 44)
        self.assertEqual(ct.hex(), '97055b8e938a895f')
        self.assertEqual(simon_decrypt32(ct, rk, 44), pt)

    def test_known_vector_128_128(self):
        key = bytes(range(16))
        pt = bytes(range(16))
        rk = simon_key_schedule_128_128(key)
        ct = simon_encrypt64(pt, rk, 68)
        self.assertEqual(ct.hex(), 'be82f3a471c42ae7c0328db2eda1ce92')
        self.assertEqual(simon_decrypt64(ct, rk, 68), pt)

    def test_known_vector_128_192(self):
        key = bytes(range(24))
        pt = bytes(range(16))
        rk = simon_key_schedule_128_192(key)
        ct = simon_encrypt64(pt, rk, 69)
        self.assertEqual(ct.hex(), '775f694562ce5cf261619de2bdbe7903')
        self.assertEqual(simon_decrypt64(ct, rk, 69), pt)

    def test_known_vector_128_256(self):
        key = bytes(range(32))
        pt = bytes(range(16))
        rk = simon_key_schedule_128_256(key)
        ct = simon_encrypt64(pt, rk, 72)
        self.assertEqual(ct.hex(), '708c031e1d44519f5d235198757c2394')
        self.assertEqual(simon_decrypt64(ct, rk, 72), pt)

    def test_paper_vector_064_096(self):
        key = bytes.fromhex('0001020308090a0b10111213')
        pt = bytes.fromhex('636c696e6720726f')
        rk = simon_key_schedule_064_096(key)
        ct = simon_encrypt32(pt, rk, 42)
        self.assertEqual(ct.hex(), 'c88f1a117fe2a25c')
        self.assertEqual(simon_decrypt32(ct, rk, 42), pt)

    def test_paper_vector_064_128(self):
        key = bytes.fromhex('0001020308090a0b1011121318191a1b')
        pt = bytes.fromhex('756e64206c696b65')
        rk = simon_key_schedule_064_128(key)
        ct = simon_encrypt32(pt, rk, 44)
        self.assertEqual(ct.hex(), '7aa0dfb920fcc844')
        self.assertEqual(simon_decrypt32(ct, rk, 44), pt)

    def test_paper_vector_128_128(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        pt = bytes.fromhex('2074726176656c6c6572732064657363')
        rk = simon_key_schedule_128_128(key)
        ct = simon_encrypt64(pt, rk, 68)
        self.assertEqual(ct.hex(), 'bc0b4ef82a83aa653ffe541e1e1b6849')
        self.assertEqual(simon_decrypt64(ct, rk, 68), pt)

    def test_paper_vector_128_192(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
        pt = bytes.fromhex('72696265207768656e20746865726520')
        rk = simon_key_schedule_128_192(key)
        ct = simon_encrypt64(pt, rk, 69)
        self.assertEqual(ct.hex(), '5bb897256e8d9c6c4f0ddcfcef61acc4')
        self.assertEqual(simon_decrypt64(ct, rk, 69), pt)

    def test_paper_vector_128_256(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        pt = bytes.fromhex('697320612073696d6f6f6d20696e2074')
        rk = simon_key_schedule_128_256(key)
        ct = simon_encrypt64(pt, rk, 72)
        self.assertEqual(ct.hex(), '68b8e7ef872af73ba0a3c8af79552b8d')
        self.assertEqual(simon_decrypt64(ct, rk, 72), pt)

    def test_paper_vector_032_064(self):
        key = bytes([0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19])
        pt = bytes([0x77, 0x68, 0x65, 0x65])
        ct_expected = bytes([0xBB, 0xE9, 0x9B, 0xC6])
        rk = simon_key_schedule_032_064(key)
        ct = simon_encrypt16(pt, rk, 32)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt16(ct, rk, 32), pt)

    def test_paper_vector_048_072(self):
        key = bytes([0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12])
        pt = bytes([0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61])
        ct_expected = bytes([0xAC, 0x2C, 0x29, 0xAC, 0xE5, 0xDA])
        rk = simon_key_schedule_048_072(key)
        ct = simon_encrypt24(pt, rk, 36)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt24(ct, rk, 36), pt)

    def test_paper_vector_048_096(self):
        key = bytes([0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a])
        pt = bytes([0x6e, 0x64, 0x20, 0x63, 0x69, 0x72])
        ct_expected = bytes([0x56, 0xf1, 0xac, 0xa5, 0x06, 0x6e])
        rk = simon_key_schedule_048_096(key)
        ct = simon_encrypt24(pt, rk, 36)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt24(ct, rk, 36), pt)

    def test_paper_vector_096_096(self):
        key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D])
        pt = bytes([0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x69, 0x6c, 0x6c, 0x61, 0x72, 0x20])
        ct_expected = bytes([0x82, 0xf0, 0x8f, 0x3d, 0x06, 0x69, 0xb4, 0x62, 0xa4, 0x07, 0x28, 0x60])
        rk = simon_key_schedule_096_096(key)
        ct = simon_encrypt48(pt, rk, 52)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt48(ct, rk, 52), pt)

    def test_paper_vector_096_144(self):
        key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15])
        pt = bytes([0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74])
        ct_expected = bytes([0xe9, 0x1a, 0xdb, 0xc5, 0x59, 0x3f, 0x1e, 0x45, 0x6c, 0x1c, 0xad, 0xec])
        rk = simon_key_schedule_096_144(key)
        ct = simon_encrypt48(pt, rk, 54)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt48(ct, rk, 54), pt)

    def test_blogspot_simon_48_72(self):
        # https://cryptotestvectors.blogspot.com/2015/02/simon4872-test-vectors.html
        # Blog writes words in big-endian MSW-first; converted to LE byte arrays here.
        pt = bytes.fromhex('6c696e672061')
        key = bytes.fromhex('00010208090a101112')
        ct_expected = bytes.fromhex('ac2c29ace5da')
        rk = simon_key_schedule_048_072(key)
        ct = simon_encrypt24(pt, rk)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt24(ct, rk), pt)

    def test_blogspot_simon_48_96(self):
        # https://cryptotestvectors.blogspot.com/2015/02/blog-post.html
        # Blog writes words in big-endian MSW-first; converted to LE byte arrays here.
        pt = bytes.fromhex('6e6420636972')
        key = bytes.fromhex('00010208090a10111218191a')
        ct_expected = bytes.fromhex('56f1aca5066e')
        rk = simon_key_schedule_048_096(key)
        ct = simon_encrypt24(pt, rk)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt24(ct, rk), pt)

    def test_blogspot_simon_32_64(self):
        # https://cryptotestvectors.blogspot.com/2015/01/simon32-test-vectors.html
        # Blog writes words in big-endian MSW-first; converted to LE byte arrays here.
        pt = bytes.fromhex('77686565')
        key = bytes.fromhex('0001080910111819')
        ct_expected = bytes.fromhex('bbe99bc6')
        rk = simon_key_schedule_032_064(key)
        ct = simon_encrypt16(pt, rk)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt16(ct, rk), pt)

    def test_blogspot_simon_64_96(self):
        # https://cryptotestvectors.blogspot.com/2015/02/simon-6496-test-vectors.html
        # Blog writes words in big-endian MSW-first; converted to LE byte arrays here.
        pt = bytes.fromhex('636c696e6720726f')
        key = bytes.fromhex('0001020308090a0b10111213')
        ct_expected = bytes.fromhex('c88f1a117fe2a25c')
        rk = simon_key_schedule_064_096(key)
        ct = simon_encrypt32(pt, rk)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt32(ct, rk), pt)

    def test_blogspot_simon_64_128(self):
        # https://cryptotestvectors.blogspot.com/2015/02/simon-64128-test-vectors.html
        # Blog writes words in big-endian MSW-first; converted to LE byte arrays here.
        pt = bytes.fromhex('756e64206c696b65')
        key = bytes.fromhex('0001020308090a0b1011121318191a1b')
        ct_expected = bytes.fromhex('7aa0dfb920fcc844')
        rk = simon_key_schedule_064_128(key)
        ct = simon_encrypt32(pt, rk)
        self.assertEqual(ct, ct_expected)
        self.assertEqual(simon_decrypt32(ct, rk), pt)
