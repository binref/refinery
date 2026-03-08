from ... import TestUnitBase

from refinery.lib.aria import ARIA
from refinery.lib.crypto import ECB


class TestARIA(TestUnitBase):

    def test_rfc5794_128(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        c = ARIA(key, ECB())
        ct = c.block_encrypt(pt)
        self.assertEqual(ct.hex(), 'd718fbd6ab644c739da95f3be6451778')
        self.assertEqual(c.block_decrypt(ct), pt)

    def test_rfc5794_192(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        c = ARIA(key, ECB())
        ct = c.block_encrypt(pt)
        self.assertEqual(ct.hex(), '26449c1805dbe7aa25a468ce263a9e79')
        self.assertEqual(c.block_decrypt(ct), pt)

    def test_rfc5794_256(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        c = ARIA(key, ECB())
        ct = c.block_encrypt(pt)
        self.assertEqual(ct.hex(), 'f92bd7c79fb72e2f2b8f80c1972d24fc')
        self.assertEqual(c.block_decrypt(ct), pt)

    def test_binary_refinery_vector(self):
        key = bytes.fromhex('112ceb500423df4153280c81dd5c634a')
        pt = bytes.fromhex('42696e61727920526566696e65727921')
        c = ARIA(key, ECB())
        ct = c.block_encrypt(pt)
        self.assertEqual(ct.hex(), '33eb72dcfbd7b225432fa73bb10d9e10')
        self.assertEqual(c.block_decrypt(ct), pt)

    def test_known_ciphertext(self):
        data = bytes.fromhex('33 eb 72 dc fb d7 b2 25 43 2f a7 3b b1 0d 9e 10')
        test = data | self.load('md5:refined', raw=True) | str
        self.assertEqual(test, "Binary Refinery!")

    def test_invertible_ecb(self):
        data = self.generate_random_buffer(256)
        for key_size in (16, 24, 32):
            key = bytes(range(key_size))
            encrypter = self.load(key, padding='raw', reverse=True)
            decrypter = self.load(key, padding='raw')
            self.assertEqual(data, bytes(data | encrypter | decrypter),
                F'ECB roundtrip failed for key size {key_size}')

    def test_invertible_cbc(self):
        data = self.generate_random_buffer(256)
        for key_size in (16, 24, 32):
            key = bytes(range(key_size))
            iv = bytes(range(16))
            encrypter = self.load(key, iv=iv, mode='CBC', padding='raw', reverse=True)
            decrypter = self.load(key, iv=iv, mode='CBC', padding='raw')
            self.assertEqual(data, bytes(data | encrypter | decrypter),
                F'CBC roundtrip failed for key size {key_size}')

    def test_invertible_ctr(self):
        data = self.generate_random_buffer(200)
        key = bytes(range(16))
        iv = bytes(range(16))
        encrypter = self.load(key, iv=iv, mode='CTR', raw=True, reverse=True)
        decrypter = self.load(key, iv=iv, mode='CTR', raw=True)
        self.assertEqual(data, bytes(data | encrypter | decrypter))
