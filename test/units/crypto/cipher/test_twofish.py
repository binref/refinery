from ... import TestUnitBase

from refinery.lib.twofish import Twofish
from refinery.lib.crypto import ECB


class TestTwofish(TestUnitBase):

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

    def test_invertible_ofb(self):
        data = self.generate_random_buffer(200)
        key = bytes(range(16))
        iv = bytes(range(16))
        encrypter = self.load(key, iv=iv, mode='OFB', raw=True, reverse=True)
        decrypter = self.load(key, iv=iv, mode='OFB', raw=True)
        self.assertEqual(data, bytes(data | encrypter | decrypter))

    def test_invertible_cfb(self):
        data = self.generate_random_buffer(200)
        key = bytes(range(16))
        iv = bytes(range(16))
        encrypter = self.load(key, iv=iv, mode='CFB', raw=True, reverse=True)
        decrypter = self.load(key, iv=iv, mode='CFB', raw=True)
        self.assertEqual(data, bytes(data | encrypter | decrypter))

    def test_invertible_pcbc(self):
        data = self.generate_random_buffer(256)
        key = bytes(range(16))
        iv = bytes(range(16))
        encrypter = self.load(key, iv=iv, mode='PCBC', padding='raw', reverse=True)
        decrypter = self.load(key, iv=iv, mode='PCBC', padding='raw')
        self.assertEqual(data, bytes(data | encrypter | decrypter))

    def test_known_vector_128(self):
        key = bytes(16)
        tf = Twofish(key, ECB())
        pt = bytes(16)
        ct = tf.block_encrypt(pt)
        self.assertEqual(ct.hex().upper(), '9F589F5CF6122C32B6BFEC2F2AE8C35A')

    def test_known_vector_192(self):
        tf = Twofish(bytes(24), ECB())
        ct = tf.block_encrypt(bytes(16))
        self.assertEqual(ct.hex().upper(), 'EFA71F788965BD4453F860178FC19101')

    def test_known_vector_256(self):
        key = bytes(32)
        tf = Twofish(key, ECB())
        pt = bytes(16)
        ct = tf.block_encrypt(pt)
        self.assertEqual(ct.hex().upper(), '57FF739D4DC92C1BD7FC01700CC8216F')

    def test_known_vector_128_sequential_key(self):
        tf = Twofish(bytes(range(16)), ECB())
        ct = tf.block_encrypt(bytes(range(16)))
        self.assertEqual(ct.hex().upper(), '9FB63337151BE9C71306D159EA7AFAA4')
        self.assertEqual(tf.block_decrypt(ct), bytes(range(16)))

    def test_known_vector_256_sequential_key(self):
        tf = Twofish(bytes(range(32)), ECB())
        ct = tf.block_encrypt(bytes(range(16)))
        self.assertEqual(ct.hex().upper(), '8EF0272C42DB838BCF7B07AF0EC30F38')
        self.assertEqual(tf.block_decrypt(ct), bytes(range(16)))

    def test_iterated_vector_128(self):
        ct0 = bytes.fromhex('9F589F5CF6122C32B6BFEC2F2AE8C35A')
        tf = Twofish(ct0, ECB())
        ct1 = tf.block_encrypt(ct0)
        self.assertEqual(ct1.hex().upper(), '1B1B186DFE4F1FC4385BC76FF3CA4027')

    def test_known_ciphertext(self):
        data = bytes.fromhex(
            'F036A7AAEAD1A81BFAEAE6C3CB0B7C5E000EE20E2C33667FEF'
            '72B2948FE32A0E93BCB636F96402D847719F736F8B06F92563'
            '0ECEEFF802531B1608D1008D9AA7')
        test = data | self.load(B'BINARY.REFINERY.') | str
        self.assertEqual(test, 'The Binary Refinery refines the Finest Binaries.')

    def test_block_encrypt_decrypt_roundtrip(self):
        for key_size in (16, 24, 32):
            key = self.generate_random_buffer(key_size)
            tf = Twofish(key, ECB())
            pt = self.generate_random_buffer(16)
            ct = tf.block_encrypt(pt)
            self.assertNotEqual(pt, ct)
            pt2 = tf.block_decrypt(ct)
            self.assertEqual(pt, pt2)

    def test_padding_pkcs7(self):
        data = b'Hello, Twofish!'
        key = bytes(range(16))
        encrypter = self.load(key, padding='pkcs7', reverse=True)
        decrypter = self.load(key, padding='pkcs7')
        self.assertEqual(data, bytes(data | encrypter | decrypter))

    def test_all_key_sizes_via_unit(self):
        data = self.generate_random_buffer(48)
        for ks in (16, 24, 32):
            key = self.generate_random_buffer(ks)
            enc = self.load(key, padding='raw', reverse=True)
            dec = self.load(key, padding='raw')
            self.assertEqual(data, bytes(data | enc | dec))
