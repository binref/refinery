from refinery.lib.crypto import (
    pad_iso7816,
    pad_pkcs7,
    pad_x923,
    unpad_iso7816,
    unpad_pkcs7,
    unpad_x923,
    rotl128,
    rotr128,
    rotl64,
    rotr64,
    rotl48,
    rotr48,
    rotl32,
    rotr32,
    rotl24,
    rotr24,
    rotl16,
    rotr16,
    rotl8,
    rotr8,
    rotl,
    rotr,
    strxor,
    Padding,
    pad,
    unpad,
    ECB,
    CBC,
    CTR,
    OFB,
    CFB,
    PCBC,
    CIPHER_MODES,
    DataUnaligned,
    Operation,
    BlockCipher,
    BlockCipherFactory,
)
from .. import TestBase


class TestCryptoLib(TestBase):

    def test_padding(self):
        for block_size in (7, 8, 16):
            for size in (
                block_size + 3,
                block_size + 4,
                block_size - 2,
                block_size - 3,
            ):
                original = self.generate_random_buffer(size)
                buffer = bytearray(original)

                for i, _pad in enumerate((pad_pkcs7, pad_x923, pad_iso7816), 1):
                    _pad(buffer, block_size)
                    proper_unpad = None
                    for j, _unpad in enumerate((unpad_pkcs7, unpad_x923, unpad_iso7816), 1):
                        if i == j:
                            proper_unpad = _unpad
                            continue
                        with self.assertRaises(ValueError, msg=(
                            F'Buffer of size {size} for block size {block_size} padded with '
                            F'method {i} was successfully unpadded with method {j}.'
                        )):
                            _unpad(buffer, block_size)
                    assert proper_unpad is not None
                    proper_unpad(buffer, block_size)
                    self.assertEqual(original, buffer)

    def test_pad_unpad_enum(self):
        data = bytearray(b'Hello World!')
        original = bytearray(data)
        pad(data, 16, Padding.PKCS7)
        self.assertEqual(len(data), 16)
        unpad(data, 16, Padding.PKCS7)
        self.assertEqual(data, original)

        data = bytearray(b'Hello World!')
        pad(data, 16, Padding.X923)
        self.assertEqual(len(data), 16)
        unpad(data, 16, Padding.X923)
        self.assertEqual(data, original)

        data = bytearray(b'Hello World!')
        pad(data, 16, Padding.ISO7816)
        unpad(data, 16, Padding.ISO7816)
        self.assertEqual(data, original)

    def test_pad_invalid_method(self):
        data = bytearray(b'Hello')
        with self.assertRaises(ValueError):
            pad(data, 8, 'invalid_method')

    def test_unpad_invalid_method(self):
        data = bytearray(b'Hello\x03\x03\x03')
        with self.assertRaises(ValueError):
            unpad(data, 8, 'invalid_method')

    def test_rotl32_rotr32_inverse(self):
        for value in (0x12345678, 0xDEADBEEF, 0x00000001, 0x80000000):
            for shift in range(0, 32):
                self.assertEqual(rotr32(rotl32(value, shift), shift), value)

    def test_rotl64_rotr64_inverse(self):
        for value in (0x123456789ABCDEF0, 0xDEADBEEFCAFEBABE):
            for shift in range(0, 64, 8):
                self.assertEqual(rotr64(rotl64(value, shift), shift), value)

    def test_rotl8_rotr8_inverse(self):
        for value in range(256):
            for shift in range(8):
                self.assertEqual(rotr8(rotl8(value, shift), shift), value)

    def test_rotl_rotr_generic(self):
        for n in (12, 20, 24):
            mask = (1 << n) - 1
            value = 0xABC & mask
            for shift in range(n):
                self.assertEqual(rotr(n, rotl(n, value, shift), shift), value)

    def test_strxor(self):
        self.assertEqual(strxor(b'\x00\xFF\xAA', b'\xFF\xFF\x55'), b'\xFF\x00\xFF')

    def test_strxor_different_lengths(self):
        self.assertEqual(strxor(b'\xFF\xFF\xFF', b'\x00\xFF'), b'\xFF\x00')

    def test_cipher_modes_registered(self):
        self.assertIn('ECB', CIPHER_MODES)
        self.assertIn('CBC', CIPHER_MODES)
        self.assertIn('CTR', CIPHER_MODES)
        self.assertIn('OFB', CIPHER_MODES)
        self.assertIn('CFB', CIPHER_MODES)
        self.assertIn('PCBC', CIPHER_MODES)

    def test_ecb_encrypt_decrypt(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xFF for b in data)

        def fake_decrypt(data):
            return bytes(b ^ 0xFF for b in data)

        mode = ECB()
        plaintext = b'\x01\x02\x03\x04'
        dst = memoryview(bytearray(len(plaintext)))
        from refinery.lib.crypto import Operation
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_decrypt, 4)
        ciphertext = bytes(dst)
        self.assertEqual(ciphertext, b'\xFE\xFD\xFC\xFB')
        mode.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_decrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_data_unaligned_error(self):
        e = DataUnaligned(8, 3)
        self.assertIn('8', str(e))
        self.assertIn('3', str(e))

    def test_unpad_pkcs7_invalid_pad_byte(self):
        data = bytearray(b'Hello\x00\x00\x09')
        with self.assertRaises(ValueError):
            unpad_pkcs7(data, 8)

    def test_unpad_x923_invalid_pad_byte(self):
        data = bytearray(b'Hello\x01\x01\x03')
        with self.assertRaises(ValueError):
            unpad_x923(data, 8)

    def test_rotl16_rotr16_inverse(self):
        for value in (0x1234, 0xABCD, 0x0001, 0x8000):
            for shift in range(16):
                self.assertEqual(rotr16(rotl16(value, shift), shift), value)

    def test_rotl24_rotr24_inverse(self):
        for value in (0x123456, 0xABCDEF, 0x000001, 0x800000):
            for shift in range(24):
                self.assertEqual(rotr24(rotl24(value, shift), shift), value)

    def test_rotl48_rotr48_inverse(self):
        for value in (0x123456789ABC, 0xABCDEF012345, 0x000000000001, 0x800000000000):
            for shift in range(0, 48, 4):
                self.assertEqual(rotr48(rotl48(value, shift), shift), value)

    def test_rotl128_rotr128_inverse(self):
        for value in (0x0123456789ABCDEF0123456789ABCDEF, 0x1, 1 << 127):
            for shift in range(0, 128, 16):
                self.assertEqual(rotr128(rotl128(value, shift), shift), value)

    def test_rotl32_known_values(self):
        self.assertEqual(rotl32(0x00000001, 1), 0x00000002)
        self.assertEqual(rotl32(0x80000000, 1), 0x00000001)
        self.assertEqual(rotl32(0x12345678, 0), 0x12345678)

    def test_rotr32_known_values(self):
        self.assertEqual(rotr32(0x00000002, 1), 0x00000001)
        self.assertEqual(rotr32(0x00000001, 1), 0x80000000)
        self.assertEqual(rotr32(0x12345678, 0), 0x12345678)

    def test_rotl_rotr_generic_arbitrary_widths(self):
        for n in (5, 7, 10, 13, 17, 31):
            mask = (1 << n) - 1
            for value in (1, mask, mask >> 1, 0):
                for shift in range(n):
                    self.assertEqual(rotr(n, rotl(n, value, shift), shift), value)

    def test_rotl_rotr_generic_shift_larger_than_n(self):
        n = 12
        value = 0xABC
        for shift in (n, n + 3, 2 * n, 2 * n + 5):
            self.assertEqual(rotr(n, rotl(n, value, shift), shift), value)

    def test_strxor_empty(self):
        self.assertEqual(strxor(b'', b''), b'')
        self.assertEqual(strxor(b'\xFF', b''), b'')
        self.assertEqual(strxor(b'', b'\xFF'), b'')

    def test_strxor_self(self):
        data = b'\x12\x34\x56\x78'
        self.assertEqual(strxor(data, data), b'\x00\x00\x00\x00')

    def test_unpad_iso7816_no_marker(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08')
        with self.assertRaises(ValueError):
            unpad_iso7816(data, 8)

    def test_unpad_pkcs7_pad_value_too_large(self):
        data = bytearray(b'AB\x09\x09\x09\x09\x09\x09\x09\x09')
        with self.assertRaises(ValueError):
            unpad_pkcs7(data, 8)

    def test_unpad_pkcs7_inconsistent_padding(self):
        data = bytearray(b'ABCDE\x01\x02\x03')
        with self.assertRaises(ValueError):
            unpad_pkcs7(data, 8)

    def test_padding_exact_block_size(self):
        for method, _pad, _unpad in (
            (Padding.PKCS7, pad_pkcs7, unpad_pkcs7),
            (Padding.X923, pad_x923, unpad_x923),
            (Padding.ISO7816, pad_iso7816, unpad_iso7816),
        ):
            data = bytearray(b'ABCDEFGH')
            original = bytearray(data)
            _pad(data, 8)
            self.assertEqual(len(data), 16)
            _unpad(data, 8)
            self.assertEqual(data, original)

    def test_cbc_encrypt_decrypt_roundtrip(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xAA for b in data)
        def fake_decrypt(data):
            return bytes(b ^ 0xAA for b in data)

        iv = b'\x00' * 4
        plaintext = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        dst = memoryview(bytearray(len(plaintext)))

        mode = CBC(iv)
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_decrypt, 4)
        ciphertext = bytes(dst)

        mode2 = CBC(iv)
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_decrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_pcbc_encrypt_decrypt_roundtrip(self):
        def fake_encrypt(data):
            return bytes(b ^ 0x55 for b in data)
        def fake_decrypt(data):
            return bytes(b ^ 0x55 for b in data)

        iv = b'\x00' * 4
        plaintext = b'\x10\x20\x30\x40\x50\x60\x70\x80'
        dst = memoryview(bytearray(len(plaintext)))

        mode = PCBC(iv)
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_decrypt, 4)
        ciphertext = bytes(dst)

        mode2 = PCBC(iv)
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_decrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_ofb_encrypt_decrypt_roundtrip(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xFF for b in data)
        def fake_decrypt(data):
            return bytes(b ^ 0xFF for b in data)

        iv = b'\x00' * 4
        plaintext = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        dst = memoryview(bytearray(len(plaintext)))

        mode = OFB(iv)
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_decrypt, 4)
        ciphertext = bytes(dst)

        mode2 = OFB(iv)
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_decrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_ctr_encrypt_decrypt_roundtrip(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xCC for b in data)
        def fake_decrypt(data):
            return bytes(b ^ 0xCC for b in data)

        plaintext = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        dst = memoryview(bytearray(len(plaintext)))

        mode = CTR(block_size=4, nonce=b'\x00\x00')
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_decrypt, 4)
        ciphertext = bytes(dst)

        mode2 = CTR(block_size=4, nonce=b'\x00\x00')
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_decrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_ctr_little_endian(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xCC for b in data)

        plaintext = b'\x01\x02\x03\x04'
        dst = memoryview(bytearray(len(plaintext)))
        mode = CTR(block_size=4, nonce=b'\x00\x00', little_endian=True)
        self.assertTrue(mode.little_endian)
        self.assertEqual(mode.byte_order, 'little')
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_encrypt, 4)
        self.assertNotEqual(bytes(dst), plaintext)

    def test_ctr_with_counter_dict(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xCC for b in data)

        counter = {
            'prefix': b'\x00',
            'suffix': b'\x00',
            'counter_len': 2,
            'initial_value': 0,
            'little_endian': False,
        }
        mode = CTR(counter=counter)
        self.assertEqual(mode.block_size, 4)
        plaintext = b'\x01\x02\x03\x04'
        dst = memoryview(bytearray(len(plaintext)))
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_encrypt, 4)

    def test_ctr_no_block_size_or_counter_raises(self):
        with self.assertRaises(ValueError):
            CTR()

    def test_ctr_nonce_exceeds_block_size_raises(self):
        with self.assertRaises(ValueError):
            CTR(block_size=4, nonce=b'\x00' * 5)

    def test_ctr_counter_dict_block_size_mismatch_raises(self):
        counter = {
            'prefix': b'\x00',
            'suffix': b'\x00',
            'counter_len': 2,
        }
        with self.assertRaises(ValueError):
            CTR(block_size=8, counter=counter)

    def test_cfb_segment_size_not_multiple_of_8_raises(self):
        with self.assertRaises(NotImplementedError):
            CFB(iv=b'\x00' * 8, segment_size=7)

    def test_cfb_encrypt_decrypt_roundtrip(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xAB for b in data)

        iv = b'\x00' * 4
        plaintext = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        dst = memoryview(bytearray(len(plaintext)))

        mode = CFB(iv, segment_size=16)
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_encrypt, 4)
        ciphertext = bytes(dst)

        mode2 = CFB(iv, segment_size=16)
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_encrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_cfb_segment_size_8_byte_by_byte(self):
        def fake_encrypt(data):
            return bytes(b ^ 0xAB for b in data)

        iv = b'\x00' * 4
        plaintext = b'\x01\x02\x03\x04'
        dst = memoryview(bytearray(len(plaintext)))

        mode = CFB(iv, segment_size=8)
        mode.apply(Operation.Encrypt, dst, memoryview(plaintext), fake_encrypt, fake_encrypt, 4)
        ciphertext = bytes(dst)

        mode2 = CFB(iv, segment_size=8)
        mode2.apply(Operation.Decrypt, dst, memoryview(ciphertext), fake_encrypt, fake_encrypt, 4)
        self.assertEqual(bytes(dst), plaintext)

    def test_block_cipher_factory_with_simple_cipher(self):
        class SimpleXorCipher(BlockCipher):
            block_size = 4
            key_size = {4}

            def __init__(self, key, mode=None, **kw):
                super().__init__(key, mode)

            def block_encrypt(self, data):
                return bytes(a ^ b for a, b in zip(data, self.key))

            def block_decrypt(self, data):
                return bytes(a ^ b for a, b in zip(data, self.key))

        factory = BlockCipherFactory(SimpleXorCipher)
        self.assertEqual(factory.name, 'SimpleXorCipher')
        self.assertEqual(factory.block_size, 4)
        self.assertEqual(factory.key_size, {4})

        cipher = factory.new(b'\xAA\xBB\xCC\xDD')
        plaintext = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08')
        ciphertext = cipher.encrypt(plaintext)
        result = cipher.decrypt(ciphertext)
        self.assertEqual(bytes(result), bytes(plaintext))

    def test_block_cipher_factory_ecb_default_mode(self):
        class TinyCipher(BlockCipher):
            block_size = 4
            key_size = {2}

            def __init__(self, key, mode=None, **kw):
                super().__init__(key, mode)

            def block_encrypt(self, data):
                return bytes(b ^ self.key[0] for b in data)

            def block_decrypt(self, data):
                return bytes(b ^ self.key[0] for b in data)

        factory = BlockCipherFactory(TinyCipher)
        cipher = factory.new(b'\x42\x00')
        plaintext = bytearray(b'TEST')
        ct = cipher.encrypt(plaintext)
        pt = cipher.decrypt(ct)
        self.assertEqual(bytes(pt), b'TEST')

    def test_block_cipher_factory_cbc_mode(self):
        class TinyCipher(BlockCipher):
            block_size = 4
            key_size = {2}

            def __init__(self, key, mode=None, **kw):
                super().__init__(key, mode)

            def block_encrypt(self, data):
                return bytes(b ^ self.key[0] for b in data)

            def block_decrypt(self, data):
                return bytes(b ^ self.key[0] for b in data)

        factory = BlockCipherFactory(TinyCipher)
        cipher = factory.new(b'\x42\x00', mode=factory.MODE_CBC, iv=b'\x00\x00\x00\x00')
        plaintext = bytearray(b'TESTDATA')
        ct = cipher.encrypt(plaintext)
        cipher2 = factory.new(b'\x42\x00', mode=factory.MODE_CBC, iv=b'\x00\x00\x00\x00')
        pt = cipher2.decrypt(ct)
        self.assertEqual(bytes(pt), b'TESTDATA')

    def test_block_cipher_invalid_key_size(self):
        class TinyCipher(BlockCipher):
            block_size = 4
            key_size = {4}

            def __init__(self, key, mode=None, **kw):
                super().__init__(key, mode)

            def block_encrypt(self, data):
                return data

            def block_decrypt(self, data):
                return data

        with self.assertRaises(ValueError):
            TinyCipher(b'\x00\x00', ECB())

    def test_block_cipher_data_unaligned(self):
        class TinyCipher(BlockCipher):
            block_size = 4
            key_size = {4}

            def __init__(self, key, mode=None, **kw):
                super().__init__(key, mode)

            def block_encrypt(self, data):
                return data

            def block_decrypt(self, data):
                return data

        cipher = TinyCipher(b'\x00\x00\x00\x00', ECB())
        with self.assertRaises(DataUnaligned):
            cipher.encrypt(b'\x01\x02\x03')

    def test_cipher_modes_have_identifiers(self):
        for name, mode in CIPHER_MODES.items():
            self.assertIsInstance(mode._identifier, int)
