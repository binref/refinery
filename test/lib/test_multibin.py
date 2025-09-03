from refinery.lib.argformats import multibin
from refinery.lib.loader import load_detached as L

from .. import TestBase


class TestMultiBin(TestBase):

    def test_seeded_multibin(self):
        for spec, r in (
            ('b64:h', False),
            ('b64:h:', False),
            ('h:b64', True),
            (':h:b64', True)
        ):
            m = multibin(spec, reverse=r, seed=b'636D566D6157356C636E6B3D')
            self.assertEqual(m, B'refinery')

    def test_reversed_multibin(self):
        m = multibin('636D566D6157356C636E6B3D:H:b64', reverse=True)
        self.assertEqual(m, B'refinery')

    def test_multibin_simple(self):
        m = multibin('xor[0x50]:x:-16:')
        b = bytearray([4] * 12 + [5] * 16)
        a = m(b)
        self.assertEqual(a, 16 * B'\x55')
        self.assertEqual(b, bytearray([4] * 12))

    def test_encrypted_buffer(self):
        key = b'encryptioniseasy'
        iv = b'iviviviviviviviv'
        alice = self.ldu('aes', key, iv=iv)
        plaintext = self.generate_random_buffer(200)
        encrypted = alice.reverse(plaintext)

        # bob expects the key first, then the iv
        bob = self.ldu('aes', 'x::16', '--iv', 'x::16')
        self.assertEqual(plaintext, bob(key + iv + encrypted))

        # charlie expects the iv first, then the key
        charlie = self.ldu('aes', '--iv', 'x::16', 'x::16')
        self.assertEqual(plaintext, charlie(iv + key + encrypted))

    def test_bytes_arguments(self):
        key = self.generate_random_buffer(16)
        iv = self.generate_random_buffer(16)
        data = self.generate_random_buffer(512)
        aes = self.ldu('aes', key, iv=iv)
        self.assertEqual(aes.decrypt(aes.encrypt(data)), data)

    def test_invalid_multibin_modifier(self):
        self.assertEqual(multibin('foobar:s:content'), B'foobar:s:content')

    def test_multibin_nested_args(self):
        buffer = B'Too much Technology in too little Time'
        m = multibin(F'xor[ucrypt[8,H:4242]:swordfish]:H:{buffer.hex()}')
        ucrypt = self.ldu('ucrypt', size=8, salt=bytes.fromhex('4242'))
        self.assertEqual(m, self.ldu('xor', ucrypt(B'swordfish'))(buffer))

    def test_multibin_delayed(self):
        buffer = self.generate_random_buffer(1024)
        unit1 = self.ldu('xor', 'snip[:4]:x::8')
        unit2 = self.ldu('xor', 'H:{}'.format(buffer[:4].hex()))
        self.assertEqual(unit1(buffer), unit2(buffer[8:]))

    def test_unit_loader(self):
        m = multibin('hex[-R]:x::4')
        b = bytearray.fromhex('BAADF00DCAB00F')
        a = m(b)
        self.assertEqual(a, B'BAADF00D')

    def test_range_modifier(self):
        m = multibin('range:0x31:0x39+1')
        self.assertEqual(m, B'123456789')

    def test_subtraction_range(self):
        data = B'\xC0\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        data = data + self.generate_random_buffer(50)
        sub1 = L('put k x::1 [') | L('sub add[var:k]:range::10 ]')
        sub2 = L('sub   x::1  ') | L('sub range::10')
        out1 = bytes(sub1(data))
        out2 = bytes(sub2(data))
        self.assertEqual(out1, out2)

    def test_readme_01(self):
        m = multibin('repl[q:1%2c2%2c3,2]:1,2,3,4,5')
        self.assertEqual(m, B'2,4,5')

    def test_pbkdf2(self):
        r = bytes.fromhex('E6 16 47 03 3A 80 F6 22 BC 62 1D 0B EC 0E B4 48')
        m = multibin('pbkdf2[16,foo,100]:bar')
        self.assertEqual(m, r)
