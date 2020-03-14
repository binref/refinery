#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.argformats import multibin

from .. import TestBase


class TestFraming(TestBase):

    def test_multibin_simple(self):
        m = multibin('xor[0x50]:x:-16:')
        b = bytearray([4] * 12 + [5] * 16)
        a = m(b)
        self.assertEqual(a, 16 * B'\x55')
        self.assertEqual(b, bytearray([4] * 12))

    def test_encrypted_buffer(self):
        key = b'encryptioniseasy'
        iv = b'iviviviviviviviv'
        alice = self.ldu('aes', 'CBC', key=key, iv=iv)
        plaintext = self.generate_random_buffer(200)
        encrypted = alice.reverse(plaintext)

        # bob expects the key first, then the iv
        bob = self.ldu('aes', 'CBC', 'x::16', '--iv', 'x::16')
        self.assertEqual(plaintext, bob(key + iv + encrypted))

        # charlie expects the iv first, then the key
        charlie = self.ldu('aes', 'CBC', '--iv', 'x::16', 'x::16')
        self.assertEqual(plaintext, charlie(iv + key + encrypted))

    def test_bytes_arguments(self):
        key = self.generate_random_buffer(16)
        iv = self.generate_random_buffer(16)
        data = self.generate_random_buffer(512)
        aes = self.ldu('aes', 'CBC', key, iv=iv)
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
