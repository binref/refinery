#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.argformats import multibin
from .. import TestBase, refinery


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
        alice = refinery.aes('CBC', key=key, iv=iv)
        plaintext = self.generate_random_buffer(200)
        encrypted = alice.reverse(plaintext)

        # bob expects the key first, then the iv
        bob = refinery.aes('CBC', 'x::16', '--iv', 'x::16')
        self.assertEqual(plaintext, bob(key + iv + encrypted))

        # charlie expects the iv first, then the key
        charlie = refinery.aes('CBC', '--iv', 'x::16', 'x::16')
        self.assertEqual(plaintext, charlie(iv + key + encrypted))

    def test_invalid_multibin_modifier(self):
        self.assertEqual(multibin('foobar:s:content'), B'foobar:s:content')

    def test_multibin_nested_args(self):
        buffer = B'Too much Technology in too little Time'
        m = multibin(F'xor[ucrypt[8,H:4242]:swordfish]:H:{buffer.hex()}')
        ucrypt = refinery.ucrypt(size=8, salt=bytes.fromhex('4242'))
        self.assertEqual(m, refinery.xor(arg=[ucrypt(B'swordfish')])(buffer))
