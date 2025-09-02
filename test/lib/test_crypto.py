#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.crypto import (
    pad_iso7816,
    pad_pkcs7,
    pad_x923,
    unpad_iso7816,
    unpad_pkcs7,
    unpad_x923,
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

                for i, pad in enumerate((pad_pkcs7, pad_x923, pad_iso7816), 1):
                    pad(buffer, block_size)
                    proper_unpad = None
                    for j, unpad in enumerate((unpad_pkcs7, unpad_x923, unpad_iso7816), 1):
                        if i == j:
                            proper_unpad = unpad
                            continue
                        with self.assertRaises(ValueError, msg=(
                            F'Buffer of size {size} for block size {block_size} padded with '
                            F'method {i} was successfully unpadded with method {j}.'
                        )):
                            unpad(buffer, block_size)
                    assert proper_unpad is not None
                    proper_unpad(buffer, block_size)
                    self.assertEqual(original, buffer)
