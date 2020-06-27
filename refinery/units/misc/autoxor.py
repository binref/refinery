#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import numpy as np

from .. import Unit


class autoxor(Unit):
    """
    Automatically perform a single byte XOR decryption of the input data. The unit
    uses the most frequent byte value from the input data as the decryption key.
    """
    def process(self, data):
        data = np.frombuffer(memoryview(data), np.ubyte)
        xkey = np.argmax(np.bincount(data))
        self.log_info(F'using key 0x{xkey:02X}')
        data ^= xkey
        return data
