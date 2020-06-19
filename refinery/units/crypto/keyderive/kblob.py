#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ....lib.mscrypto import CRYPTOKEY
from ... import Unit


class kblob(Unit):
    """Extracts a key from a Microsoft Crypto API BLOB structure."""

    def process(self, data):
        blob = CRYPTOKEY(data)
        self.log_info(F'BLOB Type: {blob.header.type!s}')
        self.log_info(F'Algorithm: {blob.header.algorithm!s}')
        return bytes(blob.key)
