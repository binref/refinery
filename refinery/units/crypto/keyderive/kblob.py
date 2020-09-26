#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ....lib.mscrypto import CRYPTOKEY
from ... import Unit


class kblob(Unit):
    """
    Extracts a key from a Microsoft Crypto API BLOB structure.
    """

    def process(self, data):
        blob = CRYPTOKEY(data)
        self.log_info(F'BLOB Type: {blob.header.type!s}')
        self.log_info(F'Algorithm: {blob.header.algorithm!s}')
        try:
            return bytes(blob.key)
        except AttributeError as A:
            raise ValueError(F'unable to derive key from {blob.header.type!s}') from A
