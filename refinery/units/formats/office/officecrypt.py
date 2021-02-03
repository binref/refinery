#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import arg, Unit
from ....lib.structures import MemoryFile
import msoffcrypto


class officecrypt(Unit):
    """
    A simple proxy for the `msoffcrypto` package to decrypt office documents.
    """

    def __init__(self, password: arg(help='The document password.', type=str)):
        super().__init__(password=password)

    def process(self, data):
        with MemoryFile(data) as stream:
            doc = msoffcrypto.OfficeFile(stream)
            doc.load_key(password=self.args.password)
            with MemoryFile(bytearray()) as output:
                doc.decrypt(output)
                return output.getvalue()
