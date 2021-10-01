#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import arg, Unit
from ....lib.structures import MemoryFile
import msoffcrypto


class officecrypt(Unit):
    """
    A simple proxy for the `msoffcrypto` package to decrypt office documents.
    """

    def __init__(self, password: arg.binary(help=(
        'The document password. By default, the Excel default password "{default}" is used.'
    )) = b'VelvetSweatshop'):
        super().__init__(password=password)

    def process(self, data):
        password: bytes = self.args.password
        with MemoryFile(data) as stream:
            doc = msoffcrypto.OfficeFile(stream)
            if not doc.is_encrypted():
                self.log_warn('the document is not encrypted; returning input')
                return data
            if password:
                doc.load_key(password=password.decode(self.codec))
            with MemoryFile(bytearray()) as output:
                doc.decrypt(output)
                return output.getvalue()
