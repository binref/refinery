#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Arg, Unit
from refinery.lib.structures import MemoryFile


class officecrypt(Unit):
    """
    A simple proxy for the `msoffcrypto` package to decrypt office documents.
    """

    def __init__(self, password: Arg.Binary(help=(
        'The document password. By default, the Excel default password "{default}" is used.'
    )) = b'VelvetSweatshop'):
        super().__init__(password=password)

    @Unit.Requires('msoffcrypto-tool', ['formats', 'office'])
    def _msoffcrypto():
        import msoffcrypto
        return msoffcrypto

    def process(self, data):
        password: bytes = self.args.password
        with MemoryFile(data) as stream:
            doc = self._msoffcrypto.OfficeFile(stream)
            if not doc.is_encrypted():
                self.log_warn('the document is not encrypted; returning input')
                return data
            if password:
                doc.load_key(password=password.decode(self.codec))
            with MemoryFile(bytearray()) as output:
                doc.decrypt(output)
                return output.getvalue()
