#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile

from . import HashUnit


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """

    def process(self, data):
        th = pefile.PE(data=data).get_imphash()
        return th.encode(self.codec) if self.args.text else bytes.fromhex(th)
