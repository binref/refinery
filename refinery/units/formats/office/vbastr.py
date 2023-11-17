#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from uuid import uuid4

from refinery import Unit


class vbastr(Unit):
    """
    Extract VBA macro form strings from Office documents.
    """
    @Unit.Requires('oletools', 'formats', 'office')
    def _olevba():
        from oletools import olevba
        return olevba

    def process(self, data):
        try:
            parser = self._olevba.VBA_Parser(uuid4(), data=bytes(data), relaxed=True)
        except self._olevba.FileOpenError:
            raise ValueError('Input data not recognized by VBA parser')
        for _, _, string in parser.extract_form_strings():
            if string is not None:
                yield string.encode(self.codec)
