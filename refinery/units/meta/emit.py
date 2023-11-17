#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple tool to output binary data. Multiple arguments are output in framed
format, see `refinery.lib.frame`.
"""
from refinery.units import Arg, Unit


class emit(Unit):

    def __init__(self, *data: Arg(help=(
        'Data to be emitted. If no argument is specified, data '
        'is retrieved from the clipboard. Multiple arguments are '
        'output in framed format.'
    ))):
        super().__init__(data=data)

    @Unit.Requires('pyperclip')
    def _pyperclip():
        import pyperclip
        return pyperclip

    def process(self, data):
        if not self.args.data:
            data = self._pyperclip.paste()
            yield data and data.encode(self.codec, 'replace') or B''
        else:
            yield from self.args.data
