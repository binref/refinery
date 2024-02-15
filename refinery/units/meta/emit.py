#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple tool to output binary data. Multiple arguments are output in framed
format, see `refinery.lib.frame`.
"""
import os

from refinery.units import Arg, Unit


class emit(Unit):

    def __init__(self, *data: Arg(help=(
        'Data to be emitted. If no argument is specified, data is retrieved from '
        'the clipboard. Multiple arguments are output in framed format.'
    ))):
        super().__init__(data=data)

    @Unit.Requires('pyperclip')
    def _pyperclip():
        import pyperclip
        return pyperclip

    def process(self, data):
        if self.args.data:
            yield from self.args.data
            return
        if os.name == 'nt':
            from refinery.lib.winclip import get_any_data
            mode, data = get_any_data()
            if mode is not None:
                self.log_info(F'retrieved clipboard data in {mode.name} format')
            yield data
        else:
            data = self._pyperclip.paste()
            if not data:
                return
            yield data.encode(self.codec, 'replace')
