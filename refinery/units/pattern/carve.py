#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, PatternExtractor
from ...lib.patterns import formats


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """
    def __init__(
        self, format: arg.choice(choices=[p.name for p in formats], metavar='format',
            help='Specify one of the following formats: {choices}'),
        decode: arg.switch('-d', help='Automatically decode known patterns.') = False,
        single: arg.switch('-s', help='Only get the biggest match; equivalent to -qlt1') = False,
        min=1, max=None, len=None,
        stripspace=False, unique=False, longest=False, take=None, utf16=True, ascii=True
    ):
        if single:
            take = 1        # noqa warning about unused variable
            longest = True  # noqa warning about unused variable
            unique = True   # noqa warning about unused variable
        del single
        self.superinit(super(), **vars())
        self.args.format = formats[format]
        if not decode:
            decoder = NotImplemented
        elif self.args.format is formats.string:
            def decoder(chunk):
                return decoder.unesc(chunk[1:-1])
            from ..encoding.esc import esc
            decoder.unesc = esc()
        elif self.args.format in (formats.HEX, formats.hex):
            from ..encoding.hex import hex
            decoder = hex()
        elif self.args.format is formats.hexdump:
            from ..blockwise.pack import pack
            decoder = pack(0x10, hexdump=True)
        elif self.args.format is formats.intarray:
            from ..blockwise.pack import pack
            decoder = pack()
        elif self.args.format is formats.b64:
            from ..encoding.b64 import b64
            decoder = b64()
        elif self.args.format is formats.b64u:
            from ..encoding.b64 import b64
            decoder = b64(urlsafe=True)
        elif self.args.format is formats.ps1str:
            from ..encoding.ps1str import ps1str
            decoder = ps1str()
        elif self.args.format is formats.hexarray:
            from ..blockwise.pack import pack
            decoder = pack(0x10)
        elif self.args.format is formats.vbe:
            from ..encoding.vbe import vbe
            decoder = vbe()
        else:
            decoder = NotImplemented
        self.decoder = decoder

    def process(self, data):
        it = iter(self.matches_filtered(memoryview(data), bytes(self.args.format)))
        if self.decoder is NotImplemented:
            yield from it
        for chunk in it:
            try:
                yield self.decoder(chunk)
            except Exception as E:
                self.log_info(F'decoder failure: {E!s}')
