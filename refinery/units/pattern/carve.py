#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, PatternExtractor
from ...lib.patterns import formats


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """
    def __init__(
        self, format: arg.choice(choices=[p.dashname for p in formats], metavar='format',
            help='Specify one of the following formats: {choices}'),
        unique: arg.switch('-q', help='Yield every match only once.') = False,
        decode: arg.switch('-d', help='Automatically decode known patterns.') = False,
        single: arg.switch('-s', help='Only get the biggest match; equivalent to -qlt1') = False,
        min=1, max=None, len=None,
        stripspace=False, longest=False, take=None, utf16=True, ascii=True
    ):
        if single:
            take = 1
            longest = True
            unique = True
        super().__init__(
            min=min,
            max=max,
            len=len,
            stripspace=stripspace,
            duplicates=not unique,
            longest=longest,
            take=take,
            ascii=ascii,
            utf16=utf16,
            format=formats.from_dashname(format)
        )
        if not decode:
            decoder = NotImplemented
        elif self.args.format is formats.string:
            def decoder(chunk):
                return decoder.unesc(chunk[1:-1])
            from ..encoding.esc import esc
            decoder.unesc = esc()
        elif self.args.format in (formats.uppercase_hex, formats.hex):
            from ..encoding.hex import hex
            decoder = hex()
        elif self.args.format is formats.hexdump:
            from ..formats.hexdmp import hexdmp
            decoder = hexdmp()
        elif self.args.format is formats.intarray:
            from ..blockwise.pack import pack
            decoder = pack()
        elif self.args.format is formats.b64:
            from ..encoding.b64 import b64
            decoder = b64()
        elif self.args.format is formats.b64url:
            from ..encoding.b64 import b64
            decoder = b64(urlsafe=True)
        elif self.args.format is formats.b32:
            from ..encoding.b32 import b32
            decoder = b32()
        elif self.args.format is formats.ps1str:
            from ..encoding.ps1str import ps1str
            decoder = ps1str()
        elif self.args.format is formats.hexarray:
            from ..blockwise.pack import pack
            decoder = pack(0x10)
        elif self.args.format is formats.vbe:
            from ..encoding.vbe import vbe
            decoder = vbe()
        elif self.args.format in (
            formats.url_encoded_hex,
            formats.url_encoded_narrow,
            formats.url_encoded_coarse,
        ):
            from ..encoding.url import url
            decoder = url()
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
