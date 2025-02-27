#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.pattern import Arg, PatternExtractor
from refinery.lib.patterns import formats


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """
    def __init__(
        self, format: Arg.Choice(choices=[p.display for p in formats], metavar='format',
            help='Specify one of the following formats: {choices}'),
        unique: Arg.Switch('-q', help='Yield every match only once.') = False,
        decode: Arg.Switch('-d', help='Automatically decode known patterns.') = False,
        single: Arg.Switch('-s', help='Only get the biggest match; equivalent to -qlt1') = False,
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
        elif self.args.format in (formats.multiline_string, formats.string):
            from ..encoding.esc import esc
            decoder = esc(unicode=True, quoted=True)
        elif self.args.format is formats.integer:
            from ..encoding.base import base
            decoder = base()
        elif self.args.format in (formats.uppercase_hex, formats.spaced_hex, formats.hex):
            from ..encoding.hex import hex
            decoder = hex()
        elif self.args.format is formats.hexdump:
            from ..formats.hexload import hexload
            decoder = hexload()
        elif self.args.format is formats.intarray:
            from ..blockwise.pack import pack
            decoder = pack()
        elif self.args.format in (formats.b64, formats.b64any, formats.spaced_b64):
            from ..encoding.b64 import b64
            decoder = b64()
        elif self.args.format in (formats.b85, formats.spaced_b85):
            from ..encoding.b85 import b85
            decoder = b85()
        elif self.args.format is formats.b64url:
            from ..encoding.b64 import b64
            decoder = b64(urlsafe=True)
        elif self.args.format is formats.b32:
            from ..encoding.b32 import b32
            decoder = b32()
        elif self.args.format is formats.ps1str:
            from ..encoding.escps import escps
            decoder = escps()
        elif self.args.format is formats.vbastr:
            from ..encoding.escps import escps
            decoder = escps()
        elif self.args.format is formats.hexarray:
            from ..blockwise.pack import pack
            decoder = pack(0x10)
        elif self.args.format is formats.wshenc:
            from ..encoding.wshenc import wshenc
            decoder = wshenc()
        elif self.args.format is formats.uuencode:
            from ..encoding.uuenc import uuenc
            decoder = uuenc()
        elif self.args.format in (
            formats.urlquote,
            formats.urlquote_coarse,
            formats.urlquote_narrow,
        ):
            from ..encoding.url import url
            decoder = url()
        else:
            decoder = NotImplemented
        self.decoder = decoder

    def process(self, data):
        it = iter(self.matches_filtered(memoryview(data), self.args.format.value.bin_compiled))
        if self.decoder is NotImplemented:
            yield from it
        for chunk in it:
            try:
                yield self.decoder(chunk)
            except Exception as E:
                self.log_info(F'decoder failure: {E!s}')


class csd(carve):
    """
    Short for carve & decode; carves the single largest buffer of a given format from the input
    and decodes it with the appropriate decoder.
    """
    def __init__(self, format, utf16=True, ascii=True):
        super().__init__(
            format,
            decode=True,
            single=True,
            utf16=utf16,
            ascii=ascii,
        )


class csb(carve):
    """
    Short for carve single buffer; carves the single largest buffer of a given format from the
    input data and returns it.
    """
    def __init__(self, format, utf16=True, ascii=True):
        super().__init__(
            format,
            decode=False,
            single=True,
            utf16=utf16,
            ascii=ascii,
        )
