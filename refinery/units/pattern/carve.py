from __future__ import annotations

import msgpack

from refinery.lib.patterns import formats, pattern_with_size_limits
from refinery.lib.types import Param
from refinery.units import Chunk
from refinery.units.pattern import Arg, PatternExtractor

_FORMATS = ', '.join(p.display for p in formats)


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """
    def __init__(
        self, format: Param[str, Arg.String(metavar='format',
            help=F'Specify one of the following formats: {_FORMATS}')],
        unique: Param[bool, Arg.Switch('-q', help='Yield every match only once.')] = False,
        decode: Param[bool, Arg.Switch('-d', help='Automatically decode known patterns.')] = False,
        single: Param[bool, Arg.Switch('-s', help='Only get the biggest match; equivalent to -qlt1')] = False,
        min=1, max=0, len=0,
        stripspace=False, longest=False, take=0, utf16=True, ascii=True
    ):
        if single:
            take = 1
            longest = True
            unique = True
        try:
            format = formats.from_dashname(format)
        except Exception:
            raise ValueError(F'{format} is not a valid format')
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
            format=format
        )
        if not decode:
            decoder = None
        elif self.args.format == formats.str:
            from ..encoding.esc import esc
            decoder = esc(unicode=True, quoted=True)
        elif self.args.format == formats.int:
            from ..encoding.base import base
            decoder = base()
        elif self.args.format in (formats.b16, formats.b16s, formats.hex):
            from ..encoding.hex import hex
            decoder = hex()
        elif self.args.format == formats.hexdump:
            from ..formats.hexload import hexload
            decoder = hexload()
        elif self.args.format == formats.intarray:
            from ..blockwise.pack import pack
            decoder = pack()
        elif self.args.format == formats.strarray:
            from ..encoding.esc import esc
            def _decoder(data: Chunk) -> bytes: # noqa
                return msgpack.packb([
                    m[0] | esc | bytes for m in formats.str.value.finditer(data)]) or B''
            decoder = _decoder
        elif self.args.format in (formats.b64, formats.b64s):
            from ..encoding.b64 import b64
            decoder = b64()
        elif self.args.format in (formats.b85, formats.b85s):
            from ..encoding.b85 import b85
            decoder = b85()
        elif self.args.format == formats.b64u:
            from ..encoding.b64 import b64
            decoder = b64(urlsafe=True)
        elif self.args.format == formats.b32:
            from ..encoding.b32 import b32
            decoder = b32()
        elif self.args.format == formats.ps1str:
            from ..encoding.escps import escps
            decoder = escps()
        elif self.args.format == formats.vbastr:
            from ..encoding.escps import escps
            decoder = escps()
        elif self.args.format == formats.hexarray:
            from ..blockwise.pack import pack
            decoder = pack(0x10)
        elif self.args.format == formats.wshenc:
            from ..encoding.wshenc import wshenc
            decoder = wshenc()
        elif self.args.format == formats.uuenc:
            from ..encoding.uuenc import uuenc
            decoder = uuenc()
        elif self.args.format in (
            formats.urlquote,
            formats.urlhex,
        ):
            from ..encoding.url import url
            decoder = url()
        else:
            decoder = None
        self.decoder = decoder

    def process(self, data):
        sizes = self._getbounds()
        pattern = pattern_with_size_limits(
            self.args.format.value, max(1, sizes.min), abs(sizes.max))
        self.log_info('using pattern:', pattern.str.pattern)
        it = iter(self.matches_filtered(memoryview(data), pattern.bin))
        if (decoder := self.decoder) is None:
            yield from it
        else:
            for chunk in it:
                try:
                    yield decoder(chunk)
                except Exception as E:
                    self.log_info(F'decoder failure: {E!s}')


class csd(carve):
    """
    Short for carve & decode; carves the single largest buffer of a given format from the input
    and decodes it with the appropriate decoder.
    """
    def __init__(self, format, utf16=True, ascii=True, stripspace=False):
        super().__init__(
            format,
            decode=True,
            single=True,
            utf16=utf16,
            ascii=ascii,
            stripspace=stripspace,
        )


class csb(carve):
    """
    Short for carve single buffer; carves the single largest buffer of a given format from the
    input data and returns it.
    """
    def __init__(self, format, utf16=True, ascii=True, stripspace=False):
        super().__init__(
            format,
            decode=False,
            single=True,
            utf16=utf16,
            ascii=ascii,
            stripspace=stripspace,
        )
