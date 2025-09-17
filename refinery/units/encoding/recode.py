from __future__ import annotations

import codecs
import enum

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class Handler(enum.Enum):
    STRICT = 'strict'
    IGNORE = 'ignore'
    REPLACE = 'replace'
    XMLREF = 'xmlcharrefreplace'
    BACKSLASH = 'backslashreplace'
    SURROGATE = 'surrogateescape'


class recode(Unit):
    """
    Expects input string data encoded in the `from` encoding and encodes it in
    the `to` encoding, then outputs the result.
    """

    def __init__(
        self,
        decode: Param[str, Arg.String(metavar='decode-as', help='Input encoding; Guess encoding by default.')] = None,
        encode: Param[str, Arg.String(metavar='encode-as', help=F'Output encoding; The default is {Unit.codec}.')] = Unit.codec,
        decerr: Param[str, Arg.Option('-d', choices=Handler,
            help='Specify an error handler for decoding.')] = None,
        encerr: Param[str, Arg.Option('-e', choices=Handler,
            help='Specify an error handler for encoding.')] = None,
        errors: Param[str, Arg.Option('-E', choices=Handler, help=(
            'Specify an error handler for both encoding and decoding. '
            'The possible choices are the following: {choices}'))] = None,
    ):
        super().__init__(
            decode=decode,
            encode=encode,
            decerr=Arg.AsOption(decerr or errors or 'STRICT', Handler).value,
            encerr=Arg.AsOption(encerr or errors or 'STRICT', Handler).value
        )

    @Unit.Requires('chardet', ['default', 'extended'])
    def _chardet():
        import chardet
        return chardet

    def _detect(self, data):
        mv = memoryview(data)
        if not any(mv[1::2]): return 'utf-16le'
        if not any(mv[0::2]): return 'utf-16be'
        detection = self._chardet.detect(data)
        codec = detection['encoding']
        self.log_info(lambda: F'Using input encoding: {codec}, detected with {int(detection["confidence"] * 100)}% confidence.')
        return codec

    def _recode(self, enc, dec, encerr, decerr, data):
        dec = dec or self._detect(data)
        return codecs.encode(codecs.decode(data, dec, errors=decerr), enc, errors=encerr)

    def reverse(self, data):
        return self._recode(self.args.decode, self.args.encode, self.args.decerr, self.args.encerr, data)

    def process(self, data):
        return self._recode(self.args.encode, self.args.decode, self.args.encerr, self.args.decerr, data)
