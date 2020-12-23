#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, Dict, Any
from codecs import encode, decode
from .. import arg, Unit
from ...lib.tools import isbuffer


class ByteStringWrapper:
    def __init__(self, string: ByteString, codec: str):
        self.string = string
        self.codec = codec

    def __repr__(self):
        return self.string.hex().upper()

    def __str__(self):
        try:
            return self.string.decode(self.codec)
        except UnicodeDecodeError:
            return self.string.decode('ascii', 'backslashreplace')

    @classmethod
    def FormatMap(cls, data: ByteString, codec: str) -> Dict[str, Any]:
        meta = getattr(data, 'meta', {})
        return meta and {key: cls(value, codec) if isbuffer(value) else value for key, value in meta.items()}


class cfmt(Unit):
    """
    Transform a given chunk by applying a format string operation. The positional format
    string placeholder `{}` will be replaced by the incoming data, named placeholders have
    to be present as meta variables in the current chunk. For example, the following
    pipeline can be used to print all files in a given directory with their corresponding
    SHA-256 hash:

        fread ** [| sha256 -t | cfmt {} {path} ]]

    By default, format string arguments are simply joined along a space character to form
    a single format string.
    """

    def __init__(
        self,
        *formats: arg(help='Format strings.', type=str, metavar='format'),
        separator: arg('-s', group='SEP', metavar='S',
            help='Separator to insert between format strings. The default is a space character.') = ' ',
        multiplex: arg.switch('-m', group='SEP',
            help='Do not join the format strings along the separator, generate one output for each.') = False
    ):
        def fixfmt(fmt):
            if not isinstance(fmt, str):
                fmt = fmt.decode(self.codec)
            return decode(encode(fmt, 'latin-1', 'backslashreplace'), 'unicode-escape')
        formats = [fixfmt(f) for f in formats]
        if not multiplex:
            formats = [fixfmt(separator).join(formats)]
        super().__init__(formats=formats)

    def process(self, data):
        meta = ByteStringWrapper.FormatMap(data, self.codec)
        data = ByteStringWrapper(data, self.codec)
        for spec in self.args.formats:
            yield spec.format(data, **meta).encode(self.codec)
