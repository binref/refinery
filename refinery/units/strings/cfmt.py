#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from codecs import encode, decode
from .. import arg, Unit
from ...lib.tools import isbuffer


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
        class bwrap:
            codec = self.codec
            def __init__(self, data): self.data = data
            def __repr__(self): return self.data.hex()

            def __str__(self):
                try:
                    return self.data.decode(self.codec)
                except UnicodeDecodeError:
                    return self.data.decode('ascii', 'backslashreplace')

        meta = getattr(data, 'meta', {})
        data = data.decode('latin-1')
        meta = meta and {key: bwrap(value) if isbuffer(value) else value for key, value in meta.items()}
        for spec in self.args.formats:
            yield spec.format(data, **meta).encode(self.codec)
