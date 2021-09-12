#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from codecs import encode, decode

from .. import arg, Unit
from ...lib.meta import metavars


class cfmt(Unit):
    """
    Transform a given chunk by applying a format string operation. The positional format
    string placeholder `{}` will be replaced by the incoming data, named placeholders have
    to be present as meta variables in the current chunk. For example, the following
    pipeline can be used to print all files in a given directory with their corresponding
    SHA-256 hash:

        ef ** [| sha256 -t | cfmt {} {path} ]]

    By default, format string arguments are simply joined along a space character to form
    a single format string.
    """

    def __init__(
        self,
        *formats: arg(help='Format strings.', type=str, metavar='format'),
        put: arg('-p', type=str, metavar='NAME', help='Store the formatted string in a meta variable.') = None,
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
        super().__init__(formats=formats, put=put)

    def process(self, data):
        meta = metavars(data, ghost=True)
        name = self.args.put
        for spec in self.args.formats:
            result = meta.format_str(spec, self.codec, data).encode(self.codec)
            if name is not None:
                result = self.labelled(data, **{name: result})
            yield result
