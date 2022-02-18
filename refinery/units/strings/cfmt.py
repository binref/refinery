#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from codecs import encode, decode
from functools import partial

from refinery.units import arg, Unit
from refinery.lib.meta import metavars


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
        *formats : arg(help='Format strings.', type=str, metavar='format'),
        variable : arg('-n', type=str, metavar='NAME', help='Store the formatted string in a meta variable.') = None,
        separator: arg('-s', group='SEP', metavar='S',
            help='Separator to insert between format strings. The default is a space character.') = ' ',
        multiplex: arg.switch('-m', group='SEP',
            help='Do not join the format strings along the separator, generate one output for each.') = False,
        binary   : arg.switch('-b', help='Use the binary formatter instead of the string formatter.') = False,
    ):
        def fixfmt(fmt):
            if not isinstance(fmt, str):
                fmt = fmt.decode(self.codec)
            return decode(encode(fmt, 'latin-1', 'backslashreplace'), 'unicode-escape')
        formats = [fixfmt(f) for f in formats]
        if not multiplex:
            formats = [fixfmt(separator).join(formats)]
        super().__init__(formats=formats, variable=variable, binary=binary)

    def process(self, data):
        meta = metavars(data, ghost=True)
        args = [data]
        variable = self.args.variable
        if self.args.binary:
            formatter = partial(meta.format_bin, codec=self.codec, args=args)
        else:
            def formatter(spec):
                return meta.format_str(spec, self.codec, args, escaped=True).encode(self.codec)
        for spec in self.args.formats:
            result = formatter(spec)
            if variable is not None:
                result = self.labelled(data, **{variable: result})
            yield result
