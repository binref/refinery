#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


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
        if not multiplex:
            formats = [separator.join(formats)]
        super().__init__(formats=formats)

    def process(self, data):
        meta = getattr(data, 'meta', {})
        data = data.decode('latin-1')
        for spec in self.args.formats:
            yield spec.format(data, **meta).encode('latin-1')
