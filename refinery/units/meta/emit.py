#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple tool to output binary data. Multiple arguments are output in framed
format, see `refinery.lib.frame`.
"""
from ...lib.argformats import multibin
from ...lib.clipboard import paste
from .. import Unit


class emit(Unit):

    def interface(self, argp):
        argp.add_argument('data', type=multibin, default=None, nargs='*',
            help=(
                'Data to be emitted. If no argument is specified, data '
                'is retrieved from the clipboard. Multiple arguments are '
                'output in framed format.'
            )
        )
        return super().interface(argp)

    def process(self, data):
        if not self.args.data:
            data = paste()
            try:
                data = data.encode(self.codec)
            except AttributeError:
                # data is None
                data = B''
            except UnicodeDecodeError:
                data = data.encode('utf-16le')
            yield data
        else:
            yield from self.args.data

    @classmethod
    def run(cls, argv=None, stream=None):
        super(emit, cls).run(argv=argv,
            stream=stream or open(__import__('os').devnull, 'rb')
        )
