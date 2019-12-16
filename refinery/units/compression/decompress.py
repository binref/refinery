#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import number

from .gz import gz
from .ap import aplib
from .zl import zl
from .lz import lzma
from .bz2 import bz2
from .lznt1 import lznt1


class decompress(Unit):
    """
    Attempts all available decompression units against the input and returns
    the output of the first successful one. If none succeeds, the data is
    returned unaltered.
    """
    def interface(self, argp):
        argp.add_argument(
            '-t', '--tolerance',
            metavar='n',
            default=12,
            type=number,
            help='Decompress will attempt to strip up to n bytes from the '
                 'beginning of the data. The default is 12.'
        )
        argp.add_argument(
            '-P', '--no-prepend',
            action='store_false',
            dest='prepend',
            help='By default, if decompression fails, the unit attempts to '
                 'prefix the data with all possible values of a single byte '
                 'and decompress the result. This behavior can be disabled '
                 'with this flag.'
        )
        return super().interface(argp)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.engines = [
            engine() for engine in [zl, lzma, aplib, lznt1, gz, bz2]
        ]

    _MINIMUM_COMPRESSION_FACTOR = 0.5

    def process(self, data):
        for engine in self.engines:
            try:
                result = engine.process(data)
                assert len(result) > len(data) * self._MINIMUM_COMPRESSION_FACTOR
                self.log_info(F'{engine.__class__.__name__} worked.')
                return result
            except Exception:
                pass
        if self.args.prepend:
            for p in range(0x100):
                for engine in self.engines:
                    try:
                        result = engine.process(bytes((p,)) + data)
                        assert len(result) > len(data) * self._MINIMUM_COMPRESSION_FACTOR
                        self.log_info(F'{engine.__class__.__name__} worked after prepending {p:02X}.')
                        return result
                    except Exception:
                        pass
        for t in range(1, self.args.tolerance):
            for engine in self.engines:
                self.log_debug(F'skipping {t:02d}, algorithm {engine.__class__.__name__}')
                try:
                    result = engine.process(data[t:])
                    assert len(result) > len(data) * self._MINIMUM_COMPRESSION_FACTOR
                    self.log_info(F'{engine.__class__.__name__} worked after skipping {t} bytes.')
                    return result
                except Exception:
                    pass
        else:
            self.log_info('nothing worked, returning original data.')
            return data
