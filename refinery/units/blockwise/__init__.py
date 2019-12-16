#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contains all units that can work on blocks a fixed length. Note that block cipher
algorithms can be found in `refinery.units.crypto.cipher`.
"""
from itertools import cycle
from inspect import signature, Parameter

from .. import Unit
from ...lib.argformats import numbin, number
from ...lib import chunks


class NoNumpy(Exception):
    pass


class BlockTransformation(Unit, abstract=True):
    def interface(self, argp):
        block = argp.add_argument_group(
            'Block Options',
            'Controls how the input data is split into blocks.'
        )
        block.add_argument('-N', '--nbo', dest='little_endian', action='store_false',
            help='Read chunks in network byte order (big endian).')
        block.add_argument('-B', '--blocksize', metavar='N', type=number[1:], default=1,
            help='The size of each block in bytes, default is 1.')

        return super().interface(argp)

    @property
    def bytestream(self):
        return self.args.blocksize == 1

    @property
    def fbits(self):
        return 8 * self.args.blocksize

    @property
    def fmask(self):
        return (1 << self.fbits) - 1

    def rest(self, data):
        if self.bytestream:
            return B''
        end = self.args.blocksize * (len(data) // self.args.blocksize)
        return data[end:]

    def chunk(self, data, raw=False):
        if not raw:
            return chunks.unpack(data, self.args.blocksize, self.args.little_endian)

        def chunkraw(data):
            stop = len(data)
            stop = stop - stop % self.args.blocksize
            for k in range(0, stop, self.args.blocksize):
                yield data[k : k + self.args.blocksize]

        return chunkraw(data)

    def unchunk(self, data, raw=False):
        if not raw:
            return chunks.pack(data, self.args.blocksize, self.args.little_endian)

        def bytefilter(it):
            for item in it:
                if isinstance(item, (bytes, bytearray)):
                    yield item
                else:
                    yield bytes(item)

        return B''.join(bytefilter(data))

    def process(self, data):
        return self.unchunk(
            self.process_block(b) for b in self.chunk(data)
        ) + self.rest(data)

    def process_block(self, block):
        """
        A blockwise operation implements this routine to process each block, which
        is given as an integer. The return value is also expected to be an integer.
        """
        raise NotImplementedError


class ArithmeticUnit(BlockTransformation, abstract=True):
    operate = NotImplemented
    inplace = NotImplemented

    def interface(self, argp):
        specs = signature(self.operate)
        nargs = len(specs.parameters) - 1
        if any(p.kind == Parameter.VAR_POSITIONAL for p in specs.parameters.values()):
            nargs = '*'
        if nargs:
            argp.add_argument('arg', type=numbin, nargs=nargs, help=(
                'A single numeric expression which provides the right argument to the operation, '
                'where the left argument is each block in the input data. This argument can also '
                'contain a sequence of bytes which is then split into blocks of the same size as '
                'the input data and used cyclically.'))
        else:
            argp.set_defaults(arg=[])
        return super().interface(argp)

    def process_ecb_fast(self, data):
        """
        Attempts to perform the operation more quickly by using numpy arrays.
        """
        try:
            import numpy
        except ModuleNotFoundError:
            raise NoNumpy

        order = '<' if self.args.little_endian else '>'
        dtype = numpy.dtype(F'{order}u{self.args.blocksize}')
        blocks = len(data) // self.args.blocksize

        def nparg(buffer):
            if hasattr(buffer, '__len__') and len(buffer) == 1:
                buffer = buffer[0]
            if isinstance(buffer, int):
                self.log_info('detected numeric argument')
                return buffer & self.fmask
            return numpy.fromiter(cycle(buffer), dtype, blocks)

        rest = data[blocks * self.args.blocksize:]
        data = numpy.frombuffer(data, dtype, blocks)
        args = [nparg(a) for a in self.args.arg]

        if self.inplace is NotImplemented:
            data = self.operate(data, *args)
            if data.dtype != dtype:
                data = data.astype(dtype)
        else:
            data = data.copy()
            self.inplace(data, *args)
        return data.tobytes() + rest

    def process(self, data):
        try:
            result = self.process_ecb_fast(data)
        except NoNumpy:
            pass
        except Exception as error:
            self.log_warn(F'falling back to default method after numpy failed with error: {error}')
        else:
            self.log_debug('successfully used numpy to process data in ecb mode')
            return result
        self._arg = [cycle(a) for a in self.args.arg]
        return super().process(data)

    def process_block(self, block):
        return self.operate(block, *(next(a) & self.fmask for a in self._arg)) & self.fmask
