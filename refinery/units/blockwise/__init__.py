#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contains all units that can work on blocks a fixed length. Note that block cipher
algorithms can be found in `refinery.units.crypto.cipher`.
"""
import abc
import itertools

from refinery.units import Arg, Unit
from refinery.lib.argformats import numseq
from refinery.lib import chunks
from refinery.lib.tools import infinitize, cached_property
from refinery.lib.inline import iterspread
from refinery.lib.types import Singleton, INF


class FastBlockError(ImportError):
    pass


class NoMask(metaclass=Singleton):
    def __rand__(self, other):
        return other


class BlockTransformationBase(Unit, abstract=True):

    def __init__(
        self,
        bigendian: Arg.Switch('-E', help='Read chunks in big endian.') = False,
        blocksize: Arg.Number('-B', help='The size of each block in bytes, default is 1.') = 1,
        precision: Arg.Number('-P', help=(
            'The size of the variables used for computing the result. By default, this is equal to the block size. The value may be '
            'zero, indicating that arbitrary precision is required.')) = None,
        **keywords
    ):
        if precision is None:
            precision = blocksize
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, **keywords)

    @cached_property
    def bytestream(self):
        """
        Indicates whether or not the block size is equal to 1, i.e. whether the unit is operating
        on a stream of bytes. In this case, many operations can be simplified.
        """
        return self.args.blocksize == 1

    @cached_property
    def fbits(self):
        size = self.args.precision
        if not size:
            return INF
        return 8 * size

    @cached_property
    def fmask(self):
        fbits = self.fbits
        if fbits is INF:
            return NoMask
        return (1 << fbits) - 1

    def rest(self, data):
        if self.bytestream:
            return B''
        end = self.args.blocksize * (len(data) // self.args.blocksize)
        return data[end:]

    def chunk(self, data, raw=False):
        if not raw:
            return chunks.unpack(data, self.args.blocksize, self.args.bigendian)

        def chunkraw(data, b: int):
            stop = len(data)
            stop = stop - stop % b
            for k in range(0, stop, b):
                yield data[k : k + b]

        return chunkraw(data, self.args.blocksize)

    def unchunk(self, data, raw=False):
        if self.args.precision > self.args.blocksize:
            mask = (1 << (8 * self.args.blocksize)) - 1
            data = (chunk & mask for chunk in data)
        if not raw:
            return chunks.pack(data, self.args.blocksize, self.args.bigendian)

        def bytefilter(it):
            for item in it:
                if isinstance(item, (bytes, bytearray)):
                    yield item
                else:
                    yield bytes(item)

        return B''.join(bytefilter(data))


class BlockTransformation(BlockTransformationBase, abstract=True):

    def process(self, data):
        pb = self.process_block
        return self.unchunk(
            pb(b) for b in self.chunk(data)
        ) + self.rest(data)

    @abc.abstractmethod
    def process_block(self, block):
        """
        A blockwise operation implements this routine to process each block, which
        is given as an integer. The return value is also expected to be an integer.
        """
        raise NotImplementedError


class ArithmeticUnit(BlockTransformation, abstract=True):

    def __init__(self, *argument: Arg(type=numseq, help=(
        'A single numeric expression which provides the right argument to the operation, '
        'where the left argument is each block in the input data. This argument can also '
        'contain a sequence of bytes which is then split into blocks of the same size as '
        'the input data and used cyclically.')),
        bigendian=False, blocksize=1, precision=None, **kw
    ):
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, argument=argument, **kw)

    def _normalize_argument(self, it):
        for block in infinitize(it):
            yield block & self.fmask

    @abc.abstractmethod
    def operate(self, block, *args) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def inplace(self, block, *args) -> None:
        tmp = self.operate(block, *args)
        if tmp.dtype != block.dtype:
            tmp = tmp.astype(block.dtype)
        block[:] = tmp

    @Unit.Requires('numpy', 'speed', 'default')
    def _numpy():
        import numpy
        return numpy

    def _fastblock(self, data):
        """
        Attempts to perform the operation more quickly by using numpy arrays.
        """
        try:
            numpy = self._numpy
        except ModuleNotFoundError as IE:
            raise FastBlockError from IE
        order = '<>'[self.args.bigendian]
        try:
            dtype = numpy.dtype(F'{order}u{self.args.precision}')
        except TypeError:
            dtype = numpy.dtype('O')
        stype = numpy.dtype(F'{order}u{self.args.blocksize}')
        blocks = len(data) // self.args.blocksize

        def nparg(buffer):
            if hasattr(buffer, '__len__') and len(buffer) == 1:
                buffer = buffer[0]
            if isinstance(buffer, int):
                self.log_info('detected numeric argument')
                return buffer & self.fmask
            infty = self._normalize_argument(buffer)
            if not self.args.precision:
                return numpy.array(list(itertools.islice(infty, blocks)), dtype=dtype)
            else:
                return numpy.fromiter(infty, dtype, blocks)

        rest = data[blocks * self.args.blocksize:]

        data = numpy.frombuffer(memoryview(data), stype, blocks)
        if stype != dtype:
            data = data.astype(dtype)
        args = [nparg(a) for a in self.args.argument]
        self.inplace(data, *args)
        if stype != dtype:
            data = data.astype(stype)
        return data.tobytes() + rest

    def process(self, data):
        try:
            self.log_debug('Attempting to process input using numpy method.')
            result = self._fastblock(data)
        except ImportError:
            pass
        except Exception as error:
            self.log_warn(F'Falling back to default method after numpy failed with error: {error}')
        else:
            self.log_debug('successfully used numpy to process data in ecb mode')
            return result

        arguments = [self._normalize_argument(a) for a in self.args.argument]

        try:
            mask = self.fmask
            if mask is NoMask:
                mask = None
            spread = iterspread(self.operate, self.chunk(data), *arguments, mask=mask)
            return self.unchunk(spread(self)) + self.rest(data)
        except Exception as E:
            self.log_warn(F'unable to inline this operation: {E!s}')
            self.log_warn(R'falling back all the way to failsafe method')
            self._arg = arguments
            return super().process(data)

    def process_block(self, block):
        return self.operate(block, *(next(a) for a in self._arg)) & self.fmask


class UnaryOperation(ArithmeticUnit, abstract=True):
    def __init__(self, bigendian=False, blocksize=1):
        super().__init__(
            bigendian=bigendian, blocksize=blocksize)

    def inplace(self, block) -> None:
        super().inplace(block)


class BinaryOperation(ArithmeticUnit, abstract=True):
    def __init__(self, argument: Arg(nargs=Arg.delete), bigendian=False, blocksize=1):
        super().__init__(argument,
            bigendian=bigendian, blocksize=blocksize)

    def inplace(self, block, argument) -> None:
        super().inplace(block, argument)
