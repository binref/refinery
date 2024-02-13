#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contains all units that can work on blocks a fixed length. Note that block cipher
algorithms can be found in `refinery.units.crypto.cipher`.
"""
from __future__ import annotations

import abc
import itertools

from typing import TYPE_CHECKING

from refinery.units import Arg, Unit
from refinery.lib.argformats import numseq
from refinery.lib import chunks
from refinery.lib.tools import infinitize, cached_property
from refinery.lib.inline import iterspread
from refinery.lib.types import Singleton, INF

if TYPE_CHECKING:
    from numpy import ndarray
    from typing import TypeVar, Iterable, Generator, Optional
    _T = TypeVar('_T')


class FastBlockError(Exception):
    pass


class NoMask(metaclass=Singleton):
    def __rand__(self, other):
        return other


class BlockTransformationBase(Unit, abstract=True):

    def __init__(
        self,
        bigendian: Arg.Switch('-E', help='Read chunks in big endian.') = False,
        blocksize: Arg.Number('-B', help='The size of each block in bytes, default is 1.') = None,
        precision: Arg.Number('-P', help=(
            'The size of the variables used for computing the result. By default, this is equal to the block size. The value may be '
            'zero, indicating that arbitrary precision is required.')) = None,
        _truncate: Arg.Delete() = 0,
        **keywords
    ):
        if precision is None:
            precision = blocksize
        self._truncate = _truncate
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, **keywords)

    @cached_property
    def _byte_order_symbol(self):
        if self.args.bigendian:
            return '>'
        else:
            return '<'

    @cached_property
    def _byte_order_adjective(self):
        if self.args.bigendian:
            return 'big'
        else:
            return 'little'

    @property
    def bytestream(self):
        """
        Indicates whether or not the block size is equal to 1, i.e. whether the unit is operating
        on a stream of bytes. In this case, many operations can be simplified.
        """
        return self.blocksize == 1

    @property
    def blocksize(self):
        return self.args.blocksize or 1

    @property
    def precision(self):
        precision = self.args.precision
        if precision is None:
            return self.blocksize
        if precision == 0:
            return INF
        return precision

    @property
    def fbits(self):
        return 8 * self.precision

    @property
    def fmask(self):
        fbits = self.fbits
        if fbits is INF:
            return NoMask
        return (1 << fbits) - 1

    def rest(self, data: bytearray):
        """
        Returns all excess bytes at the end of the input data that do not form a full block, based on
        the current operational block size of the unit.
        """
        if self.bytestream:
            return B''
        end = self.blocksize * (len(data) // self.blocksize)
        return data[end:]

    def chunk_into_bytes(self, data: _T) -> Generator[_T | bytearray, None, None]:
        """
        Returns an iterator over the blocks of the input data according to the current operational block
        size. The blocks are returned as slices of the input data. Note that zero bytes may be appended if
        auto padding is enabled.
        """
        n = len(data)
        b = self.blocksize
        m = n - n % b
        for k in range(0, m, b):
            yield data[k : k + b]
        if self._truncate > 0 or m == n:
            return
        last = bytearray(data[m:])
        last.extend(itertools.repeat(0, -n % b))
        yield last

    def chunk(self, data: bytearray):
        """
        Returns an iterator over the blocks of the input data according to the current operational block
        size. The blocks are returned as integers that have been parsed out according to the unit's byte
        order setting.
        """
        pad = self._truncate < 1
        return chunks.unpack(data, self.blocksize, self.args.bigendian, pad=pad)

    def unchunk(self, data: Iterable[int]):
        """
        Convert an iterable of integer blocks into a byte string representation based on the operational
        block size and byte order settings of the unit.
        """
        if self.precision > self.blocksize:
            mask = (1 << (8 * self.blocksize)) - 1
            data = (chunk & mask for chunk in data)
        return chunks.pack(data, self.blocksize, self.args.bigendian)


class BlockTransformation(BlockTransformationBase, abstract=True):

    def process(self, data):
        work = self.process_block
        size = len(data)
        temp = (work(b) for b in self.chunk(data))
        out = self.unchunk(temp)
        if self._truncate < 1:
            del out[size:]
        elif self._truncate < 2:
            out.extend(self.rest(data))
        return out

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
        bigendian=False, blocksize=None, precision=None, **kw
    ):
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, argument=argument, **kw)

    def _argument_parse_hook(self, it):
        if hasattr(it, '__len__') and len(it) == 1:
            it = it[0]
        return it, False

    def _normalize_argument(self, it, masked=False):
        def _mask(it):
            warnings = 3
            for block in it:
                out = block & self.fmask
                if warnings and out != block:
                    warnings -= 1
                    self.log_warn(F'reduced argument to 0x{out:0{self.fbits // 4}X}; original value was 0x{block:X}')
                    if not warnings:
                        self.log_warn('additional warnings are suppressed')
                yield out
        it = infinitize(it)
        if not masked:
            it = _mask(it)
        return it

    @abc.abstractmethod
    def operate(self, block, *args) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def inplace(self, block: ndarray, *args) -> Optional[ndarray]:
        tmp: ndarray = self.operate(block, *args)
        if tmp.dtype != block.dtype:
            tmp = tmp.astype(block.dtype)
        block[:] = tmp

    @Unit.Requires('numpy', 'speed', 'default', 'extended')
    def _numpy():
        import numpy
        return numpy

    def _fastblock(self, data):
        """
        Attempts to perform the operation more quickly by using numpy arrays.
        """
        try:
            numpy = self._numpy
        except ImportError as IE:
            raise FastBlockError from IE

        order = self._byte_order_symbol
        args = [self._argument_parse_hook(a) for a in self.args.argument]
        blocks = len(data) // self.blocksize

        try:
            if self.precision is None:
                dtype = numpy.dtype('O')
            else:
                dtype = numpy.dtype(F'{order}u{self.precision!s}')
        except TypeError as T:
            raise FastBlockError from T

        npargs = []

        for k, (it, masked) in enumerate(args):
            na = self._normalize_argument(it, masked)
            args[k] = na
            if isinstance(it, int):
                if not masked:
                    it &= self.fmask
                npa = it
            elif self.precision is INF:
                npa = numpy.array(list(itertools.islice(na, blocks)), dtype=dtype)
            else:
                npa = numpy.fromiter(na, dtype, blocks)
            npargs.append(npa)

        overlap = len(data) - blocks * self.blocksize

        try:
            stype = numpy.dtype(F'{order}u{self.blocksize}')
        except TypeError as T:
            raise FastBlockError from T

        src = numpy.frombuffer(memoryview(data), stype, blocks)
        if stype != dtype:
            src = src.astype(dtype)
        tmp = self.inplace(src, *npargs)
        if tmp is not None:
            src = tmp
        if stype != dtype:
            src = src.astype(stype)
        dst = bytearray(memoryview(src))
        if overlap and self._truncate < 2:
            rest = self.rest(data)
            if self._truncate < 1:
                last_ops = [next(a) for a in args]
                last_int = int.from_bytes(rest, self._byte_order_adjective)
                dst_tail = self.operate(last_int, *last_ops)
                dst_tail = dst_tail.to_bytes(self.blocksize, self._byte_order_adjective)
                rest = dst_tail[:overlap]
            dst.extend(rest)
        return dst

    def process(self, data):
        try:
            self.log_debug('attempting to process input using numpy method')
            result = self._fastblock(data)
        except FastBlockError:
            pass
        except Exception as error:
            self.log_warn('falling back to default method after fast block failed with error:', error)
        else:
            self.log_debug('fast block method successful')
            return result
        try:
            arguments = [
                self._normalize_argument(*self._argument_parse_hook(a))
                for a in self.args.argument
            ]
            mask = self.fmask
            size = len(data)
            if mask is NoMask:
                mask = None
            spread = iterspread(self.operate, self.chunk(data), *arguments, mask=mask)
            out = self.unchunk(spread(self))
            if self._truncate < 1:
                del out[size:]
            elif self._truncate < 2:
                out.extend(self.rest(data))
            return out
        except Exception as E:
            self.log_warn(F'unable to inline this operation: {E!s}')
            self.log_warn(R'falling back all the way to failsafe method')
            self._arg = arguments
            return super().process(data)

    def process_block(self, block):
        return self.operate(block, *(next(a) for a in self._arg)) & self.fmask


class UnaryOperation(ArithmeticUnit, abstract=True):
    def __init__(self, bigendian=False, blocksize=None, **kw):
        super().__init__(
            bigendian=bigendian, blocksize=blocksize, **kw)

    def inplace(self, block) -> None:
        super().inplace(block)


class BinaryOperation(ArithmeticUnit, abstract=True):
    def __init__(self, argument: Arg.Delete(), bigendian=False, blocksize=None):
        super().__init__(argument,
            bigendian=bigendian, blocksize=blocksize)

    def inplace(self, block, argument) -> None:
        super().inplace(block, argument)


class BinaryOperationWithAutoBlockAdjustment(BinaryOperation, abstract=True):

    def _argument_parse_hook(self, it):
        it, masked = super()._argument_parse_hook(it)
        if isinstance(it, int):
            masked = True
            if self.args.blocksize is None:
                self.log_debug('detected numeric argument with no specified block size')
                bits = it.bit_length()
                if bits > self.blocksize * 8:
                    length, r = divmod(bits, 8)
                    length += int(bool(r))
                    self.log_info(F'setting block size to {length} based on the argument bit size')
                    self._blocksize = length
            else:
                it &= self.fmask
        return it, masked

    @property
    def blocksize(self):
        try:
            blocksize = self._blocksize
        except AttributeError:
            blocksize = None
        return blocksize or super().blocksize

    def process(self, data):
        try:
            return super().process(data)
        finally:
            self._blocksize = None
