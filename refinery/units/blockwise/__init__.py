"""
Contains all units that can work on blocks a fixed length. Note that block cipher
algorithms can be found in `refinery.units.crypto.cipher`.
"""
from __future__ import annotations

import abc
import itertools

from collections.abc import Sized
from functools import cached_property
from typing import TYPE_CHECKING

from refinery.lib import chunks
from refinery.lib.inline import iterspread
from refinery.lib.tools import infinitize
from refinery.lib.types import INF, InfiniteIterable, Param, buf, isq
from refinery.units import Arg, Unit

if TYPE_CHECKING:
    from typing import Callable, Generator, Iterable, Iterator, Literal, TypeVar

    from numpy import ndarray
    _I = Iterable[int] | list[int] | int
    _T = TypeVar('_T', ndarray, int)


class FastBlockError(Exception):
    pass


class BlockTransformationBase(Unit, abstract=True):

    def __init__(
        self,
        bigendian: Param[bool, Arg.Switch('-E', help='Read chunks in big endian.')] = False,
        blocksize: Param[int, Arg.Number('-B', help=(
            'The size of each block in bytes. The default is {default}.'
        ))] = 1,
        precision: Param[int, Arg.Number('-P', help=(
            'The size of the variables used for computing the result. By default, this is equal to the block size. '
            'The value may be zero, indicating that arbitrary precision is required.'))] = -1,
        _truncate: Arg.Delete() = 0,
        **keywords
    ):
        self._truncate = _truncate
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, **keywords)

    @cached_property
    def _byte_order_symbol(self):
        if self.args.bigendian:
            return '>'
        else:
            return '<'

    @cached_property
    def _byte_order_adjective(self) -> Literal['big', 'little']:
        return 'big' if self.args.bigendian else 'little'

    @property
    def bytestream(self):
        """
        Indicates whether or not the block size is equal to 1, i.e. whether the unit is operating
        on a stream of bytes. In this case, many operations can be simplified.
        """
        return self.blocksize == 1

    @property
    def blocksize(self) -> int:
        return self.args.blocksize or 1

    @property
    def precision(self) -> int | INF:
        precision = self.args.precision
        if precision < 0:
            return self.blocksize
        if precision == 0:
            return INF()
        return precision

    @property
    def fbits(self) -> int | INF:
        return 8 * self.precision

    @property
    def fmask(self) -> int:
        return (1 << self.fbits) - 1

    def rest(self, data: bytearray):
        """
        Returns all excess bytes at the end of the input data that do not form a full block, based on
        the current operational block size of the unit.
        """
        if self.bytestream:
            return B''
        end = self.blocksize * (len(data) // self.blocksize)
        return data[end:]

    def chunk_into_bytes(self, data: buf) -> Generator[buf]:
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

    def __init__(self, *argument: Param[isq, Arg.NumSeq(help=(
        'A single numeric expression which provides the right argument to the operation, '
        'where the left argument is each block in the input data. This argument can also '
        'contain a sequence of bytes which is then split into blocks of the same size as '
        'the input data and used cyclically.'))],
        bigendian=False, blocksize=1, precision=-1, **kw
    ):
        super().__init__(bigendian=bigendian, blocksize=blocksize, precision=precision, argument=argument, **kw)

    def _argument_parse_hook(self, it: _I) -> tuple[_I, bool]:
        return it, False

    def _log_argument_reduction(self, original: int, reduced: int):
        self.log_warn(F'reduced argument to 0x{reduced:0{self.fbits // 4}X}; original value was 0x{original:X}')

    def _argument_reduction_logger(self) -> Callable[[int, int], None]:
        """
        Returns a function that logs argument reductions, warning about the first three of them
        before suppressing all further warnings.
        """
        warnings = 3

        def log(original: int, reduced: int):
            nonlocal warnings
            if not warnings:
                return
            warnings -= 1
            self._log_argument_reduction(original, reduced)
            if not warnings:
                self.log_warn('additional warnings are suppressed')

        return log

    def _mask_argument(self, it: _I) -> _I:
        """
        Reduces the given argument to the unit's block precision, warning about the first few
        reductions. Byte buffers pass through unchanged because their elements always fit the frame
        mask; integers are reduced directly. An `refinery.lib.types.InfiniteIterable` input is
        wrapped so that the result is still recognized as infinite.
        """
        if isinstance(it, int):
            out = it & self.fmask
            if out != it:
                self._log_argument_reduction(it, out)
            return out
        if isinstance(it, (bytes, bytearray)):
            return it

        def reduced(it: Iterable[int]):
            mask = self.fmask
            log = self._argument_reduction_logger()
            for block in it:
                out = block & mask
                if out != block:
                    log(block, out)
                yield out

        if isinstance(it, InfiniteIterable):
            return InfiniteIterable(reduced(it))
        return reduced(it)

    def _infinitize_argument(self, min_size: int, it: Iterable[int] | int) -> Iterator[int]:
        """
        Converts the given argument into an iterator over its blocks. Finite arguments repeat
        cyclically; byte sequences larger than 1 KiB are materialized at the required size instead,
        and integers repeat forever.
        """
        if isinstance(it, (bytes, bytearray)) and (n := len(it)) > 0x400:
            quotient, remainder = divmod(min_size, n)
            if remainder > 0:
                quotient += 1
            if quotient > 1:
                it = it * quotient
            return iter(it)
        if isinstance(it, int):
            it = (it,)
        return iter(infinitize(it)) # type:ignore

    def _prepare_argument(
        self,
        min_size: int,
        it: _I,
        masked: bool = False,
        vector: bool = False,
    ) -> Iterator[int]:
        """
        Prepares an argument returned by `_argument_parse_hook`: unless the hook has already reduced
        it to the unit's block precision, the argument is masked and then infinitized. When `vector`
        is set, integers and infinite arguments are not reduced here because the caller reduces them
        itself; this is used only by the numpy code path in `_fastblock`.
        """
        if not masked and not (vector and isinstance(it, (int, InfiniteIterable))):
            it = self._mask_argument(it)
        return self._infinitize_argument(min_size, it)

    @abc.abstractmethod
    def operate(self, block: _T, *args) -> _T:
        raise NotImplementedError

    def inplace(self, block: ndarray, *args) -> ndarray | None:
        tmp = self.operate(block, *args)
        if tmp.dtype != block.dtype:
            tmp = tmp.astype(block.dtype)
        block[:] = tmp

    @Unit.Requires('numpy', 0)
    def _numpy():
        import numpy
        return numpy

    def _argument_array(
        self,
        na: Iterator[int],
        dtype,
        num_blocks: int,
        log: Callable[[int, int], None],
    ) -> ndarray:
        """
        Converts an infinite argument that has not been reduced yet into a numpy array of the given
        dtype, reducing all values to the unit's block precision and reporting reductions via
        `log`. The argument is pulled and converted in chunks so that the temporary memory usage
        does not grow with the input size. Every chunk is staged in a list before it is converted,
        and values too large for the wide integer type are reduced in Python: an overflow would
        otherwise abort the pull halfway through the argument, which the one-shot arguments shared
        with the fallback paths would not survive.
        """
        numpy = self._numpy
        wide = numpy.dtype(F'{self._byte_order_symbol}u8')
        result = numpy.empty(num_blocks, dtype)

        pos = 0
        while pos < num_blocks:
            take = min(num_blocks - pos, 0x10000)
            chunk = list(itertools.islice(na, take))
            if len(chunk) < take:
                raise FastBlockError
            try:
                block = numpy.fromiter(chunk, wide, take)
            except OverflowError:
                reduced = [v & self.fmask for v in chunk]
                for original, masked in zip(chunk, reduced):
                    if original != masked:
                        log(original, masked)
                block = numpy.fromiter(reduced, wide, take)
            else:
                excess = numpy.flatnonzero(block > self.fmask)
                for k in excess[:3].tolist():
                    log(chunk[k], int(block[k]) & self.fmask)
                block &= self.fmask
            result[pos:pos + take] = block
            pos += take
        return result

    def _fastblock(self, data) -> bytearray:
        """
        Attempts to perform the operation more quickly by using numpy arrays.
        """
        try:
            numpy = self._numpy
        except ImportError as IE:
            raise FastBlockError from IE

        self.log_debug('fastblock: parsing and extending arguments')

        def _execute_hooks():
            for a in self.args.argument:
                it, masked = self._argument_parse_hook(a)
                na = self._prepare_argument(len(data), it, masked, vector=True)
                yield it, masked, na

        _hooks_executed = list(_execute_hooks())

        byte_order = self._byte_order_symbol
        num_blocks = len(data) // self.blocksize

        try:
            if self.precision is INF:
                # NumPy type for Python Objects
                dtype = numpy.dtype('O')
            else:
                dtype = numpy.dtype(F'{byte_order}u{self.precision!s}')
        except TypeError as T:
            raise FastBlockError from T

        br_args = []
        np_args = []
        loggers = []

        for it, masked, na in _hooks_executed:
            log = self._argument_reduction_logger()
            if isinstance(it, int):
                if not masked:
                    reduced = it & self.fmask
                    if reduced != it:
                        log(it, reduced)
                    it = reduced
                na = itertools.repeat(int(it))
                npa = int(it)
            elif self.precision is INF:
                npa = numpy.array(list(itertools.islice(na, num_blocks)), dtype=dtype)
            elif isinstance(it, InfiniteIterable):
                npa = self._argument_array(na, dtype, num_blocks, log)
            else:
                npa = numpy.fromiter(na, dtype, num_blocks)
            loggers.append(log)
            br_args.append(na)
            np_args.append(npa)

        if (_truncate := self._truncate) >= 2 or (_t := len(data) - num_blocks * self.blocksize) <= 0:
            rest = ()
        else:
            rest = data[-_t:]
            if _truncate < 1:
                last_ops = []
                for a, log in zip(br_args, loggers):
                    block = next(a)
                    reduced = block & self.fmask
                    if reduced != block:
                        log(block, reduced)
                    last_ops.append(reduced)
                last_int, = self.chunk(rest)
                dst_tail = self.operate(last_int, *last_ops) & self.fmask
                dst_tail = dst_tail.to_bytes(self.blocksize, self._byte_order_adjective)
                rest = dst_tail[:_t]

        try:
            stype = numpy.dtype(F'{byte_order}u{self.blocksize}')
        except TypeError as T:
            raise FastBlockError from T

        if not isinstance(data, bytearray):
            data = bytearray(data)

        self.log_debug(F'fastblock: loading {num_blocks} blocks of type {stype} from source data')

        dst = data
        src = numpy.frombuffer(dst, stype, num_blocks)
        if stype != dtype:
            src = src.astype(dtype)

        tmp = self.inplace(src, *np_args)

        if tmp is not None:
            src = tmp
            dst = None
        if stype != dtype:
            src = src.astype(stype)
            dst = None

        mem = memoryview(src)

        if dst is None:
            dst = bytearray(mem)
        elif (n := mem.nbytes) < len(dst):
            del tmp
            del mem
            del src
            try:
                del dst[n:]
            except BufferError:
                import gc
                gc.collect()
                del dst[n:]

        dst.extend(rest)
        return dst

    def process(self, data):
        try:
            self.log_debug('attempting to process input using numpy method')
            result = self._fastblock(data)
        except FastBlockError:
            pass
        except Exception as error:
            if self.log_debug():
                raise
            self.log_warn('falling back to default method after fast block failed with error:', error)
        else:
            self.log_debug('fast block method successful')
            return result
        size = len(data)
        arguments = [
            self._prepare_argument(size, *self._argument_parse_hook(a))
            for a in self.args.argument
        ]
        try:
            spread = iterspread(self.operate, self.chunk(data), *arguments, mask=self.fmask)
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
    def __init__(self, bigendian=False, blocksize=1, **kw):
        super().__init__(
            bigendian=bigendian, blocksize=blocksize, **kw)


class BinaryOperation(ArithmeticUnit, abstract=True):
    def __init__(self, *argument, bigendian=False, blocksize=1):
        if not argument:
            raise ValueError('a binary operation requires at least one argument')
        super().__init__(*argument, bigendian=bigendian, blocksize=blocksize)


class BinaryOperationWithAutoBlockAdjustment(BinaryOperation, abstract=True):
    def __init__(
        self, *argument, bigendian=False,
        blocksize: Param[int, Arg.Number(help=(
            'The size of each block in bytes. It is chosen, by default, to be the smallest size that can '
            'hold the provided argument without loss of precision. For example, passing the value 0x1234 '
            'will result in a default block size of 2, while passing the value 12 will mean that the '
            'default block size is 1.'
        ))] = 0
    ):
        super().__init__(*argument, bigendian=bigendian, blocksize=blocksize)

    def _argument_parse_hook(self, it: _I) -> tuple[_I, bool]:
        if isinstance(it, Sized) and len(it) == 1:
            it = it[0]
        if masked := isinstance(it, int):
            if not self.args.blocksize:
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
            blocksize = 0
        return blocksize or super().blocksize

    def process(self, data):
        try:
            return super().process(data)
        finally:
            self._blocksize = 0
