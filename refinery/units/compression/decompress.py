from __future__ import annotations

from enum import IntFlag

import colorama

from refinery.lib.id import get_structured_data_type
from refinery.lib.tools import bounds, normalize_to_display
from refinery.lib.types import INF, NamedTuple, Param, buf
from refinery.units import Arg, RefineryPartialResult, Unit

if True:
    colorama.init()

from colorama import Fore, Style

from .ap import aplib
from .blz import blz
from .brotli import brotli
from .bz2 import bz2
from .flz import flz
from .jcalg import jcalg
from .lz import _auto_decompress_lzma as lzma
from .lz4 import lz4
from .lzf import lzf
from .lzjb import lzjb
from .lznt1 import lznt1
from .lzo import lzo
from .lzw import lzw
from .mscf import MODE as MSCF_MODE
from .mscf import mscf
from .nrv import nrv2b, nrv2d, nrv2e
from .pkw import pkw
from .qlz import qlz
from .szdd import szdd
from .zl import zl
from .zstd import zstd

_COLOR_FAILURE = Fore.LIGHTRED_EX
_COLOR_SUCCESS = Fore.LIGHTCYAN_EX
_COLOR_WARNING = Fore.LIGHTYELLOW_EX
_CR = Style.RESET_ALL

_NO_PREFIX = {'pkw'}


class _R(IntFlag):
    InvalidData    = 0b000000  # noqa
    NotMangled     = 0b000001  # noqa
    ValidData      = 0b000010  # noqa
    KnownFormat    = 0b000100  # noqa
    HadOutput      = 0b001000  # noqa
    HadNoErrors    = 0b010000  # noqa
    Candidate      = 0b000110  # noqa
    Successful     = 0b011000  # noqa
    KnownFormatOut = 0b100000  # noqa

    @property
    def total(self):
        return self.value.bit_count()

    @property
    def summary(self):
        if self is _R.InvalidData:
            return F'{_COLOR_FAILURE}invalid{_CR}'
        elif _R.HadNoErrors & self:
            return F'{_COLOR_SUCCESS}success{_CR}'
        elif _R.HadOutput & self:
            return F'{_COLOR_WARNING}partial{_CR}'
        else:
            return F'{_COLOR_FAILURE}failure{_CR}'

    @property
    def brief(self):
        return ''.join(
            t if self & x else '\x20'
            for t, x in {
                'M': _R.KnownFormatOut,
                'V': _R.ValidData,
                'F': _R.KnownFormat,
                'O': _R.HadOutput,
                'K': _R.HadNoErrors
            }.items()
        )


class decompress(Unit):
    """
    Attempts all available decompression units against the input and returns
    the output of the first successful one. If none succeeds, the data is
    returned unaltered. The process is heavily biased against LZNT1 decompression
    due to a large tendency for LZNT1 false positives.
    """
    def __init__(
        self,
        prepend: Param[bool, Arg.Switch('-P', '--no-prepend', off=True, help=(
            'By default, if decompression fails, the unit attempts to prefix '
            'the data with all possible values of a single byte and decompress '
            'the result. This behavior can be disabled with this flag.')
        )] = True,
        tolerance: Param[int, Arg.Number('-t', help=(
            'Maximum number of bytes to strip from the beginning of the data; '
            'The default value is 12.')
        )] = 12,
        max_ratio: Param[float, Arg.Double('-m', metavar='R', help=(
            'To determine whether a decompression algorithm was successful, the '
            'ratio of compressed size to decompressed size may at most be as large '
            'as this number, a floating point value R; default value is {default}.')
        )] = 1.0,
        min_ratio: Param[float, Arg.Double('-n', metavar='R', help=(
            'Require that compression ratios must be at least as large as R. This '
            'is a "too good to be true" heuristic against algorithms like lznt1 '
            'that can produce false positives. The default is {default}.')
        )] = 0.0001,
        expand_limits: Param[slice, Arg.Bounds('-d', metavar='a:b', help=(
            'Ratio limits are expanded for sizes of input data in the given range, '
            'the default being 0:0x100. The reason for this is that small buffers '
            'can increase in size when compressed under many formats. Set this to :0 '
            'or use strict limits to disable this setting.')
        )] = range(0, 0x101),
        expand_factor: Param[float, Arg.Double('-k', help=(
            'The number by which the maximum compression ratio is multiplied for '
            'small buffers. The default is {default}.'
        ))] = 1.75,
        strict_limits: Param[bool, Arg.Switch('-l', help=(
            'For recognized formats i.e. when a magic signature is present, the '
            'above limits are disabled by default. Activate this flag to enforce '
            'them in every case.')
        )] = False

    ):
        if min_ratio <= 0:
            raise ValueError('The compression factor must be nonnegative.')
        super().__init__(
            tolerance=tolerance,
            prepend=prepend,
            min_ratio=min_ratio,
            max_ratio=max_ratio,
            strict_limits=strict_limits,
            expand_limits=expand_limits,
            expand_factor=expand_factor,
        )
        self.engines: dict[str, Unit] = {}
        for mode in (
            MSCF_MODE.XPRESS,
            MSCF_MODE.XPRESS_HUFF,
        ):
            mode = normalize_to_display(mode.name).casefold()
            unit = mscf.assemble(mode)
            self.engines[F'{unit.name}[{mode}]'] = unit
        for engine in [
            mscf,
            pkw,
            zstd,
            szdd,
            bz2,
            zl,
            lzf,
            flz,
            lzma,
            lzw,
            jcalg,
            lzo,
            aplib,
            qlz,
            brotli,
            blz,
            lzjb,
            lz4,
            lznt1,
            nrv2e,
            nrv2d,
            nrv2b,
        ]:
            unit: Unit = engine.assemble()
            _, _, name = unit.name.rpartition('auto-decompress-')
            self.engines[name] = unit
        for unit in self.engines.values():
            unit.log_detach()

    def process(self, data):

        data = memoryview(data)
        tiny = bounds[self.args.expand_limits]

        class Decompression(NamedTuple):
            method: str
            engine: Unit
            rating: _R
            result: buf | None = None
            cutoff: int = 0
            prefix: int | None = None
            magic: str | None = None

            def __str__(self):
                status = self.rating.summary
                method = self.method
                prefix = self.prefix
                if prefix is not None:
                    prefix = F'{_COLOR_WARNING}0x{prefix:02X}{_CR}'
                if cutoff := self.cutoff:
                    cutoff = F'{_COLOR_WARNING}0x{cutoff:02X}{_CR}'
                else:
                    cutoff = R'0x00'
                return F'prefix={prefix}, cutoff={cutoff}, [{status}] method={method}'

            def __len__(self):
                if not self.result:
                    return 0
                return len(self.result)

            @property
            def ratio(self):
                if not self.result:
                    return INF
                return (len(data) + int(bool(self.prefix)) - self.cutoff) / len(self)

            @property
            def unmodified(self):
                return self.prefix is None and self.cutoff == 0

        if self.args.prepend:
            buffer = bytearray(1 + len(data))
            buffer[1:] = data

        best_by_rating: dict[_R, Decompression] = {}

        def best_current_rating():
            return max(best_by_rating, default=_R.InvalidData)

        def decompress(method: str, engine: Unit, cutoff: int = 0, prefix: int | None = None, careful: bool = False):
            ingest = data[cutoff:]
            rating = _R.ValidData
            magic = None
            if cutoff == 0 and prefix is None and not careful:
                rating |= _R.NotMangled
            if prefix is not None:
                buffer[0] = prefix
                ingest = buffer
            is_handled = engine.handles(ingest)
            if is_handled is True:
                rating |= _R.KnownFormat
            if is_handled is False:
                return Decompression(method, engine, _R.InvalidData, None, cutoff, prefix)
            try:
                result = next(engine.act(ingest))
            except RefineryPartialResult as pr:
                rating |= _R.HadOutput
                result = pr.partial
            except Exception:
                result = None
            else:
                rating |= _R.Successful
                magic = get_structured_data_type(result)
                if magic is not None:
                    magic = magic.mnemonic
                    rating |= _R.KnownFormatOut

            return Decompression(method, engine, rating, result, cutoff, prefix, magic)

        def update(new: Decompression, discard_if_too_good=False):
            if not new.result:
                return
            ratio = new.ratio
            known = new.rating & _R.KnownFormat
            strict = self.args.strict_limits
            max_ratio = self.args.max_ratio
            min_ratio = self.args.min_ratio
            if not strict and len(data) in tiny:
                max_ratio *= self.args.expand_factor
                min_ratio /= self.args.expand_factor
            if (strict or not known) and not (min_ratio <= ratio <= max_ratio):
                return
            best = best_by_rating.get(new.rating, None)
            prefix = new.prefix
            if prefix is not None:
                prefix = F'0x{prefix:02X}'
            if new.unmodified and best and not best.unmodified:
                threshold = 1.00
            else:
                threshold = 0.95

            if not best:
                q = 0
            elif (q := len(best) / len(new)) > 1:
                # This is unexpected, but indicates that we may have produced incorrect output
                # before: What seems to work best is to force a reset at this point, although
                # it seems like there should be a better solution than this.
                q = -1
                assert best.result
                vb = memoryview(best.result)
                vn = memoryview(new.result)
                # This looks like we have skipped part of the compressed stream; At this point
                # we can abort and not force an update.
                if new.cutoff and vb[-len(vn):] == vn:
                    return

            if q < threshold:
                if best and discard_if_too_good:
                    if q < 0.5:
                        return
                    if new.rating & _R.Successful != _R.Successful:
                        return
                best_by_rating[new.rating] = new
                logger = self.log_info
                _color = _COLOR_SUCCESS
            else:
                logger = self.log_info
                _color = _COLOR_FAILURE
            if ratio >= 9:
                rs = 'USELESS'
                rc = _COLOR_FAILURE
            else:
                rs = F'{ratio * 100:6.2f}%'
                if ratio >= 1.1:
                    rc = _COLOR_FAILURE
                elif ratio >= 1.0:
                    rc = _COLOR_WARNING
                else:
                    rc = _COLOR_SUCCESS
            if q < 0:
                qs = 'RESTART'
            else:
                qs = F'{q:07.4f}'
            logger(lambda: (
                F'[{new.rating.brief}] [{rc}{rs}{_CR}] [q={_color}{qs}{_CR}] {new!s}'))

        for method, engine in self.engines.items():
            self.log_debug(F'attempting engine: {method}')
            careful = isinstance(engine, (lznt1, flz, lzjb))
            for t in range(self.args.tolerance + 1):
                if best_current_rating() >= _R.Successful and careful and t > 0:
                    break
                update(decompress(method, engine, t, None, careful), careful)
            if self.args.prepend and method not in _NO_PREFIX and best_current_rating() < _R.Successful:
                for p in range(0x100):
                    update(decompress(method, engine, 0, p, careful), careful)

        for r, u in best_by_rating.items():
            self.log_debug(r, u.method)

        for r in sorted(best_by_rating, reverse=True):
            if dc := best_by_rating[r]:
                if not dc.rating & _R.HadOutput:
                    continue
                self.log_info(F'settling on {dc.method} decompression, cutoff={dc.cutoff} and prefix={dc.prefix}.')
                if dc.rating & _R.NotMangled:
                    self.log_info('supporting evidence: no modifications to the buffer were necessary')
                if dc.rating & _R.KnownFormat:
                    self.log_info('supporting evidence: found a known magic signature')
                if dc.rating & _R.HadNoErrors:
                    self.log_info('supporting evidence: engine produced output without errors')
                elif dc.rating & _R.HadOutput:
                    self.log_info('supporting evidence: there were errors, but the engine produced output')
                if not dc.rating & _R.Successful:
                    self.log_info('the only decompression with result returned only a partial result.')
                if dc.rating & _R.KnownFormatOut and (magic := dc.magic):
                    self.log_info(F'the decompressed result had a known format: {magic}')
                return self.labelled(dc.result, method=dc.method)

        raise ValueError('no compression engine worked')
