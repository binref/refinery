#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, List, NamedTuple, Optional, Dict

from enum import IntFlag

from refinery.units import Arg, Unit, RefineryPartialResult
from refinery.lib.types import INF

from .ap import aplib
from .blz import blz
from .brotli import brotli
from .bz2 import bz2
from .jcalg import jcalg
from .lz import _auto_decompress_lzma as lzma
from .lz4 import lz4
from .lzjb import lzjb
from .lznt1 import lznt1
from .lzo import lzo
from .szdd import szdd
from .zl import zl
from .qlz import qlz
from .lzf import lzf
from .lzw import lzw
from .nrv import nrv2b, nrv2d, nrv2e
from .zstd import zstd


class _R(IntFlag):
    InvalidData = 0b00000  # noqa
    NotMangled  = 0b00001  # noqa
    ValidData   = 0b00010  # noqa
    KnownFormat = 0b00100  # noqa
    HadOutput   = 0b01000  # noqa
    HadNoErrors = 0b10000  # noqa
    Candidate   = 0b00110  # noqa
    Successful  = 0b11000  # noqa

    @property
    def total(self):
        return self.value.bit_count()

    @property
    def summary(self):
        if self is _R.InvalidData:
            return 'invalid'
        elif _R.HadNoErrors & self:
            return 'success'
        elif _R.HadOutput & self:
            return 'partial'
        else:
            return 'failure'

    @property
    def brief(self):
        return ''.join(
            t if self & x else ' '
            for t, x in {
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
        prepend: Arg.Switch('-P', '--no-prepend', off=True, help=(
            'By default, if decompression fails, the unit attempts to prefix '
            'the data with all possible values of a single byte and decompress '
            'the result. This behavior can be disabled with this flag.')
        ) = True,
        tolerance: Arg.Number('-t', help=(
            'Maximum number of bytes to strip from the beginning of the data; '
            'The default value is 12.')
        ) = 12,
        max_ratio: Arg('-m', metavar='R', help=(
            'To determine whether a decompression algorithm was successful, the '
            'ratio of compressed size to decompressed size may at most be as large '
            'as this number, a floating point value R; default value is {default}.')
        ) = 1.0,
        min_ratio: Arg('-n', metavar='R', help=(
            'Require that compression ratios must be at least as large as R. This '
            'is a "too good to be true" heuristic against algorithms like lznt1 '
            'that can produce false positives. The default is {default}.')
        ) = 0.0001,
        strict_limits: Arg('-l', action='store_true', help=(
            'For recognized formats, i.e. when a magic signature is present, the '
            'above limits are disabled by default. Activate this flag to enforce '
            'them in every case.')
        ) = False

    ):
        if min_ratio <= 0:
            raise ValueError('The compression factor must be nonnegative.')
        super().__init__(
            tolerance=tolerance,
            prepend=prepend,
            min_ratio=min_ratio,
            max_ratio=max_ratio,
            strict_limits=strict_limits,
        )
        self.engines: List[Unit] = [
            engine.assemble() for engine in [
                zstd, szdd, bz2, zl, lzf, lzma, lzw, jcalg, lzo, aplib, qlz, brotli, blz, lzjb, lz4, lznt1, nrv2e, nrv2d, nrv2b]
        ]
        for engine in self.engines:
            engine.log_detach()

    def process(self, data):

        data = memoryview(data)

        class Decompression(NamedTuple):
            engine: Unit
            rating: _R
            result: Optional[ByteString] = None
            cutoff: int = 0
            prefix: Optional[int] = None

            def __str__(self):
                status = self.rating.summary
                engine = self.engine.name
                prefix = self.prefix
                if prefix is not None:
                    prefix = F'0x{prefix:02X}'
                return F'prefix={prefix}, cutoff=0x{self.cutoff:02X}, [{status}] engine={engine}'

            def __len__(self):
                return len(self.result)

            @property
            def ratio(self):
                if not self.result:
                    return INF
                return len(data) / len(self)

            @property
            def unmodified(self):
                return self.prefix is None and self.cutoff == 0

            @property
            def method(self):
                return self.engine.name

        if self.args.prepend:
            buffer = bytearray(1 + len(data))
            buffer[1:] = data

        best_by_rating: Dict[_R, Decompression] = {}

        def best_current_rating():
            return max(best_by_rating, default=_R.InvalidData)

        def decompress(engine: Unit, cutoff: int = 0, prefix: Optional[int] = None, careful: bool = False):
            ingest = data[cutoff:]
            rating = _R.ValidData
            if cutoff == 0 and prefix is None and not careful:
                rating |= _R.NotMangled
            if prefix is not None:
                buffer[0] = prefix
                ingest = buffer
            is_handled = engine.handles(ingest)
            if is_handled is True:
                rating |= _R.KnownFormat
            if is_handled is False:
                return Decompression(engine, _R.InvalidData, None, cutoff, prefix)
            try:
                result = next(engine.act(ingest))
            except RefineryPartialResult as pr:
                rating |= _R.HadOutput
                result = pr.partial
            except Exception:
                result = None
            else:
                rating |= _R.Successful
            return Decompression(engine, rating, result, cutoff, prefix)

        def update(new: Decompression, discard_if_too_good=False):
            ratio = new.ratio
            if self.args.strict_limits or not new.rating & _R.KnownFormat:
                if ratio > self.args.max_ratio:
                    return
                if ratio < self.args.min_ratio:
                    return
            best = best_by_rating.get(new.rating, None)
            prefix = new.prefix
            if prefix is not None:
                prefix = F'0x{prefix:02X}'
            if new.unmodified and best and not best.unmodified:
                threshold = 1
            else:
                threshold = 0.95
            if not best or len(new) < len(best):
                q = 0
            else:
                q = len(best) / len(new)
            ratio *= 100
            brief = new.rating.brief
            if q < threshold:
                if best and discard_if_too_good:
                    if q < 0.5:
                        return
                    if new.rating & _R.Successful != _R.Successful:
                        return
                self.log_info(lambda:
                    F'[switch] [{brief}] [q={q:07.4f}] compression ratio {ratio:07.4f}% with: {new!s}')
                best_by_rating[new.rating] = new
            else:
                self.log_debug(lambda:
                    F'[reject] [{brief}] [q={q:07.4f}] compression ratio {ratio:07.4f}% with: {new!s}')

        for engine in self.engines:
            self.log_debug(F'attempting engine: {engine.name}')
            careful = isinstance(engine, (lznt1, lzf, lzjb))
            for t in range(self.args.tolerance + 1):
                if best_current_rating() >= _R.Successful and careful and t > 0:
                    break
                update(decompress(engine, t, None, careful), careful)
            if self.args.prepend and best_current_rating() < _R.Successful:
                for p in range(0x100):
                    update(decompress(engine, 0, p, careful), careful)

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
                return self.labelled(dc.result, method=dc.method)

        raise ValueError('no compression engine worked')
