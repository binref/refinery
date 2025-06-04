#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable, Iterator
from itertools import chain

from refinery.units import Arg, Unit, Chunk
from refinery.lib.argformats import DelayedNumSeqArgument
from refinery.lib.meta import check_variable_name


_MERGE_META = '@'
_CONVERSION = ':'
_CHERRYPICK = '='


class _popcount:
    def __init__(self, name: str):
        self.conversion = None
        self.cherrypick = None
        self.current = 0
        if name == _MERGE_META:
            self.count = 1
            self.field = ...
            return
        try:
            if isinstance(name, int):
                count = name
            else:
                count = int(name, 0)
        except Exception:
            name, colon, conversion = name.partition(_CONVERSION)
            name, equal, cherrypick = name.partition(_CHERRYPICK)
            if equal:
                self.cherrypick = cherrypick
            if colon:
                self.conversion = conversion
            self.count = 1
            self.field = check_variable_name(name)
        else:
            self.count = count
            self.field = None
        if self.count < 1:
            raise ValueError(F'Popcounts must be positive integer numbers, {self.count} is invalid.')

    @property
    def done(self):
        return self.current < 1

    def reset(self):
        self.current = self.count
        return self

    def into(self, meta: dict, chunk: Chunk):
        if self.done:
            return False
        if self.field:
            if self.field is ...:
                meta.update(chunk.meta.current)
            else:
                chunk = chunk.meta[c] if (c := self.cherrypick) else chunk
                if c := self.conversion:
                    chunk = DelayedNumSeqArgument(c, seed=chunk, reverse=True, typecheck=False)(chunk)
                meta[self.field] = chunk
        self.current -= 1
        return True


class pop(Unit):
    """
    In processing order, remove visible chunks from the current frame and store their contents in
    the given meta variables on all chunks that remain. All chunks in the input stream are
    consequently made visible again. If pop is used at the end of a frame, then variables will be
    local to the parent frame. A pop instruction has the following format:

        count | {_MERGE_META} | name[{_CHERRYPICK}source][{_CONVERSION}conversion]

    If the instruction is an integer, it is interpreted as `count`, specifying a number of chunks
    to be skipped from the frame without storing them. The letter "{_MERGE_META}" can be used to
    remove a single chunk from the input and merge all of its meta data into the ones that follow.
    Otherwise, the pop instruction consists of the name of the variable to be created, an optional
    source variable name, and an optional conversion sequence. If no source variable is specified,
    the chunk contents are used as the source. The conversion is a sequence of multibin handlers
    that are applied to the source data from right to left before storing it.
    For example, the argument `k:le:b64` first decodes the chunk data using base64, then converts
    it to an integer in little endian format, and store the integer result in the variable `k`. The
    visual aid is that the content is passed from right to left through all conversions, into the
    variable `k`. Similarly, the argument k=size will store the current chunk's size in `k`.
    """
    def __init__(
        self,
        *names: Arg(type=str, metavar='instruction', help='A sequence of instructions, see above.')
    ):
        if not names:
            names = _MERGE_META,
        super().__init__(names=[_popcount(n) for n in names])

    def process(self, data):
        return data

    def filter(self, chunks: Iterable[Chunk]):
        invisible = []
        variables = {}
        remaining: Iterator[_popcount] = iter(self.args.names)

        it = iter(chunks)
        pop = next(remaining).reset()
        done = False

        for chunk in it:
            if not chunk.visible:
                self.log_debug('buffering invisible chunk')
                invisible.append(chunk)
                continue
            try:
                while not pop.into(variables, chunk):
                    pop = next(remaining).reset()
            except StopIteration:
                done = True
                invisible.append(chunk)
                break

        if not done and pop.done:
            try:
                next(remaining)
            except StopIteration:
                done = True

        if not done:
            msg = 'Not all variables could be assigned.'
            if not self.leniency:
                raise ValueError(F'{msg} Increase leniency to downgrade this failure to a warning.')
            self.log_warn(msg)

        nesting = self.args.nesting

        for chunk in chain(invisible, it):
            meta = chunk.meta
            meta.update(variables)
            if nesting < 0:
                for name in variables:
                    meta.set_scope(name, chunk.scope + nesting)
            chunk.visible = True
            yield chunk


pop.__doc__ = pop.__doc__.format(
    _MERGE_META=_MERGE_META,
    _CONVERSION=_CONVERSION,
    _CHERRYPICK=_CHERRYPICK,
)

__pdoc__ = dict(pop=pop.__doc__)
