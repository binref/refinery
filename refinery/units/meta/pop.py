#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable, Iterator
from itertools import chain

from refinery.units import Arg, Unit, Chunk
from refinery.lib.argformats import DelayedNumSeqArgument
from refinery.lib.meta import check_variable_name


class _popcount:
    _MERGE_SYMBOL = '@'

    def __init__(self, name: str):
        self.conversion = None
        self.current = 0
        if name == self._MERGE_SYMBOL:
            self.count = 1
            self.field = ...
            return
        try:
            if isinstance(name, int):
                count = name
            else:
                count = int(name, 0)
        except Exception:
            name, colon, conversion = name.partition(':')
            self.count = 1
            self.field = check_variable_name(name)
            if colon == ':':
                self.conversion = conversion
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
                if self.conversion:
                    delayed = DelayedNumSeqArgument(self.conversion, seed=chunk, typecheck=False)
                    chunk = delayed(chunk)
                meta[self.field] = chunk
        self.current -= 1
        return True


class pop(Unit):
    """
    In processing order, remove visible chunks from the current frame and store their contents in the given
    meta variables. All chunks in the input stream are consequently made visible again. If pop is used at
    the end of a frame, then variables will be local to the parent frame.
    """
    def __init__(
        self,
        *names: Arg(type=str, metavar=F'[name[:conversion]|count|{_popcount._MERGE_SYMBOL}]', help=(
            R'Specify either the name of a single variable to receive the contents of an input chunk, or '
            R'an integer expression that specifies a number of values to be removed from the input without '
            F'storing them. Additionally, it is possible to specify the symbol "{_popcount._MERGE_SYMBOL}" '
            R'to remove a single chunk from the input and merge its meta data into the following ones. By '
            R'default, a single merge is performed. When a variable name is specified, a sequence of '
            R'transformations can be appended to be applied before storing it. For example, the argument '
            R'k:le:b64 would first decode the chunk using base64, then convert it to an integer in little '
            R'endian format, and store the integer result in the variable `k`. The visual aid is that the '
            R'content is passed from right to left through all conversions, into the variable `k`.'
        ))
    ):
        if not names:
            names = _popcount._MERGE_SYMBOL,
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
            raise ValueError('Not all variables could be assigned.')

        nesting = self.args.nesting

        for chunk in chain(invisible, it):
            meta = chunk.meta
            meta.update(variables)
            if nesting < 0:
                for name in variables:
                    meta.set_scope(name, chunk.scope + nesting)
            chunk.visible = True
            yield chunk
