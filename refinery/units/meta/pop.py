#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools

from .. import arg, Unit
from . import check_variable_name


class _popcount:
    _MERGE_SYMBOL = '@'

    def __init__(self, name):
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
            self.count = 1
            self.field = check_variable_name(name)
        else:
            self.count = count
            self.field = None
        if self.count < 1:
            raise ValueError(F'Popcounts must be positive integer numbers, {self.count} is invalid.')

    def reset(self):
        self.current = self.count
        return self

    def into(self, meta, item):
        if self.current < 1:
            return False
        if self.field:
            if self.field is ...:
                meta.update(item.meta)
            else:
                meta[self.field] = item
        self.current -= 1
        return True


class pop(Unit):
    """
    In processing order, remove visible chunks from the current frame and store their contents in the given
    meta variables. All chunks in the input stream are consequently made visible again.
    """
    def __init__(
        self,
        *names: arg(type=str, metavar=F'[name|count|{_popcount._MERGE_SYMBOL}]', help=(
            R'Specify either the name of a single variable to receive the contents of an input chunk, or '
            R'an integer expression that specifies a number of values to be removed from the input without '
            F'storing them. Additionally, it is possible to specify the symbol "{_popcount._MERGE_SYMBOL}" '
            R'to remove a single chunk from the input and merge its meta data into the following ones. '
            F'By default, a single merge is performed.'
        ))
    ):
        if not names:
            names = _popcount._MERGE_SYMBOL,
        super().__init__(names=[_popcount(n) for n in names])

    def process(self, data):
        return data

    def filter(self, chunks):
        invisible = []
        variables = {}
        remaining = iter(self.args.names)

        it = iter(chunks)
        pop: _popcount = next(remaining).reset()

        for chunk in it:
            if not chunk.visible:
                self.log_debug('buffering invisible chunk')
                invisible.append(chunk)
                continue
            try:
                while not pop.into(variables, chunk):
                    pop = next(remaining).reset()
            except StopIteration:
                invisible.append(chunk)
                break
        try:
            next(remaining)
        except StopIteration:
            pass
        else:
            raise ValueError('Not all variables could be assigned.')

        for chunk in itertools.chain(invisible, it):
            chunk.meta.update(variables)
            chunk.visible = True
            yield chunk
