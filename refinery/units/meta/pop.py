#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools

from .. import arg, Unit
from . import check_variable_name


class _popcount:

    def __init__(self, name):
        try:
            self.count = int(name, 0)
        except Exception:
            self.count = 1
            self.name = check_variable_name(name)
        else:
            self.name = None
        if self.count < 1:
            raise ValueError(F'Popcounts must be positive integer numbers, {self.count} is invalid.')

    def reset(self):
        self.current = self.count
        return self

    def into(self, meta, item):
        if self.current < 1:
            return False
        if self.name:
            meta[self.name] = item
        self.current -= 1
        return True


class pop(Unit):
    """
    In processing order, remove visible chunks from the current frame and store their contents in the
    given meta variables.
    """
    def __init__(
        self,
        *names: arg(type=str, metavar='[name|count]', help=(
            'Specify either the name of a single variable to receive the contents of an input chunk, or '
            'an integer expression that specifies a number of values to be removed from the input without '
            'storing them.'
        ))
    ):
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
