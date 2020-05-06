#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools

from .. import arg, Unit


class mpop(Unit):
    """
    In processing order, remove visible chunks from the current frame and store
    their contents in the given meta variables.
    """
    def __init__(
        self,
        *names: arg(type=str, metavar='name', help='The meta variable names.')
    ):
        super().__init__(names=names)

    def process(self, data):
        return data

    def filter(self, chunks):
        invisible = []
        variables = {}
        remaining = iter(self.args.names)

        it = iter(chunks)

        for chunk in it:
            if not chunk.visible:
                self.log_debug('buffering invisible chunk')
                invisible.append(chunk)
                continue
            try:
                name = next(remaining)
                variables[name] = chunk
                self.log_debug('setting variable', name)
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
