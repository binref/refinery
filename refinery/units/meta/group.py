#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class group(Unit):
    """
    Group incoming chunks into frames of the given size.
    """
    def __init__(self, size: arg.number(help='Size of each group; must be at least 2.', bound=(2, None))):
        super().__init__(size=size)

    def process(self, data):
        members = data.meta.pop('__grpm')
        assert len(members) < self.args.size, F'received {len(members) + 1} items in group'
        yield data
        yield from members

    def filter(self, inputs):
        members = []
        header = None
        for chunk in inputs:
            if not chunk.visible:
                yield chunk
                continue
            if len(members) > self.args.size - 2:
                yield header
                header = None
            if header is None:
                header = chunk
                header['__grpm'] = members = []
            else:
                members.append(chunk)
        if header is not None:
            yield header
