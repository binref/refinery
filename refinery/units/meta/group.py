#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


_GROUP_MEMBER_ATTRIBUTE = '_group_members'


class group(Unit):
    """
    Group incoming chunks into frames of the given size.
    """
    def __init__(self, size: arg.number(help='Size of each group; must be at least 2.', bound=(2, None))):
        super().__init__(size=size)

    def process(self, data):
        members = data.__dict__.pop(_GROUP_MEMBER_ATTRIBUTE, [])
        if len(members) >= self.args.size:
            raise RuntimeError(F'received {len(members) + 1} items in group')
        yield data
        yield from members

    def filter(self, chunks):
        members = []
        header = None
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            if len(members) > self.args.size - 2:
                yield header
                header = None
            if header is None:
                header = chunk
                members.clear()
                assert _GROUP_MEMBER_ATTRIBUTE not in header.__dict__
                setattr(header, _GROUP_MEMBER_ATTRIBUTE, members)
            else:
                members.append(chunk)
        if header is not None:
            yield header
