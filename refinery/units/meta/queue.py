#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple tool to queue binary data as one or more chunks in the current frame.
"""
from typing import ByteString, Iterable, Union
from refinery.units import Arg, Unit, Chunk


class queue(Unit):

    def __init__(self,
        *data: Arg(help=(
            'The arguments are appended to the current frame in the given order.')),
        front: Arg.Switch('-f', help='Queue items at the top of the current frame.')
    ):
        super().__init__(data=data, front=front)

    def act(self, data: Union[Chunk, ByteString]) -> ByteString:
        return data

    def filter(self, chunks: Iterable[Chunk]):
        chunks = iter(chunks)

        try:
            head = next(chunks)
        except StopIteration:
            self.log_warn('unexpected empty frame: cannot determine depth, aborting')
            return

        def more():
            for bin in self.args.data:
                chunk = head.copy(meta=False, data=False)
                chunk[:] = bin
                yield chunk

        if self.args.front:
            yield from more()
            yield head
            yield from chunks
        else:
            yield head
            yield from chunks
            yield from more()
