#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple tool to queue binary data as one or more chunks in the current frame.
"""
from typing import ByteString, Iterable, Generator, Union
from refinery.units import Arg, Unit, Chunk


class QueueUnit(Unit, abstract=True):
    def __init__(self, *data: Arg(help=(
        'The arguments are inserted into the current frame in the given order. These arguments '
        'are multibin expressions; If the expression depends on the input data, it will always '
        'refer to the first chunk in the current frame. If no argument is given, a single empty'
        ' chunk is inserted.'
    ))):
        super().__init__(data=data)

    def act(self, data: Union[Chunk, ByteString]) -> ByteString:
        return data

    def _queue(self, chunks: Iterable[Chunk], front: bool) -> Generator[Chunk, None, None]:
        it = iter(chunks)

        try:
            head = next(it)
        except StopIteration as SI:
            raise RuntimeError('unexpected empty frame: cannot determine depth') from SI

        def queue():
            data = self.args.data or [B'']
            for bin in data:
                chunk = head.copy(meta=False, data=False)
                chunk[:] = bin
                yield chunk

        def frame():
            yield head
            yield from it

        a, b = frame(), queue()
        if front:
            a, b = b, a
        yield from a
        yield from b


class qf(QueueUnit):
    """
    Short for "queue front": Insert new chunks at the beginning of the current frame.
    """
    def filter(self, chunks: Iterable[Chunk]):
        yield from self._queue(chunks, True)


class qb(QueueUnit):
    """
    Short for "queue back": Insert new chunks at the end of the current frame.
    """
    def filter(self, chunks: Iterable[Chunk]):
        yield from self._queue(chunks, False)
