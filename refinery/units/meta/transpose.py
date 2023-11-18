#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable, List
from refinery.units import Arg, Unit, Chunk


class transpose(Unit):
    """
    Interprets the chunks in the current frame as rows of a matrix and yields the columns
    of that matrix. When chunks are not of even length, the matrix is considered to have
    empty entries in some positions. Optionally, a padding sequence can be provided to pad
    all rows to the same length.
    """
    @Unit.Requires('numpy', 'speed', 'default', 'extended')
    def _numpy():
        import numpy
        return numpy

    def __init__(
        self,
        padding: Arg(help='Optional byte sequence to use as padding for incomplete rows.') = B'',
    ):
        super().__init__(bigendian=False, padding=padding)

    def filter(self, chunks: Iterable[Chunk]):
        rows = []
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            rows.append(chunk)
        if not rows:
            return
        matrix = rows[0]
        matrix.temp = rows
        yield matrix

    def process(self, data: Chunk):
        chunks: List[Chunk] = data.temp
        if not chunks:
            return
        length = [len(chunk) for chunk in chunks]
        n = min(length)
        m = max(length)
        pad = self.args.padding
        if pad:
            for chunk in chunks:
                while len(chunk) < m:
                    chunk.extend(pad)
                del chunk[m:]
        if n > 0:
            try:
                np = self._numpy
            except ImportError:
                pass
            else:
                t = [chunk[n:] for chunk in chunks if len(chunk) > n]
                for chunk in chunks:
                    del chunk[n:]
                a = np.array(chunks, dtype=np.uint8).transpose()
                for row in a:
                    yield row.tobytes('C')
                m = m - n
                chunks = t
        for i in range(m):
            yield bytes(chunk[i] for chunk in chunks if len(chunk) > i)
