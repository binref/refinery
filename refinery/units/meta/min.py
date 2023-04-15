#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable
from refinery.units import Arg, Unit, Chunk
from refinery.lib.meta import metavars


class min_(Unit):
    """
    Picks the minimum of all elements in the current `refinery.lib.frame`.
    """

    def __init__(
        self,
        key: Arg('key', type=str, help='A meta variable expression to sort by instead of sorting the content.') = None,
    ):
        super().__init__(key=key)

    def filter(self, chunks: Iterable[Chunk]):
        def get_value(chunk: Chunk):
            if key is None:
                return chunk
            return metavars(chunk).get(key)

        key = self.args.key
        it = iter(chunks)

        for min_chunk in it:
            if not min_chunk.visible:
                yield min_chunk
            else:
                min_index = 0
                min_value = get_value(min_chunk)
                break
        else:
            return

        for index, chunk in enumerate(chunks, 1):
            if not chunk.visible:
                yield chunk
                continue
            value = get_value(chunk)
            try:
                is_min = value < min_value
            except TypeError:
                if min_value is None:
                    self.log_info(
                        F'Discarding chunk {min_index} in favor of {index} because {key} was not '
                        F'set on the former; new minimum is {value!r}.')
                    is_min = True
                else:
                    self.log_info(
                        F'Discarding chunk {index} because {key} had value {value!r}; it could not '
                        F'be compared to the current minimum {min_value!r} on chunk {min_index}.')
                    is_min = False
            if is_min:
                min_value = value
                min_chunk = chunk
                min_index = index

        yield min_chunk
