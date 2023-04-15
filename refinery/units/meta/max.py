#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable
from refinery.units import Arg, Unit, Chunk
from refinery.lib.meta import metavars


class max_(Unit):
    """
    Picks the maximum of all elements in the current `refinery.lib.frame`.
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

        for max_chunk in it:
            if not max_chunk.visible:
                yield max_chunk
            else:
                max_index = 0
                max_value = get_value(max_chunk)
                break
        else:
            return

        for index, chunk in enumerate(chunks, 1):
            if not chunk.visible:
                yield chunk
                continue
            value = get_value(chunk)
            try:
                is_max = value > max_value
            except TypeError:
                if max_value is None:
                    self.log_info(
                        F'Discarding chunk {max_index} in favor of {index} because {key} was not '
                        F'set on the former; new maximum is {value!r}.')
                    is_max = True
                else:
                    self.log_info(
                        F'Discarding chunk {index} because {key} had value {value!r}; it could not '
                        F'be compared to the current maximum {max_value!r} on chunk {max_index}.')
                    is_max = False
            if is_max:
                max_value = value
                max_chunk = chunk
                max_index = index

        yield max_chunk
