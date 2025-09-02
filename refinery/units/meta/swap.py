#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Iterable

from refinery.units import Arg, Unit

from refinery.lib.meta import check_variable_name
from refinery.lib.frame import Chunk
from refinery.lib.tools import isbuffer


class swap(Unit):
    """
    Swap the contents of an existing variable with the contents of the chunk or with another meta variable.
    When swapping with the chunk, the variable has to contain a binary string. When swapping with a variable
    that does not exist, the original variable is cleared, essentially renaming the variable.
    """
    def __init__(
        self,
        src: Arg(type=str, help='The meta variable name.'),
        dst: Arg(type=str, help='Optional name of the second meta variable.') = None
    ):
        super().__init__(
            src=check_variable_name(src),
            dst=check_variable_name(dst)
        )

    def filter(self, chunks: Iterable[Chunk]):
        src = self.args.src
        dst = self.args.dst
        for chunk in chunks:
            if not chunk.visible:
                pass
            elif dst is None:
                try:
                    value = chunk.meta[src]
                except KeyError:
                    value = bytearray()
                if isinstance(value, str):
                    value = value.encode(self.codec)
                elif not isbuffer(value):
                    raise ValueError(F'Unable to swap data with variable {src} because it has type {type(value).__name__}.')
                if not chunk:
                    chunk.meta.discard(src)
                else:
                    chunk.meta[src] = bytes(chunk)
                chunk[:] = value
            else:
                try:
                    value = chunk.meta.pop(src)
                except KeyError:
                    raise KeyError(F'The variable {src} does not exist.')
                try:
                    swap = chunk.meta.pop(dst)
                except KeyError:
                    chunk.meta[dst] = value
                else:
                    chunk.meta[src], chunk.meta[dst] = swap, value
            yield chunk
