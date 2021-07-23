#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Iterable, TYPE_CHECKING
if TYPE_CHECKING:
    from ...lib.frame import Chunk

from .. import Unit


class cull(Unit):
    """
    Remove all chunks from the current `refinery.lib.frame` if they are not visible. Chunks can become invisible
    by exclusion through `refinery.iff`, `refinery.iffp`, `refinery.iffs`, `refinery.iffx`, or `refinery.scope`.
    """
    def filter(self, chunks: Iterable[Chunk]):
        for chunk in chunks:
            if chunk.visible:
                yield chunk
