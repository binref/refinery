#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class trivia(Unit):
    """
    Populates the set of meta variables of the current chunk with various pieces of information. The
    unit has no effect outside a frame. If no option is given, all meta variables are populated.
    """
    def __init__(
        self,
        size  : arg.switch('-L', help='The size of the chunk.') = False,
        index : arg.switch('-I', help='Index of the chunk in the current frame.') = False,
    ):
        if not any((size, index)):
            size = True
            index = True
        super().__init__(size=size, index=index)

    def process(self, data):
        return data

    def filter(self, chunks):
        index = 0
        for chunk in chunks:
            if chunk.visible:
                if self.args.index:
                    chunk['index'] = index
                    index += 1
                if self.args.size:
                    chunk['size'] = len(chunk)
            yield chunk
