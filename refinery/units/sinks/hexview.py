#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import HexViewer


class hexview(HexViewer):
    """
    Produces a hex dump of the data.
    """
    def __init__(self, hexaddr=True, width=0, expand=False):
        super().__init__(hexaddr=hexaddr, width=width, expand=expand)

    def process(self, data):
        for line in self.hexdump(data):
            yield line.encode(self.codec)
