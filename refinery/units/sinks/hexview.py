#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import HexViewer


class hexview(HexViewer):
    """
    Produces a hex dump of the data.
    """
    def process(self, data):
        for line in self.hexdump(data):
            yield line.encode(self.codec)
