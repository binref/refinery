#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from . import HexViewerMixin


class hexview(Unit, HexViewerMixin):
    """
    Produces a hex dump of the data.
    """

    def interface(self, argp):
        return super().interface(self.hexviewer_interface(argp))

    def process(self, data):
        for line in self.hexdump(data):
            yield line.encode(self.codec)
