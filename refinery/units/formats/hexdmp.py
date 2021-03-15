#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import re

from refinery.units.sinks import HexViewer
from refinery.lib.patterns import make_hexline_pattern


class hexdmp(HexViewer):
    """
    Convert hex dumps back to the original data and vice versa. All options of this unit apply
    to its reverse operation where binary data is converted to a readable hexdump format.
    The default mode of the unit expects the input data to contain a readable hexdump and
    converts it back to binary.
    """
    def __init__(self, hexaddr=True, width=0, expand=False):
        super().__init__(hexaddr=hexaddr, width=width, expand=expand)
        self._hexline_pattern = re.compile(F'{make_hexline_pattern(1)}(?:[\r\n]|$)', flags=re.MULTILINE)

    def process(self, data):
        data = data.decode(self.codec)
        decoded = bytearray()
        for hex, txt in self._hexline_pattern.findall(data):
            decoded_line = base64.b16decode(re.sub(R'\s*', '', hex))
            decoded.extend(decoded_line)
            if not txt:
                continue
            stripped_txt = txt.strip()
            if len(decoded_line) not in range(len(stripped_txt), len(txt) + 1):
                self.log_warn(F'preview size {len(txt)} does not match decoding: {hex} {txt}')
        return decoded

    def reverse(self, data):
        for line in self.hexdump(data):
            yield line.encode(self.codec)
