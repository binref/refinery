#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from refinery.units import Unit


class carve_rtf(Unit):
    """
    Extracts anything from the input data that looks like an RTF document.
    """

    def process(self, data: bytearray):
        pos = 0
        mem = memoryview(data)
        sig = re.escape(b'{\\rtf')

        while True:
            match = re.search(sig, mem[pos:], flags=re.IGNORECASE)
            if match is None:
                break
            pos = pos + match.start()
            end = pos + 1
            depth = 1
            while depth and end < len(mem):
                if mem[end] == 0x7B:  # {
                    depth += 1
                if mem[end] == 0x7D:  # }
                    depth -= 1
                end += 1
            if depth > 0:
                break
            yield self.labelled(mem[pos:end], offset=pos)
            pos = end
