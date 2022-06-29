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
            pos = re.search(sig, mem[pos:], flags=re.IGNORECASE)
            if pos is None:
                break
            pos = pos.start()
            self.log_debug(F'potential RTF document at {pos}')
            end = pos + 1
            depth = 1
            while depth and end < len(mem):
                try:
                    k = B'}{'.index(mem[end])
                except Exception:
                    continue
                else:
                    depth += 2 * k - 1
                finally:
                    end += 1
            if depth > 0:
                break
            yield self.labelled(mem[pos:end], offset=pos)
            pos = end
