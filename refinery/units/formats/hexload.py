#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import operator
import re

from typing import Dict, List, Type

from refinery.units.sinks import HexViewer
from refinery.lib.patterns import make_hexline_pattern


def regex(cls: Type) -> re.Pattern:
    return re.compile(inspect.getdoc(cls))


class hexload(HexViewer):
    """
    Convert hex dumps back to the original data and vice versa. All options of this unit apply
    to its reverse operation where binary data is converted to a readable hexdump format.
    The default mode of the unit expects the input data to contain a readable hexdump and
    converts it back to binary.
    """
    @regex
    class _ENCODED_BYTES:
        R"""
        (?ix)(?:^|(?<=\s))                      # encoded byte patches must be prefixed by white space
        (?:
            (?:                                 # separated chunks of hex data
                [a-f0-9]{2}                     # hexadecimal chunk; single byte (two hexadecimal letters)
                \s{1,2}                         # encoded byte followed by whitespace
                (?:                             # at least one more encoded byte
                    [a-f0-9]{2}                 # followed by more encoded bytes
                    (?:\s{1,2}[a-f0-9]{2})*     # unless it was just a single byte
                )?
            )
            | (?:[a-f0-9]{4}\s{1,2}             # 2-byte chunks
              (?:[a-f0-9]{4}
              (?:\s{1,2}[a-f0-9]{4})*)?)
            | (?:[a-f0-9]{8}\s{1,2}             # 4-byte chunks
              (?:[a-f0-9]{8}
              (?:\s{1,2}[a-f0-9]{8})*)?)
            | (?:(?:[a-f0-9]{2})+)              # continuous line of hexadecimal characters
        )(?=\s|$)                               # terminated by a whitespace or line end
        """

    def __init__(self, blocks=1, dense=False, expand=False, narrow=True, width=0):
        super().__init__(blocks=blocks, dense=dense, expand=expand, narrow=narrow, width=width)
        self._hexline_pattern = re.compile(F'{make_hexline_pattern(1)}(?:[\r\n]|$)', flags=re.MULTILINE)

    def process(self, data: bytearray):
        lines = data.decode(self.codec).splitlines(keepends=False)

        if not lines:
            return None

        decoded_bytes = bytearray()
        encoded_byte_matches: List[Dict[int, int]] = []

        for line in lines:
            matches: Dict[int, int] = {}
            encoded_byte_matches.append(matches)
            for match in self._ENCODED_BYTES.finditer(line):
                a, b = match.span()
                matches[a] = b - a

        it = iter(encoded_byte_matches)
        offsets = set(next(it).keys())
        for matches in it:
            offsets.intersection_update(matches.keys())
        if not offsets:
            raise ValueError('unable to determine the position of the hex bytes in this dump')
        lengths: Dict[int, List[int]] = {offset: [] for offset in offsets}
        del offsets
        for matches in encoded_byte_matches:
            for offset in lengths:
                lengths[offset].append(matches[offset])
        for offset in lengths:
            lengths[offset].sort()
        midpoint = len(encoded_byte_matches) // 2
        offset, length = max(((offset, lengths[offset][midpoint]) for offset in lengths),
            key=operator.itemgetter(1))
        end = offset + length
        del lengths
        for line in lines:
            encoded_line = line[offset:end]
            self.log_debug(F'decoding: {encoded_line.strip()}')
            decoded_line = bytes.fromhex(encoded_line)
            decoded_bytes.extend(decoded_line)
            txt = line[end:]
            txt_stripped = txt.strip()
            if not txt_stripped:
                continue
            if len(decoded_line) not in range(len(txt_stripped), len(txt) + 1):
                self.log_warn(F'preview size {len(txt_stripped)} does not match decoding: {line}')
        if decoded_bytes:
            yield decoded_bytes

    def reverse(self, data):
        for line in self.hexdump(data):
            yield line.encode(self.codec)
