#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import inspect

from refinery.units.sinks import HexViewer
from refinery.lib.patterns import make_hexline_pattern


def regex(cls):
    return re.compile(inspect.getdoc(cls))


class hexdmp(HexViewer):
    """
    Convert hex dumps back to the original data and vice versa. All options of this unit apply
    to its reverse operation where binary data is converted to a readable hexdump format.
    The default mode of the unit expects the input data to contain a readable hexdump and
    converts it back to binary.
    """
    @regex
    class _ENCODED_BYTES:
        R"""
        (?ix)(?:\s|^)                       # encoded byte patches must be prefixed by white space
        (?:
            (?:                             # separated chunks of hex data
                [a-f0-9]{2}                 # hexadecimal chunk; single byte (two hexadecimal letters)
                (\s+)                       # encoded byte followed by whitespace
                (?:                         # at least one more encoded byte
                    [a-f0-9]{2}             # followed by more encoded bytes using the same spacing
                    (?:\1[a-f0-9]{2})*      # unless it was just a single byte
                )?
            )
            | (?:[a-f0-9]{4}(\s+)(?:[a-f0-9]{4}(?:\2[a-f0-9]{4})*)?)   # 2-byte chunks
            | (?:[a-f0-9]{8}(\s+)(?:[a-f0-9]{8}(?:\3[a-f0-9]{8})*)?)   # 4-byte chunks
            | (?:(?:[a-f0-9]{2})+)\b       # continuous line of hexadecimal characters
        )
        """

    def __init__(self, hexaddr=True, width=0, expand=False):
        super().__init__(hexaddr=hexaddr, width=width, expand=expand)
        self._hexline_pattern = re.compile(F'{make_hexline_pattern(1)}(?:[\r\n]|$)', flags=re.MULTILINE)

    def process(self, data):
        lines = data.decode(self.codec).splitlines(keepends=False)
        decoded_bytes = bytearray()
        for line in lines:
            matches = {}
            for match in self._ENCODED_BYTES.finditer(line):
                encoded_bytes = match[0]
                matches[len(encoded_bytes)] = match
            if not matches:
                if decoded_bytes:
                    yield decoded_bytes
                    decoded_bytes.clear()
                continue
            encoded_line = matches[max(matches)][0]
            self.log_debug(F'decoding: {encoded_line.strip()}')
            decoded_line = bytes.fromhex(encoded_line)
            decoded_bytes.extend(decoded_line)
            txt = line[match.end():]
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
