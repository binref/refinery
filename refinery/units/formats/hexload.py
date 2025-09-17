from __future__ import annotations

import inspect
import operator
import re

from typing import NamedTuple

from refinery.lib.patterns import make_hexline_pattern
from refinery.lib.tools import lookahead
from refinery.units import RefineryPartialResult
from refinery.units.sinks import HexViewer


class HexLineCheck(NamedTuple):
    decoded_length: int
    preview_length: int
    matched_binary: bool


def regex(cls: type) -> re.Pattern:
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

    def __init__(self, blocks=1, dense=False, expand=False, narrow=False, width=0):
        super().__init__(blocks=blocks, dense=dense, expand=expand, narrow=narrow, width=width)
        self._hexline_pattern = re.compile(F'{make_hexline_pattern(1)}(?:[\r\n]|$)', flags=re.MULTILINE)

    def process(self, data: bytearray):
        if not (lines := [
            line for line in data.decode(self.codec).splitlines(keepends=False)
            if line.strip()
        ]):
            return None

        result = bytearray()
        encoded_byte_matches: list[dict[int, int]] = []

        for check in lines:
            matches: dict[int, int] = {}
            encoded_byte_matches.append(matches)
            for match in self._ENCODED_BYTES.finditer(check):
                a, b = match.span()
                matches[a] = b - a

        it = iter(encoded_byte_matches)
        offsets = set(next(it).keys())
        for matches in it:
            offsets.intersection_update(matches.keys())
        if not offsets:
            raise ValueError('unable to determine the position of the hex bytes in this dump')
        lengths: dict[int, list[int]] = {offset: [] for offset in offsets}
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

        line_checks: list[HexLineCheck] = []

        for k, check in enumerate(lines, 1):
            encoded = check[offset:end]
            onlyhex = re.search(r'^[\sA-Fa-f0-9]+', encoded)
            if not onlyhex:
                self.log_warn(F'ignoring line without hexadecimal data: {check}')
                continue
            if onlyhex.group(0) != encoded:
                if k != len(lines):
                    self.log_warn(F'ignoring line with mismatching hex data length: {check}')
                    continue
                encoded = onlyhex.group(0)
            self.log_debug(F'decoding: {encoded.strip()}')
            decoded = bytes.fromhex(encoded)
            result.extend(decoded)
            matched = True
            if preview := check[end:]:
                pattern = re.compile(
                    '.'.join(re.escape(x.decode('ascii')) for x in re.split(b'[^!-~]', decoded)))
                matched = pattern.search(preview) is not None
            line_checks.append(HexLineCheck(len(decoded), len(preview), matched))

        decoded_sizes: set[int] = set()
        for last, hl in lookahead(line_checks):
            if not last:
                decoded_sizes.add(hl.decoded_length)
                if len(decoded_sizes) > 1:
                    raise RefineryPartialResult('inconsistent text preview sizes', result)

        for k, check in enumerate(line_checks, 1):
            if check.preview_length and not check.matched_binary:
                self.log_warn(F'preview mismatch in line {k}: {lines[k - 1]}', result)

        if result:
            yield result

    def reverse(self, data):
        metrics = self._get_metrics(len(data))
        if not self.args.width:
            metrics.fit_to_width(allow_increase=True)
        for line in self.hexdump(data, metrics):
            yield line.encode(self.codec)
