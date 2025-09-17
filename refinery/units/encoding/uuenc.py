from __future__ import annotations

import itertools
import pathlib
import re

from refinery.lib import chunks
from refinery.lib.meta import metavars
from refinery.lib.structures import MemoryFile
from refinery.units import RefineryPartialResult, Unit


class uuenc(Unit):
    """
    Unit for uuencode.
    """
    def process(self, data):
        header = re.search(
            B'^begin ([0-7]{3}) (.*?)$', data, flags=re.M)
        if header is None:
            raise ValueError('invalid uu header')
        output = bytearray()
        view = memoryview(data)
        breaks = [m.end() for m in iter(re.finditer(B'^', data, flags=re.M))]
        eol = False
        for k, br in enumerate(itertools.islice(breaks, 1, None)):
            if eol and view[br:br + 3] == b'end':
                path = header[2]
                if path != B'-':
                    output = self.labelled(output, path=path)
                return output
            count = view[br] - 0x20
            if count not in range(0x41):
                raise ValueError(F'Invalid length encoding 0x{view[br]:02X} in line {k}.')
            count %= 0x40
            cursor = len(output)
            q, r = divmod(count, 3)
            q += int(bool(r))
            end = br + 1 + q * 4
            for b in range(br + 1, end, 4):
                chunk = 0
                for j in range(4):
                    character = view[b + j]
                    if character not in range(0x21, 0x61):
                        raise ValueError(F'Invalid character 0x{character:02X} in line {k}.')
                    chunk = ((character - 0x20) % 0x40) | (chunk << 6)
                output.extend(chunk.to_bytes(3, 'big'))
            del output[cursor + count:]
            eol = count == 0
            if len(output) < cursor + count:
                break
        raise RefineryPartialResult(F'Data truncated in line {k}', output)

    def reverse(self, data):
        meta = metavars(data)
        path = meta.get('path', None)
        name = path and pathlib.Path(path).name or '-'
        view = memoryview(data)
        with MemoryFile() as stream:
            stream.write(B'begin 666 ')
            stream.write(name.encode(self.codec))
            for k in range(0, len(view), 45):
                slice = view[k:k + 45]
                stream.write_byte(0x0A)
                stream.write_byte(0x20 + len(slice))
                for chunk in chunks.unpack(slice, 3, bigendian=True, pad=True):
                    for j in range(3, -1, -1):
                        stream.write_byte(0x20 + (((chunk >> j * 6) & 0x3F) or 0x40))
            stream.write(B'\n`\nend\n')
            return stream.getvalue()

    @classmethod
    def handles(cls, data):
        if len(data) < 16:
            return False
        if data[:6] == B'begin ':
            return re.fullmatch(B'[0-7]{3}', data[6:9]) is not None
