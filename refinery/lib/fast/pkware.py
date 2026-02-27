from __future__ import annotations

from refinery.lib.fast._pkware_tables import _COPY_LENGTHS, _COPY_OFFSETS, _LITERALS


class PKWareError(Exception):
    def __init__(self, msg: str, partial: bytearray):
        super().__init__(msg)
        self.partial = partial


def pkware_decompress(data: bytes | bytearray | memoryview) -> bytearray:
    codelit = data[0]
    maxdict = data[1]

    if not 0 <= codelit <= 1:
        raise ValueError(F'Invalid literal encoding value {codelit}.')
    if not 4 <= maxdict <= 6:
        raise ValueError(F'Invalid dictionary size {maxdict}.')

    pos = 2
    end = len(data)
    bbits = 0
    nbits = 0
    output = bytearray()

    def _read(n: int) -> int:
        nonlocal pos, bbits, nbits
        while nbits < n:
            if pos >= end:
                raise EOFError
            bbits |= data[pos] << nbits
            pos += 1
            nbits += 8
        result = bbits & ((1 << n) - 1)
        bbits >>= n
        nbits -= n
        return result

    def _table(table: dict[tuple[int, int], int], start: int, stop: int) -> int:
        value = length = 0
        while length < start:
            value <<= 1
            value |= _read(1)
            length += 1
        while length < stop:
            try:
                return table[length, value]
            except KeyError:
                value <<= 1
                value |= _read(1)
                length += 1
        raise ValueError(
            'Failed to decode a symbol in the compressed data stream.')

    while pos < end or nbits:
        try:
            if not _read(1):
                if codelit:
                    code = _table(_LITERALS, 4, 14)
                else:
                    code = _read(8)
                output.append(code)
            else:
                length = _table(_COPY_LENGTHS, 2, 0x10)
                if length == 519:
                    break
                offset = _table(_COPY_OFFSETS, 2, 0x09)
                more = (2 if length == 2 else maxdict)
                offset <<= more
                offset += _read(more)
                offset += 1
                cursor = len(output)
                rep, r = divmod(length, offset)
                start = cursor - offset
                chunk = bytes(output[start:cursor])
                if rep > 0:
                    output.extend(chunk * rep)
                if r > 0:
                    output.extend(chunk[:r])
        except Exception as E:
            if not output:
                raise
            raise PKWareError(str(E), output) from E

    return output
