#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import struct
import copy

from .. import arg, Unit, RefineryPartialResult


class lznt1(Unit):
    """
    LZNT1 compression and decompression. This compression algorithm is expected
    by the Win32 API routine `RtlDecompressBuffer`, for example.
    """

    def _decompress_chunk(self, chunk):
        out = B''
        while chunk:
            flags = chunk[0]
            chunk = chunk[1:]
            for i in range(8):
                if not (flags >> i & 1):
                    out += chunk[:1]
                    chunk = chunk[1:]
                else:
                    flag = struct.unpack('<H', chunk[:2])[0]
                    pos = len(out) - 1
                    l_mask = 0xFFF
                    o_shift = 12
                    while pos >= 0x10:
                        l_mask >>= 1
                        o_shift -= 1
                        pos >>= 1
                    length = (flag & l_mask) + 3
                    offset = (flag >> o_shift) + 1
                    if length >= offset:
                        tmp = out[-offset:] * (0xFFF // len(out[-offset:]) + 1)
                        out += tmp[:length]
                    else:
                        out += out[-offset:length - offset]
                    chunk = chunk[2:]
                if len(chunk) == 0:
                    break
        return out

    def _find(self, src, target, max_len):
        result_offset = 0
        result_length = 0
        for i in range(1, max_len):
            offset = src.rfind(target[:i])
            if offset == -1:
                break
            tmp_offset = len(src) - offset
            tmp_length = i
            if tmp_offset == tmp_length:
                tmp = src[offset:] * (0xFFF // len(src[offset:]) + 1)
                for j in range(i, max_len + 1):
                    offset = tmp.rfind(target[:j])
                    if offset == -1:
                        break
                    tmp_length = j
            if tmp_length > result_length:
                result_offset = tmp_offset
                result_length = tmp_length
        if result_length < 3:
            return 0, 0
        return result_offset, result_length

    def _compress_chunk(self, chunk):
        blob = copy.copy(chunk)
        out = B''
        pow2 = 0x10
        l_mask3 = 0x1002
        o_shift = 12
        while len(blob) > 0:
            bits = 0
            tmp = B''
            for i in range(8):
                bits >>= 1
                while pow2 < (len(chunk) - len(blob)):
                    pow2 <<= 1
                    l_mask3 = (l_mask3 >> 1) + 1
                    o_shift -= 1
                if len(blob) < l_mask3:
                    max_len = len(blob)
                else:
                    max_len = l_mask3
                offset1, length1 = self._find(
                    chunk[:len(chunk) - len(blob)], blob, max_len)
                # try to find more compressed pattern
                offset2, length2 = self._find(
                    chunk[:len(chunk) - len(blob) + 1], blob[1:], max_len)
                if length1 < length2:
                    length1 = 0
                if length1 > 0:
                    symbol = ((offset1 - 1) << o_shift) | (length1 - 3)
                    tmp += struct.pack('<H', symbol)
                    bits |= 0x80  # set the highest bit
                    blob = blob[length1:]
                else:
                    tmp += blob[:1]
                    blob = blob[1:]
                if len(blob) == 0:
                    break
            out += struct.pack('B', bits >> (7 - i))
            out += tmp
        return out

    def reverse(self, buf):
        out = B''
        while buf:
            chunk = buf[:self.args.chunk_size]
            compressed = self._compress_chunk(chunk)
            if len(compressed) < len(chunk):  # chunk is compressed
                flags = 0xB000
                header = struct.pack('<H', flags | (len(compressed) - 1))
                out += header + compressed
            else:
                flags = 0x3000
                header = struct.pack('<H', flags | (len(chunk) - 1))
                out += header + chunk
            buf = buf[self.args.chunk_size:]
        return out

    def process(self, data):
        out = io.BytesIO()
        offset = 0
        while offset < len(data):
            try:
                header, = struct.unpack('<H', data[offset:offset + 2])
            except struct.error as err:
                raise RefineryPartialResult(str(err), partial=out.getvalue())
            offset += 2
            size = (header & 0xFFF) + 1
            if size + 1 >= len(data):
                raise RefineryPartialResult(
                    F'chunk header indicates size {size}, but only {len(data)} bytes remain.',
                    partial=out.getvalue()
                )
            chunk = data[offset:offset + size]
            offset += size
            if header & 0x8000:
                chunk = self._decompress_chunk(chunk)
            out.write(chunk)
        return out.getvalue()

    def __init__(self, chunk_size: arg.number('-c', help='Optionally specify the chunk size for compression, default is 0x1000.') = 0x1000):
        super().__init__(chunk_size=chunk_size)
