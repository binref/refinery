#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements parsing of CBOR (Concise Binary Object Representation) data as specified in RFC 8949.
"""
from __future__ import annotations

import math
import struct

from refinery.lib.structures import StructReader
from refinery.units.formats import JSONEncoderUnit


class CBORReader(StructReader[memoryview]):
    """
    A reader for CBOR-encoded data. CBOR encodes each data item as an initial byte whose high
    3 bits indicate the major type and whose low 5 bits provide additional information (the
    argument), optionally followed by content bytes. This reader decodes all major types:

    - `0`: unsigned integer
    - `1`: negative integer
    - `2`: byte string
    - `3`: text string (UTF-8)
    - `4`: array
    - `5`: map
    - `6`: semantic tag
    - `7`: simple values and floating-point numbers
    """

    BREAK = object()

    def read_argument(self, additional: int) -> int:
        """
        Decode the argument value from the 5-bit additional information field.
        """
        if additional <= 23:
            return additional
        if additional == 24:
            return self.u8()
        if additional == 25:
            return self.u16()
        if additional == 26:
            return self.u32()
        if additional == 27:
            return self.u64()
        raise ValueError(F'Invalid additional information value: {additional}')

    @staticmethod
    def _json_float(value: float):
        if math.isnan(value):
            return 'NaN'
        if math.isinf(value):
            return '-Infinity' if value < 0 else 'Infinity'
        return value

    def read_float16(self) -> float | str:
        """
        Decode an IEEE 754 half-precision (16-bit) floating-point value.
        """
        data = self.read_exactly(2)
        value, = struct.unpack('>e', data)
        return self._json_float(value)

    def read_item(self):
        """
        Read and decode a single CBOR data item. Returns the decoded Python object.
        """
        ib = self.u8()
        major = ib >> 5
        additional = ib & 0x1F

        if major == 0:
            return self.read_argument(additional)

        if major == 1:
            return -1 - self.read_argument(additional)

        if major == 2:
            if additional == 31:
                chunks = []
                while True:
                    item = self.read_item()
                    if item is self.BREAK:
                        break
                    if not isinstance(item, (bytes, bytearray, memoryview)):
                        raise ValueError('Indefinite-length byte string contains non-byte-string chunk.')
                    chunks.append(item)
                return b''.join(bytes(c) for c in chunks)
            length = self.read_argument(additional)
            return bytes(self.read_exactly(length))

        if major == 3:
            if additional == 31:
                chunks = []
                while True:
                    item = self.read_item()
                    if item is self.BREAK:
                        break
                    if not isinstance(item, str):
                        raise ValueError('Indefinite-length text string contains non-text-string chunk.')
                    chunks.append(item)
                return ''.join(chunks)
            length = self.read_argument(additional)
            return bytes(self.read_exactly(length)).decode('utf-8')

        if major == 4:
            if additional == 31:
                items = []
                while True:
                    item = self.read_item()
                    if item is self.BREAK:
                        break
                    items.append(item)
                return items
            count = self.read_argument(additional)
            return [self.read_item() for _ in range(count)]

        if major == 5:
            if additional == 31:
                pairs = {}
                while True:
                    key = self.read_item()
                    if key is self.BREAK:
                        break
                    value = self.read_item()
                    pairs[key] = value
                return pairs
            count = self.read_argument(additional)
            pairs = {}
            for _ in range(count):
                key = self.read_item()
                value = self.read_item()
                pairs[key] = value
            return pairs

        if major == 6:
            tag_number = self.read_argument(additional)
            content = self.read_item()
            return self._decode_tagged(tag_number, content)

        if major == 7:
            if additional == 31:
                return self.BREAK
            if additional <= 23:
                return self._decode_simple(additional)
            if additional == 24:
                return self._decode_simple(self.u8())
            if additional == 25:
                return self.read_float16()
            if additional == 26:
                return self._json_float(self.f32())
            if additional == 27:
                return self._json_float(self.f64())
            raise ValueError(F'Invalid additional information for major type 7: {additional}')

        raise ValueError(F'Unknown major type: {major}')

    @staticmethod
    def _decode_simple(value: int):
        if value == 20:
            return False
        if value == 21:
            return True
        if value == 22:
            return None
        if value == 23:
            return None
        return F'simple({value})'

    @staticmethod
    def _decode_tagged(tag: int, content):
        """
        Attempt to interpret well-known tags. For tag 2 and 3 (bignums), the content is decoded
        into an integer. Other tags are returned as a descriptive dictionary.
        """
        if tag == 2 and isinstance(content, (bytes, bytearray, memoryview)):
            return int.from_bytes(content, 'big')
        if tag == 3 and isinstance(content, (bytes, bytearray, memoryview)):
            return -1 - int.from_bytes(content, 'big')
        return {'tag': tag, 'value': content}


class cbor(JSONEncoderUnit):
    """
    Parses CBOR (Concise Binary Object Representation) data and converts it to JSON. CBOR is a
    binary data serialization format defined in RFC 8949. It supports integers, byte strings,
    text strings, arrays, maps, tags, and simple values including booleans, null, and
    floating-point numbers.
    """
    def process(self, data):
        reader = CBORReader(memoryview(data), bigendian=True)
        message = reader.read_item()
        return self.to_json(message)
