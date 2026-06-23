#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements parsing of CBOR (Concise Binary Object Representation) data as specified in RFC 8949.
"""
from __future__ import annotations

from refinery.lib.cbor import CBORReader
from refinery.units.formats import JSONEncoderUnit


class cbor(JSONEncoderUnit):
    """
    Parse CBOR data and convert it to JSON.

    CBOR (Concise Binary Object Representation) is a binary data serialization format defined in
    RFC 8949. It supports integers, byte strings, text strings, arrays, maps, tags, and simple
    values including booleans, null, and floating-point numbers.
    """
    def process(self, data):
        reader = CBORReader(memoryview(data), bigendian=True)
        message = reader.read_item()
        return self.to_json(message)
