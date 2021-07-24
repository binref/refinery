#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import msgpack as mp

from ...units import RefineryPartialResult, Unit
from ...lib.structures import MemoryFile


class msgpack(Unit):
    """
    Converts a message-pack (msgpack) buffer to JSON and vice-versa.
    """
    def reverse(self, data):
        return mp.dumps(json.loads(data))

    def process(self, data):
        unpacker = mp.Unpacker(MemoryFile(data, read_as_bytes=True))
        while True:
            try:
                item = unpacker.unpack()
            except mp.exceptions.OutOfData:
                position = unpacker.tell()
                if position < len(data):
                    self.log_warn("oops")
                break
            except Exception as E:
                position = unpacker.tell()
                if not position:
                    raise
                view = memoryview(data)
                raise RefineryPartialResult(str(E), view[position:])
            else:
                yield json.dumps(item).encode(self.codec)
