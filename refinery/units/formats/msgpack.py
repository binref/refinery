#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools
import json
import msgpack as mp

from refinery.units import RefineryPartialResult, Unit
from refinery.lib.structures import MemoryFile


class msgpack(Unit):
    """
    Converts a message-pack (msgpack) buffer to JSON and vice-versa.
    """
    def reverse(self, data):
        return mp.dumps(json.loads(data))

    def process(self, data):
        unpacker: mp.fallback.Unpacker = mp.Unpacker(MemoryFile(data, read_as_bytes=True))
        for k in itertools.count():
            try:
                last = unpacker.tell()
                item = unpacker.unpack()
            except Exception as E:
                if isinstance(E, mp.OutOfData) and k == 1:
                    break
                raise RefineryPartialResult(str(E), memoryview(data)[last:]) from E
            else:
                yield json.dumps(item).encode(self.codec)
