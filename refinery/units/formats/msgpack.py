from __future__ import annotations

import itertools
import json

import msgpack as mp

from refinery.lib.structures import MemoryFile
from refinery.units import RefineryPartialResult, Unit


class msgpack(Unit):
    """
    Converts a message-pack (msgpack) buffer to JSON and vice-versa.
    """
    def reverse(self, data):
        return mp.dumps(json.loads(data))

    def process(self, data):
        unpacker: mp.fallback.Unpacker = mp.Unpacker(MemoryFile(data, output=bytes))
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
