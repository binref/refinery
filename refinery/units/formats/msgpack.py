from __future__ import annotations

import itertools

import msgpack as mp

from refinery.lib import json
from refinery.lib.structures import MemoryFile
from refinery.units import RefineryPartialResult, Unit


class msgpack(Unit):
    """
    Converts a message-pack (msgpack) buffer to JSON and vice-versa.
    """
    def reverse(self, data):
        try:
            data = json.loads(data)
        except Exception as E:
            try:
                data = json.loads(B'[%s]' % data)
            except Exception:
                raise E
        return mp.dumps(data)

    def process(self, data):
        unpacker: mp.fallback.Unpacker = mp.Unpacker(MemoryFile(data, output=bytes))
        for k in itertools.count():
            last = unpacker.tell()
            try:
                item = unpacker.unpack()
            except Exception as E:
                if isinstance(E, mp.OutOfData) and k == 1:
                    break
                raise RefineryPartialResult(str(E), memoryview(data)[last:]) from E
            else:
                yield json.dumps(item, pretty=False)
