#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import msgpack as mp

from ...units import Unit
from ...lib.structures import MemoryFile


class msgpack(Unit):
    """
    Converts a message-pack (msgpack) buffer to JSON and vice-versa.
    """
    def reverse(self, data):
        return mp.dumps(json.loads(data))

    def process(self, data):
        unpacker = iter(mp.Unpacker(MemoryFile(data, read_as_bytes=True)))
        items = []
        while True:
            try:
                items.append(next(unpacker))
            except StopIteration:
                break
            except Exception:
                self.log_warn("oops")
                break
        if len(items) == 0:
            return B'{}'
        if len(items) == 1:
            items = items[0]
        return json.dumps(items).encode(self.codec)
