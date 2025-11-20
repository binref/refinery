from __future__ import annotations

import codecs
import enum
import re

from refinery.lib.structures import StructReader
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.formats import JSONEncoderUnit


class WireType(enum.IntEnum):
    VARINT = 0
    I64 = 1
    I32 = 5
    LEN = 2
    SGROUP = 3
    EGROUP = 4


class ProtoBufReader(StructReader[memoryview]):

    try_repeated = False

    def varint(self):
        return self.read_7bit_encoded_int(64)

    def _same_type(self, a, b) -> bool:
        if type(a) is not type(b):
            return False
        if isinstance(a, dict):
            if set(a) != set(b):
                return False
            for key in a:
                if not self._same_type(a[key], b[key]):
                    return False
        return True

    def _decode_as_bytes(self, msg):
        if msg is None:
            return True
        if isinstance(msg, (bytes, bytearray, memoryview, float)):
            return True
        if isinstance(msg, list):
            return len(msg) <= 1
        if isinstance(msg, dict):
            if len(msg) > 1:
                return False
            if not msg:
                return True
            return self._decode_as_bytes(next(iter(msg.values())))
        else:
            return False

    def _as_map(self, value: list[dict]):
        if not isinstance(value, list):
            return value

        switch = False
        as_map = {}
        key_nr = None
        val_nr = None
        key_01 = None
        val_01 = None

        for entry in value:
            if not isinstance(entry, dict):
                return value
            if not len(entry) == 2:
                return value
            if not as_map:
                key_nr, val_nr = entry.keys()
            try:
                key = entry[key_nr]
                val = entry[val_nr]
            except KeyError:
                return value
            if not as_map:
                key_01 = key
                val_01 = val
            elif not self._same_type(key, key_01):
                return value
            elif not self._same_type(val, val_01):
                return value
            if key not in as_map:
                as_map[key] = val
                continue
            elif switch:
                break
            else:
                switch = True
                key_nr, val_nr = val_nr, key_nr
                key_01, val_01 = val_01, key_01
                key, val = val, key
                temp_map = {}
                for k, v in as_map.items():
                    if v in temp_map:
                        return value
                    temp_map[v] = k
                if key in temp_map:
                    return value
                temp_map[key] = val
                as_map = temp_map
        else:
            return as_map

    def read_key_value_pair(self):
        nr, wt = divmod(self.varint(), 8)
        return nr, WireType(wt)

    def read_message(self, gid: int | None = None):
        def insert(key, val):
            if key in msg:
                box = msg[key]
                if isinstance(box, list):
                    box.append(val)
                else:
                    msg[key] = [box, val]
            else:
                msg[key] = val

        msg = {}

        while not self.eof:
            nr, wt = self.read_key_value_pair()
            if nr not in range(1, 536_870_911):
                raise ValueError
            if wt == WireType.EGROUP:
                if nr == gid:
                    break
                raise ValueError
            if wt == WireType.SGROUP:
                insert(nr, self.read_message(nr))
            elif wt == WireType.VARINT:
                insert(nr, self.varint())
            elif wt == WireType.I64:
                insert(nr, self.f64())
            elif wt == WireType.I32:
                insert(nr, self.f32())
            elif wt == WireType.LEN:
                size = self.varint()
                blob = self.read_exactly(size)
                data = blob
                wire = ProtoBufReader(blob)
                try:
                    if re.fullmatch(R'[\s!-~]+', data := codecs.decode(blob, 'utf8')):
                        insert(nr, data)
                        continue
                except UnicodeDecodeError:
                    pass
                try:
                    data = wire.read_message()
                except Exception:
                    if self.try_repeated and any(b & 0x80 for b in blob):
                        wire.seekset(0)
                        data = []
                        try:
                            while not wire.eof:
                                data.append(wire.varint())
                        except (EOFError, OverflowError):
                            data = blob
                if self._decode_as_bytes(data):
                    data = blob
                insert(nr, data)
            else:
                raise TypeError

        for nr, value in msg.items():
            msg[nr] = self._as_map(value)

        return msg


class pbuf(JSONEncoderUnit):
    """
    Converts a ProtoBuf message to JSON. Deserialization is ambiguous without the definition file,
    so the output is partly based on heuristics. Some fields like fixed integers are never
    recovered, fixed 32-bit and 64-bit data types are always recovered as floating point numbers.
    For variable length data,the unit first attempts to decode the data as a printable UTF-8
    string. If this fails, it will attempt to deserialize it as ProtoBuf. If this also fails and
    the corresponding option is set, it will try to reconstruct a sequence of repeated variable
    length integers. The final fallback is to return the body as a byte string.
    """
    def __init__(
        self,
        try_repeated: Param[bool, Arg.Switch('-r',
            help='Try to detect and decode repeated integer fields.')] = False,
        encode=None,
        digest=None,
        arrays=False,
    ):
        super().__init__(
            encode=encode,
            digest=digest,
            arrays=arrays,
            try_repeated=try_repeated
        )

    def process(self, data):
        reader = ProtoBufReader(memoryview(data))
        reader.try_repeated = self.args.try_repeated
        message = reader.read_message()
        return self.to_json(message)
