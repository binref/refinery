#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
In order to represent arbitrary data as JSON, these classes help extend the built-in
json module in order to support custom encoding of already serializable types.
"""
from typing import List, Tuple, Union

import uuid
import json
import re


class JSONEncoderExMeta(type):
    """
    This metaclass is the type of `refinery.lib.json.JSONEncoderEx` and exists in
    order to facilitate a context manager at the type level.
    """

    def __enter__(cls):
        def _custom_isinstance(obj, tp):
            if cls.handled(obj):
                return False
            return isinstance(obj, tp)

        def mkiter(*args, **kwargs):
            kwargs.update(isinstance=_custom_isinstance)
            return cls._make_iterencode_old(*args, **kwargs)

        cls._make_iterencode_old = json.encoder._make_iterencode
        json.encoder._make_iterencode = mkiter
        return cls

    def __exit__(cls, etype, eval, tb):
        json.encoder._make_iterencode = cls._make_iterencode_old
        return False

    def dumps(cls, data, indent=4, **kwargs):
        kwargs.setdefault('cls', cls)
        return json.dumps(data, indent=indent, **kwargs)


class JSONEncoderEx(json.JSONEncoder, metaclass=JSONEncoderExMeta):
    """
    Base class for JSON encoders used in refinery. Any such encoder can
    be used as a context which temporarily performs a monkey-patch of the
    built-in json module to allow custom encoding of already serializable
    types such as `list` or `dict`. This is done as follows:

        class MyEncoder(JSONEncoderEx):
            pass

        with MyEncoder as encoder:
            return encoder.dumps(data)
    """
    def encode(self, obj):
        if isinstance(obj, dict) and not all(isinstance(k, str) for k in obj.keys()):
            def _encode(k):
                if isinstance(k, (bytes, bytearray, memoryview)):
                    try: return k.encode('ascii')
                    except Exception: pass
                return str(k)
            obj = {_encode(key): value for key, value in obj.items()}
        data = super().encode(obj)
        if self.substitute:
            uids = R'''(['"])({})\1'''.format('|'.join(re.escape(u) for u in self.substitute))
            return re.sub(uids, lambda m: self.substitute[m[2]], data)
        return data

    def encode_raw(self, representation):
        uid = str(uuid.uuid4())
        self.substitute[uid] = representation
        return uid

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.substitute = {}

    @classmethod
    def handled(cls, obj) -> bool:
        """
        Returns whether the given object can be handled by the decoder. When a `refinery.lib.json.JSONEncoderEx` is used as
        a context manager, then it is possible to return `True` for basic types such as `list` to provide custom encodings of
        these types.
        """
        return False


class BytesAsArrayEncoder(JSONEncoderEx):
    """
    This JSON Encoder encodes byte strings as arrays of integers.
    """

    @classmethod
    def _is_byte_array(cls, obj) -> bool:
        return isinstance(obj, (bytes, bytearray, memoryview))

    @classmethod
    def handled(cls, obj) -> bool:
        return cls._is_byte_array(obj) or super().handled(obj)

    def encode_bytes(self, obj):
        return self.encode_raw('[{}]'.format(','.join(F'{b & 0xFF:d}' for b in obj)))

    def default(self, obj):
        if self._is_byte_array(obj):
            return self.encode_bytes(obj)
        return super().default(obj)


def flattened(data: dict, prefix='', separator='.') -> List[Tuple[str, Union[int, float, str]]]:
    def flatten(cursor, prefix):
        if isinstance(cursor, dict):
            for key, value in cursor.items():
                new_prefix = key if not prefix else F'{prefix}{separator}{key}'
                yield from flatten(value, new_prefix)
        elif isinstance(cursor, list):
            width = len(F'{len(cursor)-1:X}')
            for key, value in enumerate(cursor):
                yield from flatten(value, F'{prefix}[0x{key:0{width}X}]')
        else:
            yield (prefix, cursor)
    yield from flatten(data, prefix)
