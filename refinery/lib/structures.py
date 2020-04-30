#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces and classes to read structured data.
"""
import struct
import functools
import io

from typing import Union, Tuple


class EOF(ValueError):
    def __init__(self):
        super().__init__('Unexpected end of buffer.')


class StructReader(io.BytesIO):

    def read_struct(self, format) -> Union[Tuple, int, bytes]:
        data = struct.unpack(format, self.read_exactly(struct.calcsize(format)))
        if len(data) == 1:
            return data[0]
        return data

    def read_word(self) -> int:
        return self.read_struct('<H')

    def read_dword(self) -> int:
        return self.read_struct('<I')

    def read_qword(self) -> int:
        return self.read_struct('<Q')

    def read_bigint(self, length, byteorder='little') -> int:
        return int.from_bytes(self.read_exactly(length), byteorder)

    def read_exactly(self, size) -> bytes:
        result = super().read(size)
        if len(result) != size:
            raise EOF
        return result


class StructMeta(type):
    def __init__(cls, name, bases, nmspc):
        super(StructMeta, cls).__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self, data):
            if not isinstance(data, StructReader):
                data = StructReader(data)
            return original__init__(self, data)

        cls.__init__ = wrapped__init__


class Struct(metaclass=StructMeta):
    def __init__(self, data):
        pass
