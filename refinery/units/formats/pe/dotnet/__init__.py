#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json

from typing import Any
from enum import Enum
from hashlib import md5, sha1, sha256, sha512
from zlib import crc32
from functools import lru_cache

from refinery.units import Arg, Unit
from refinery.units.encoding.hex import hex
from refinery.units.encoding.esc import esc
from refinery.units.encoding.url import url
from refinery.units.encoding.b64 import b64

from refinery.lib.json import BytesAsStringEncoder
from refinery.lib.dotnet.types import Blob
from refinery.lib.dotnet.header import DotNetHeader


class UNIT(Enum):
    HEX = hex
    ESC = esc
    URL = url
    B64 = b64


class HASH(Enum):
    MD5 = md5
    CRC32 = crc32
    SHA1 = sha1
    SHA256 = sha256
    SHA512 = sha512


class DotNetEncoder(BytesAsStringEncoder):
    def default(self, obj):
        if isinstance(obj, Blob):
            obj = bytes(obj)
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


class JSONEncoderUnit(Unit, abstract=True):
    """
    An abstract unit that provides the interface for displaying parsed data
    as JSON. By default, binary data is converted into integer arrays.
    """

    def __init__(
        self,
        encode: Arg.Option('-e', group='BIN', choices=UNIT, help=(
            'Select an encoder unit used to represent binary data in the JSON output. Available are: {choices}.')) = None,
        digest: Arg.Option('-d', group='BIN', choices=HASH, help=(
            'Select a hashing algorithm to digest binary data; instead of the data, only the hash will be displayed. The '
            'available algorithms are: {choices}.')) = None,
        **keywords
    ):
        encode = Arg.AsOption(encode, UNIT)
        digest = Arg.AsOption(digest, HASH)

        super().__init__(**keywords)

        if encode is not None and digest is not None:
            raise ValueError('Only one binary data conversion can be specified.')
        elif encode is not None:
            unit = encode.value()
            class CustomEncoder(DotNetEncoder): # noqa
                def encode_bytes(self, obj): return unit.reverse(obj).decode('utf8')
        elif digest is not None:
            class CustomEncoder(DotNetEncoder):
                def encode_bytes(self, obj): return digest(obj).hexdigest()
        else:
            CustomEncoder = DotNetEncoder

        self.encoder = CustomEncoder

    def to_json(self, obj: Any) -> bytes:
        return json.dumps(obj, cls=self.encoder, indent=4).encode(self.codec)


class CodePath:
    """
    This class can be used to recover the method to which a certain virtual address
    belongs, including its parent type and namespace.
    """
    def __init__(self, header: DotNetHeader):
        self.header = header
        self.tables = tables = header.meta.Streams.Tables
        memo = [tr.MethodList.Index - 1 for tr in tables.TypeDef]
        memo.append(len(tables.MethodDef))
        self.ranges = [range(*memo[k:k + 2]) for k in range(len(memo) - 1)]

    def method_path(self, offset: int):
        ns, tn, spec = self.method(offset)
        if tn and ns:
            ns = ns.replace('.', '/')
            spec = F'{ns}/{tn}/{spec}'
        return spec

    def method_spec(self, offset: int):
        ns, tn, spec = self.method(offset)
        if tn and ns:
            spec = F'{ns}::{tn}.{spec}'
        return spec

    @lru_cache(maxsize=None)
    def method(self, offset: int):
        def printable(name: str):
            return name.replace('.', '').isidentifier()
        ranges = self.ranges
        tables = self.tables
        header = self.header
        rva = header.pe.get_rva_from_offset(offset)
        method = min(tables.MethodDef, key=lambda m: (m.RVA > rva, rva - m.RVA))
        index = tables.MethodDef.index(method)
        method_name = method.Name
        if not printable(method_name):
            method_name = F'method_{method.RVA:08X}'
        for k, (methods, tr) in enumerate(zip(ranges, tables.TypeDef), 1):
            if index in methods:
                namespace = tr.TypeNamespace
                type_name = tr.TypeName
                if not printable(type_name):
                    type_name = F'type{k}'
                if not printable(namespace):
                    namespace = F'ns{k}'
                return namespace, type_name, method_name
        return None, None, method_name
