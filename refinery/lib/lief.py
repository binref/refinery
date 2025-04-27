#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A wrapper around the LIEF library.
"""
from __future__ import annotations

import lief as lib

if True:
    lib.logging.disable()

from lief import (
    MachO,
    PE,
    ELF,
    Binary,
    Header,
    Symbol,
    Section,
)

from refinery.lib.structures import MemoryFileRO
from refinery.lib.types import ByteStr

__all__ = [
    'load',
    'load_pe',
    'lib',
    'MachO',
    'PE',
    'ELF',
    'Binary',
    'Header',
    'Symbol',
    'Section',
]


def load_pe(
    data: ByteStr,
    parse_exports: bool = True,
    parse_imports: bool = True,
    parse_reloc: bool = True,
    parse_rsrc: bool = True,
    parse_signature: bool = True,
):
    with MemoryFileRO(data) as stream:
        cfg = PE.ParserConfig()
        cfg.parse_exports = bool(parse_exports)
        cfg.parse_imports = bool(parse_imports)
        cfg.parse_reloc = bool(parse_reloc)
        cfg.parse_rsrc = bool(parse_rsrc)
        cfg.parse_signature = bool(parse_signature)
        if parsed := PE.parse(stream, cfg):
            return parsed
        stream.seek(0)
        return lib.parse(stream)


def load_pe_fast(
    data: ByteStr,
    parse_exports: bool = False,
    parse_imports: bool = False,
    parse_reloc: bool = False,
    parse_rsrc: bool = False,
    parse_signature: bool = False,
):
    return load_pe(
        data,
        parse_exports=parse_exports,
        parse_imports=parse_imports,
        parse_reloc=parse_reloc,
        parse_rsrc=parse_rsrc,
        parse_signature=parse_signature,
    )


def load_macho(data: ByteStr) -> MachO.FatBinary | MachO.Binary:
    with MemoryFileRO(data) as stream:
        if parsed := MachO.parse(stream):
            return parsed
        stream.seek(0)
        return lib.parse(stream)


def load(data: ByteStr):
    with MemoryFileRO(data) as stream:
        if data[:2] == B'MZ':
            parsed = PE.parse(stream)
        elif data[:4] == B'\x7FELF':
            parsed = ELF.parse(stream)
        elif set(data[:4]) <= {0xFE, 0xED, 0xFA, 0xCE, 0xCF}:
            parsed = MachO.parse(stream)
        else:
            raise ValueError
        if parsed:
            return parsed
        stream.seek(0)
        return lib.parse(stream)


def string(value: str | bytes, dll: bool = False) -> str:
    if not isinstance(value, str):
        value, _, _ = value.partition(B'\0')
        value = value.decode('utf8')
    if dll and value.lower().endswith('.dll'):
        value = value[~3:]
    return value
