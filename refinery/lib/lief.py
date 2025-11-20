"""
A wrapper around the LIEF library.
"""
from __future__ import annotations

import io

import lief as lib
import lief.COFF as COFF
import lief.ELF as ELF
import lief.MachO as MachO
import lief.PE as PE

if True:
    lib.disable_leak_warning()
    lib.logging.disable()

from refinery.lib.types import buf

AbstractBinary = lib.Binary
Relocation = lib.Relocation
Header = lib.Header
Symbol = lib.Symbol
Section = lib.Section

__all__ = [
    'ELF',
    'MachO',
    'PE',
    'COFF',
    'AbstractBinary',
    'Relocation',
    'Header',
    'Symbol',
    'Section',
    'load_pe',
    'load_pe_fast',
    'load_macho',
    'load',
    'string',
]

__pdoc__ = {_forward: False for _forward in __all__[:9]}


def load_pe(
    data: buf,
    parse_exports: bool = True,
    parse_imports: bool = True,
    parse_reloc: bool = True,
    parse_rsrc: bool = True,
    parse_signature: bool = True,
):
    """
    Load a PE file using LIEF. This is an ease-of-use function which forwards the keyworda rguments
    to a config object and then invokes the LIEF parser. Everything is parsed by default. For speed
    over completeness, see `refinery.lib.lief.load_pe_fast`.
    """
    with io.BytesIO(data) as stream:
        cfg = PE.ParserConfig()
        cfg.parse_exports = bool(parse_exports)
        cfg.parse_imports = bool(parse_imports)
        cfg.parse_reloc = bool(parse_reloc)
        cfg.parse_rsrc = bool(parse_rsrc)
        cfg.parse_signature = bool(parse_signature)
        if parsed := PE.parse(stream, cfg):
            return parsed
        raise ValueError


def load_pe_fast(
    data: buf,
    parse_exports: bool = False,
    parse_imports: bool = False,
    parse_reloc: bool = False,
    parse_rsrc: bool = False,
    parse_signature: bool = False,
):
    """
    This is equivalent to `refinery.lib.lief.load_pe` with the sole exception that the parser
    settings are optimized for speed rather than for parsing as many components as possible.
    """
    return load_pe(
        data,
        parse_exports=parse_exports,
        parse_imports=parse_imports,
        parse_reloc=parse_reloc,
        parse_rsrc=parse_rsrc,
        parse_signature=parse_signature,
    )


def load_macho(data: buf) -> MachO.FatBinary | MachO.Binary:
    """
    Load a MachO file using LIEF.
    """
    with io.BytesIO(data) as stream:
        config = MachO.ParserConfig()
        config.parse_dyld_bindings = True
        config.parse_dyld_rebases = True
        config.parse_dyld_exports = True
        if parsed := MachO.parse(stream, config):
            return parsed
        raise ValueError


def load_elf(data: buf) -> ELF.Binary:
    """
    Load an ELF file using LIEF.
    """
    with io.BytesIO(data) as stream:
        config = ELF.ParserConfig()
        config.parse_dyn_symbols = True
        config.parse_relocations = True
        config.parse_symtab_symbols = True
        if parsed := ELF.parse(stream):
            return parsed
        raise ValueError


def load(data: buf):
    """
    Load a PE, ELF, or MachO executable using LIEF. The function first attempts to parse the file
    based on its first 4 bytes using a specific LIEF parser and reverts to LIEF's general purpose
    loader if these fail.
    """
    if data[:2] == B'MZ':
        return load_pe(data)
    if data[:4] == B'\x7FELF':
        return load_elf(data)
    if set(data[:4]) <= {0xFE, 0xED, 0xFA, 0xCE, 0xCF}:
        return load_macho(data)
    raise ValueError


def string(value: str | buf) -> str:
    """
    A function to convert LIEF values to a string, regardless of whether it is exposed as bytes
    or string by the foreign interface.
    """
    if not isinstance(value, str):
        if isinstance(value, memoryview):
            value = bytes(value)
        value, _, _ = value.partition(B'\0')
        value = value.decode('utf8')
    return value
