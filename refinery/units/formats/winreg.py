from __future__ import annotations

import contextlib
import dataclasses
import inspect
import re

from typing import TYPE_CHECKING

from refinery.lib.id import get_reg_export_type
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Iterable
from refinery.units.encoding.esc import esc
from refinery.units.formats import PathExtractorUnit, PathPattern, UnpackResult

if TYPE_CHECKING:
    from Registry.Registry import RegistryKey, RegistryValue


class ParseException(Exception):
    pass


@dataclasses.dataclass
class _ExportedValue:
    name: str
    data: str


@dataclasses.dataclass
class _ExportedKey:
    name: str
    values: dict[str, _ExportedValue] = dataclasses.field(default_factory=dict)


def _statements(lines: Iterable[str]) -> Iterable[str]:
    """
    Joins every line of a registry export that ends in a backslash with the line after it and
    generates the joined lines without surrounding white space; comment lines are left out.
    """
    pending = ''
    for line in lines:
        line = line.strip()
        if not pending and line.startswith(';'):
            continue
        if line.endswith('\\'):
            pending = F'{pending}{line[:-1]}'
            continue
        yield F'{pending}{line}'
        pending = ''
    if pending:
        yield pending


def _quoted_name(line: str) -> tuple[str, str] | None:
    """
    Reads the quoted value name at the start of the given line of a registry export, where a
    backslash escapes a backslash or a quote. Returns the name and the rest of the line after
    its closing quote, or `None` if the quote is not closed.
    """
    name = []
    k = 1
    while k < len(line):
        character = line[k]
        if character == '\\' and line[k + 1:k + 2] in ('\\', '"'):
            name.append(line[k + 1])
            k += 2
            continue
        if character == '"':
            return ''.join(name), line[k + 1:]
        name.append(character)
        k += 1
    return None


def _read_registry_export(lines: Iterable[str]) -> list[_ExportedKey]:
    """
    Reads the lines of a registry export that follow its header and returns the keys and values
    that importing it leaves behind: Keys and value names are matched ignoring case, the last
    assignment to a value wins, a value assigned a minus sign is deleted, and a key whose name
    starts with a minus sign is deleted together with all of its subkeys. Keys and values keep
    the spelling and the order of their first appearance; the default value has an empty name.
    """
    keys: dict[str, _ExportedKey] = {}
    key: _ExportedKey | None = None
    for line in _statements(lines):
        if line.startswith('['):
            name, bracket, _ = line[1:].rpartition(']')
            if not bracket:
                key = None
                continue
            if name.startswith('-'):
                deleted = name[1:].upper()
                prefix = F'{deleted}\\'
                for upper in [k for k in keys if k == deleted or k.startswith(prefix)]:
                    del keys[upper]
                key = None
                continue
            if (key := keys.get(upper := name.upper())) is None:
                key = keys[upper] = _ExportedKey(name)
            continue
        if key is None:
            continue
        if line.startswith('@'):
            name, rest = '', line[1:]
        elif line.startswith('"') and (quoted := _quoted_name(line)):
            name, rest = quoted
        else:
            continue
        assignment, equals, data = rest.lstrip().partition('=')
        if assignment or not equals:
            continue
        data = data.strip()
        upper = name.upper()
        if data == '-':
            key.values.pop(upper, None)
        elif (value := key.values.get(upper)) is None:
            key.values[upper] = _ExportedValue(name, data)
        else:
            value.data = data
    return list(keys.values())


class _Missing:
    """
    Names a registry value type whose exported data cannot be decoded.
    """
    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return self.name


class winreg(PathExtractorUnit):
    """
    Extract values from a Windows registry hive or from a registry export (.reg file).
    """
    @PathExtractorUnit.Requires('python-registry', 2)
    def _registry():
        import Registry
        import Registry.Registry
        import Registry.RegistryParse
        return Registry

    @staticmethod
    def _walk(patterns: list[PathPattern], key: RegistryKey, *path: str):
        here = '/'.join(path)
        if not any(p.reach(here) for p in patterns):
            winreg.log_debug(F'pruning search at {here}')
            return
        for value in key.values():
            def raw(v: RegistryValue = value):
                return v.raw_data()
            vpath = here
            vname = value.name()
            if vname != '(default)':
                vpath = F'{vpath}/{vname}'
            yield UnpackResult(vpath, raw)
        for subkey in key.subkeys():
            yield from winreg._walk(patterns, subkey, *path, subkey.name())

    def _unpack_hive(self, data: bytearray):
        try:
            with MemoryFile(data) as stream:
                root = self._registry.Registry.Registry(stream).root()
                yield from self._walk(self._patterns, root, root.name())
        except self._registry.RegistryParse.ParseException:
            raise ParseException

    def _decode_registry_export(self, data: str):
        def REG_BINARY(data: str) -> bytes:
            return bytes.fromhex(re.sub('[^a-fA-F0-9]+', '', data))

        def REG_SZ(data: str) -> bytes:
            return data.encode(self.codec) | esc(quoted=True) | bytes

        def REG_EXPAND_SZ(data: str):
            return REG_BINARY(data).decode('UTF-16LE').rstrip('\0').encode(self.codec)

        def REG_MULTI_SZ(data: str):
            for string in REG_BINARY(data).decode('UTF-16LE').split('\0'):
                if string:
                    yield string.encode(self.codec)

        def REG_DWORD(data: str):
            value = int(data, 16)
            return F'0x{value:X}'.encode(self.codec)

        def REG_QWORD(data: str):
            value = int.from_bytes(REG_BINARY(data), 'little')
            return F'0x{value:X}'.encode(self.codec)

        REG_NONE = REG_EXPAND_SZ
        REG_DWORD_BIG_ENDIAN = _Missing('REG_DWORD_BIG_ENDIAN')
        REG_LINK = _Missing('REG_LINK')
        REG_RESOURCE_LIST = _Missing('REG_RESOURCE_LIST')
        REG_FULL_RESOURCE_DESCRIPTOR = _Missing('REG_FULL_RESOURCE_DESCRIPTOR')
        REG_RESOURCE_REQUIREMENTS_LIST = _Missing('REG_RESOURCE_REQUIREMENTS_LIST')

        prefix, _, encoded = data.partition(':')

        try:
            decoder = {
                'hex(0)' : REG_NONE,
                'hex(1)' : REG_SZ,
                'hex(2)' : REG_EXPAND_SZ,
                'hex(3)' : REG_BINARY,
                'hex'    : REG_BINARY,
                'hex(4)' : REG_DWORD,
                'dword'  : REG_DWORD,
                'hex(5)' : REG_DWORD_BIG_ENDIAN,
                'hex(6)' : REG_LINK,
                'hex(7)' : REG_MULTI_SZ,
                'hex(8)' : REG_RESOURCE_LIST,
                'hex(9)' : REG_FULL_RESOURCE_DESCRIPTOR,
                'hex(a)' : REG_RESOURCE_REQUIREMENTS_LIST,
                'hex(b)' : REG_QWORD,
            }[prefix]
        except KeyError:
            decoder = REG_SZ
            encoded = data

        if isinstance(decoder, _Missing):
            self.log_warn(F'Found registry type {decoder!s}; no decoder implemented.')
            return
        self.log_debug(F'decoding as {decoder.__name__}: {encoded}')
        it = decoder(encoded)
        if not inspect.isgenerator(it):
            it = (it,)
        yield from it

    def _unpack_file(self, data: bytearray):
        for codec in ('utf16', 'utf-16le', 'utf8'):
            try:
                lines = data.decode(codec).split('\n')
            except UnicodeError:
                continue
            if lines and lines[0].startswith('Windows Registry Editor'):
                break
        else:
            raise ParseException

        for key in _read_registry_export(lines[1:]):
            self.log_debug(key.name)
            root = key.name.replace('\\', '/')
            for value in key.values.values():
                path = F'{root}/{value.name}' if value.name else root
                decoded = list(self._decode_registry_export(value.data))
                if len(decoded) == 1:
                    yield UnpackResult(path, decoded[0])
                    continue
                for k, d in enumerate(decoded):
                    yield UnpackResult(F'{path}.{k}', d)

    def unpack(self, data):
        with contextlib.suppress(ParseException):
            yield from self._unpack_hive(data)
            return
        yield from self._unpack_file(data)

    @classmethod
    def handles(cls, data):
        return get_reg_export_type(data) is not None
