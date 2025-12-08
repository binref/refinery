from __future__ import annotations

import contextlib
import inspect
import io
import re
import shlex

from configparser import ConfigParser
from pathlib import Path
from typing import TYPE_CHECKING

from refinery.lib.id import get_reg_export_type
from refinery.lib.structures import MemoryFile
from refinery.units.encoding.esc import esc
from refinery.units.formats import PathExtractorUnit, PathPattern, UnpackResult

if TYPE_CHECKING:
    from Registry.Registry import RegistryKey, RegistryValue


class ParseException(Exception):
    pass


class WinRegFileParser(ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


class winreg(PathExtractorUnit):
    """
    Extract values from a Windows registry hive or from a registry export (.reg file).
    """
    @PathExtractorUnit.Requires('python-registry', ['formats'])
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
            return bytes.fromhex(re.sub('[^a-f0-9]+', '', data))

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

        class Missing:
            def __init__(self, name: str):
                self.name = name

            def __str__(self):
                return self.name

        REG_NONE = REG_EXPAND_SZ
        REG_DWORD_BIG_ENDIAN = Missing('REG_DWORD_BIG_ENDIAN')
        REG_LINK = Missing('REG_LINK')
        REG_RESOURCE_LIST = Missing('REG_RESOURCE_LIST')
        REG_FULL_RESOURCE_DESCRIPTOR = Missing('REG_FULL_RESOURCE_DESCRIPTOR')
        REG_RESOURCE_REQUIREMENTS_LIST = Missing('REG_RESOURCE_REQUIREMENTS_LIST')

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

        if isinstance(decoder, Missing):
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
                reg = data.decode(codec).splitlines(keepends=True)
            except UnicodeError:
                continue
            lines = iter(reg)
            if next(lines).startswith('Windows Registry Editor'):
                break
        else:
            raise ParseException

        def _parse():
            parser = WinRegFileParser()
            section.seek(0)
            parser.read_file(section)
            for key in parser.sections():
                self.log_debug(key)
                for value in parser[key]:
                    name = next(iter(shlex.split(value)))
                    path = Path(key)
                    if name != '@':
                        path = path / Path(name)
                    decoded = list(self._decode_registry_export(parser[key][value]))
                    if len(decoded) == 1:
                        yield UnpackResult(str(path), decoded[0])
                        continue
                    for k, d in enumerate(decoded):
                        yield UnpackResult(F'{path!s}.{k}', d)

        section = io.StringIO()

        for line in lines:
            if line.lstrip().startswith('['):
                yield from _parse()
                section.seek(0)
                section.truncate(0)
            section.write(line)

        yield from _parse()

    def unpack(self, data):
        with contextlib.suppress(ParseException):
            yield from self._unpack_hive(data)
            return
        yield from self._unpack_file(data)

    @classmethod
    def handles(cls, data):
        return get_reg_export_type(data) is not None
