from __future__ import annotations

import codecs
import contextlib
import dataclasses
import enum
import marshal
import os
import os.path
import re
import uuid
import zlib

from typing import TYPE_CHECKING, Callable, cast

from Cryptodome.Cipher import AES

from refinery.lib.py import decompile_buffer, version2tuple
from refinery.lib.shared import xdis
from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.lib.types import Param, buf
from refinery.units.formats.archive import ArchiveUnit, Arg
from refinery.units.formats.pym import Marshal
from refinery.units.pattern.carve import carve


class Unmarshal(enum.IntEnum):
    No = 0
    Yes = 1
    YesAndDecompile = 2


def decompress_peek(buffer, size=512) -> bytes | None:
    try:
        return zlib.decompressobj().decompress(buffer[:size])
    except zlib.error:
        return None


class PiType(bytes, enum.Enum):
    BINARY          = B'b'  # noqa / binary
    DEPENDENCY      = B'd'  # noqa / runtime option
    PYZ             = B'z'  # noqa / zlib (pyz) - frozen Python code
    PACKAGE         = B'M'  # noqa / Python package (__init__.py)
    MODULE          = B'm'  # noqa / Python module
    SOURCE          = B's'  # noqa / Python script (v3)
    DATA            = B'x'  # noqa / data
    RUNTIME_OPTION  = B'o'  # noqa / runtime option
    SPLASH          = B'l'  # noqa / splash resources
    UNKNOWN         = B'uk' # noqa
    DECOMPILED      = B'dc' # noqa
    USERCODE        = B'uc' # noqa
    ENCRYPTED       = B'ec' # noqa


class PzType(enum.IntEnum):
    MODULE = 0
    PKG = 1
    DATA = 2


@dataclasses.dataclass
class PiMeta:
    type: PiType
    name: str
    data: Callable[[], buf] | buf

    def unpack(self) -> buf:
        if callable(self.data):
            self.data = self.data()
        return self.data


def make_decompiled_item(name: str, data: buf, *magics) -> PiMeta:

    def extract(data=data, magics=magics):
        error = None
        if any(data[:4] == m[:4] for m in magics):
            return decompile_buffer(data, name)
        for magic in magics:
            try:
                return decompile_buffer(magic + data, name)
            except Exception as exception:
                error = exception
        return '\n'.join(F'# {line}'
            for line in str(error).splitlines(True)).encode('utf8')

    return PiMeta(PiType.DECOMPILED, F'{name}.py', extract)


class PYZ(Struct):

    MagicSignature = B'PYZ\0'

    def __init__(self, reader: StructReader, version: str):
        reader.bigendian = True
        self.base = reader.tell()
        signature = reader.read(4)
        if signature != self.MagicSignature:
            raise ValueError('invalid magic')
        magic = bytes(reader.read(4))
        with contextlib.suppress(KeyError, AttributeError):
            version = xdis.magics.versions[magic]
        vtuple = version2tuple(version)
        padding_size = 4
        if vtuple >= (3, 3):
            padding_size += 4
        if vtuple >= (3, 7):
            padding_size += 4
        self.version = version
        self.magic = magic + padding_size * b'\0'
        self.toc_offset = reader.i32()
        self.reader = reader
        self.entries: list[PiMeta] = []

    def unpack(self, decompile: bool, key: bytes | None = None) -> bool:
        with StreamDetour(self.reader, self.base + self.toc_offset):
            toc_data = self.reader.read()
        try:
            toc = marshal.loads(toc_data)
        except Exception:
            toc = Marshal(memoryview(toc_data)).object()

        if isinstance(toc, list):
            try:
                toc = dict(toc)
            except Exception as error:
                self.entries = []
                self.error = error
                return False

        if TYPE_CHECKING:
            toc = cast(dict[str | bytes, tuple[int, int, int]], toc)

        failures = 0
        attempts = len(toc)

        for name, (_pzt, offset, length) in toc.items():
            if not isinstance(name, str):
                name = codecs.decode(name, 'utf-8')
            try:
                pzt = PzType(_pzt)
            except Exception:
                pzt = PzType.DATA

            name = name.replace('.', '/')
            if pzt is PzType.PKG:
                name = F'{name}/__init__'

            with StreamDetour(self.reader, self.base + offset):
                data = self.reader.read(length)

            if key:
                def decompressed(data=data):
                    cipher = AES.new(key, AES.MODE_CFB, bytes(data[:0x10]))
                    return zlib.decompress(cipher.decrypt(data[0x10:]))
            elif decompress_peek(data):
                def decompressed(data=data):
                    return zlib.decompress(data)
            else:
                failures += 1
                continue

            if decompile and pzt in (PzType.MODULE, PzType.PKG):
                def decompiled(data=data, name=name, magic=self.magic):
                    data = decompressed(data)
                    if data[:4] != magic[:4]:
                        data = magic + data
                    return decompile_buffer(data, name)
                self.entries.append(PiMeta(PiType.DECOMPILED, F'{name}.py', decompiled))
                name = F'{name}.pyc'
                type = PiType.SOURCE
            else:
                type = PiType.DATA

            self.entries.append(PiMeta(type, name, decompressed))

        if key:
            if failures >= 6:
                xtpyi.logger.warning(F'pyz decompression failed for {failures - 5} additional items')
            return True
        elif failures > 0.7 * attempts:
            self.entries.clear()
            return False
        else:
            return True


class PiTOCEntry(Struct):

    def __init__(self, reader: StructReader):
        reader.bigendian = True
        entry_start_offset = reader.tell()
        self.size_of_entry = reader.i32()
        self.offset = reader.i32()
        self.size_of_compressed_data = reader.i32()
        self.size_od_uncompressed_data = reader.i32()
        self.is_compressed = bool(reader.read_byte())
        entry_type = bytes(reader.read(1))
        name_length = self.size_of_entry - reader.tell() + entry_start_offset
        if name_length > 0x1000:
            raise RuntimeError(F'Refusing to process TOC entry with name of size {name_length}.')
        name, *_ = bytes(reader.read(name_length)).partition(B'\0')
        try:
            name = name.decode('utf8', 'backslashreplace')
        except Exception:
            name = str(uuid.uuid4())
        else:
            if not all(part.isprintable() for part in re.split('\\s*', name)):
                raise RuntimeError('Refusing to process TOC entry with non-printable name.')
        if entry_type == B'Z':
            entry_type = B'z'
        try:
            self.type = PiType(entry_type)
        except ValueError:
            xtpyi.log_warn(F'unknown type {entry_type!r} in field {name}')
            self.type = PiType.UNKNOWN
        self.name = name

    def __hash__(self):
        return hash(self.name)


class PyInstallerArchiveEpilogue(Struct):

    MagicSignature = bytes.fromhex('4D45490C0B0A0B0E')

    def _read_libname(self, reader: StructReader) -> str | None:
        position = reader.tell()
        try:
            libname, t, rest = reader.read_bytes(64).partition(B'\0')
        except EOFError:
            reader.seekset(position)
            return None
        try:
            libname = libname.decode('utf8')
        except Exception:
            reader.seekset(position)
            return None
        if not t or any(rest) or len(rest) < 10 or not re.fullmatch(R'[\s!-~]+', libname):
            reader.seekset(position)
            return None
        return libname

    def __init__(self, reader: StructReader, offset: int, unmarshal: Unmarshal = Unmarshal.No, decompile: bool = False):
        self.decompile = decompile
        reader.bigendian = True
        reader.seekset(offset)
        self.reader = reader
        signature = reader.read_bytes(8)
        if signature != self.MagicSignature:
            raise ValueError(
                F'offset 0x{offset:X} has invalid signature {signature.hex().upper()}; '
                F'should be {self.MagicSignature.hex().upper()}')
        self.size = reader.i32()
        toc_offset = reader.i32()
        toc_length = reader.i32()
        self.py_version = '.'.join(str(reader.u32()))
        self.py_libname = self._read_libname(reader)
        self.offset = reader.tell() - self.size

        self.toc: dict[str, PiTOCEntry] = {}
        toc_end = self.offset + toc_offset + toc_length
        reader.seekset(self.offset + toc_offset)
        while reader.tell() < toc_end:
            try:
                entry = PiTOCEntry(reader)
            except EOFError:
                xtpyi.logger.warning('end of file while reading TOC')
                break
            except Exception as error:
                xtpyi.logger.warning(F'unexpected error while reading TOC: {error!s}')
                break
            if entry.name in self.toc:
                raise KeyError(F'duplicate name {entry.name}')
            self.toc[entry.name] = entry

        self.files: dict[str, PiMeta] = {}
        no_pyz_found = True
        pyz_entries: dict[str, PYZ] = {}

        for entry in list(self.toc.values()):
            if entry.type is not PiType.PYZ:
                continue
            no_pyz_found = False
            name, xt = os.path.splitext(entry.name)
            name_pyz = F'{name}.pyz'
            if name == entry.name:
                del self.toc[name]
                self.toc[name_pyz] = entry
                entry.name = name_pyz
            reader.seekset(self.offset + entry.offset)
            if entry.is_compressed:
                data = self.extract(entry.name).unpack()
            else:
                data = reader
            pyz_entries[name] = PYZ.Parse(data, self.py_version)

        magics = {pyz.magic for pyz in pyz_entries.values()}

        if not magics:
            if not no_pyz_found:
                xtpyi.logger.warning(
                    'no magic signature could be recovered from embedded pyzip archives; this is '
                    'unsual and means that there is no way to guess the missing magic for source '
                    'file entries and it will likely not be possible to decompile them.')
            return
        elif len(magics) > 1:
            xtpyi.logger.warning('more than one magic signature was recovered; this is unusual.')

        magics = list(magics)
        keys: set[bytes] = set()

        for entry in self.toc.values():
            extracted = self.extract(entry.name)
            if entry.type not in (PiType.SOURCE, PiType.MODULE):
                self.files[entry.name] = extracted
                continue
            data = extracted.unpack()
            name, _ = os.path.splitext(extracted.name)
            del self.files[extracted.name]
            extracted.name = F'{name}.pyc'
            self.files[extracted.name] = extracted
            is_crypto_key = name.endswith('crypto_key')

            if len(magics) == 1 and data[:4] != magics[0][:4]:
                extracted.data = magics[0] + data

            if is_crypto_key or self.decompile:
                decompiled = make_decompiled_item(name, data, *magics)

                if entry.type is PiType.SOURCE:
                    decompiled.type = PiType.USERCODE
                self.files[decompiled.name] = decompiled

                if is_crypto_key:
                    for key in decompiled.unpack() | carve('string', decode=True):
                        if len(key) != 0x10:
                            continue
                        xtpyi.logger.info(F'found key: {key.decode(xtpyi.codec)}')
                        keys.add(key)

        if unmarshal is Unmarshal.No:
            return

        if not keys:
            key = None
        else:
            key = next(iter(keys))

        for name, pyz in pyz_entries.items():
            pyz.unpack(unmarshal is Unmarshal.YesAndDecompile, key)
            for unpacked in pyz.entries:
                unpacked.name = path = F'{name}/{unpacked.name}'
                if path in self.files:
                    raise ValueError(F'duplicate file name: {path}')
                self.files[path] = unpacked

    def extract(self, name: str) -> PiMeta:
        try:
            return self.files[name]
        except KeyError:
            pass
        entry = self.toc[name]
        with StreamDetour(self.reader, self.offset + entry.offset):
            data = self.reader.read(entry.size_of_compressed_data)
        if entry.is_compressed:
            def extracted(d=data):
                return zlib.decompress(d)
        else:
            extracted = data
        result = PiMeta(entry.type, name, extracted)
        self.files[name] = result
        return result


class xtpyi(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extracts and decompiles files from a Python Installer (aka PyInstaller) archive.
    """
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', date=b'date',
        decompile: Param[bool, Arg.Switch('-c', help='Attempt to decompile PYC files.')] = False,
        user_code: Param[bool, Arg.Switch('-u', group='FILTER', help=(
            'Extract only source code files from the root of the archive. These usually implement '
            'the actual domain logic. This implies the --decompile option.'))] = False,
        unmarshal: Param[int, Arg('-y', action='count', group='FILTER', help=(
            '(DANGEROUS) Unmarshal embedded PYZ archives. Warning: Maliciously crafted packages can '
            'potentially exploit this to execute code. It is advised to only use this option inside '
            'an isolated environment. Specify twice to decompile unmarshalled Python bytecode.'
        ))] = 0
    ):
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            path=path,
            date=date,
            decompile=decompile,
            unmarshal=unmarshal,
            user_code=user_code,
        )

    def unpack(self, data):
        view = memoryview(data)
        positions = [m.start() for m in re.finditer(re.escape(PyInstallerArchiveEpilogue.MagicSignature), view)]
        mode = Unmarshal(min(2, int(self.args.unmarshal)))
        self.log_debug(F'unmarshal mode: {mode.name}')
        if not positions:
            raise LookupError('unable to find PyInstaller signature')
        if len(positions) > 2:
            # first position is expected to be the sentinel value in the unpacker stub
            width = max(len(F'{p:X}') for p in positions)
            for position in positions:
                self.log_info(F'magic signature found at offset 0x{position:0{width}X}')
            self.log_warn(F'found {len(positions) - 1} potential PyInstaller epilogue markers; using last one.')
        decompile = self.args.decompile
        uc_target = PiType.USERCODE if decompile else PiType.SOURCE
        archive = PyInstallerArchiveEpilogue.Parse(view, positions[-1], mode, decompile)
        for name, file in archive.files.items():
            if self.args.user_code:
                if file.type != uc_target:
                    continue
                if name.startswith('pyiboot'):
                    continue
            yield self._pack(name, None, file.data, type=file.type.name)

    @classmethod
    def handles(cls, data: buf) -> bool | None:
        return PyInstallerArchiveEpilogue.MagicSignature in data
