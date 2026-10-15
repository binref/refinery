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

from refinery.lib.id import is_likely_pe
from refinery.lib.meta import MV
from refinery.lib.py import decompile_buffer, version2tuple
from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.lib.types import Param, buf
from refinery.units.formats import number_repeated_names
from refinery.units.formats.archive import ArchiveUnit, Arg
from refinery.units.formats.pe import get_pe_size
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
                error = str(exception)
        return '\n'.join(F'# {line}'
            for line in str(error).splitlines(True)).encode('utf8')

    return PiMeta(PiType.DECOMPILED, F'{name}.py', extract)


class PYZ(Struct):

    MagicSignature = B'PYZ\0'

    def __init__(self, reader: StructReader, version: str):
        reader.bigendian = True
        self.base = reader.tell()
        self.signature = reader.read(4)
        magic = bytes(reader.read(4))
        with contextlib.suppress(KeyError, AttributeError):
            from refinery.lib.shared.xdis import xdis
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
            except Exception:
                self.entries = []
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
        self.signature = reader.read_bytes(8)
        self.size = reader.i32()
        toc_offset = reader.i32()
        toc_length = reader.i32()
        self.py_version = '.'.join(str(reader.u32()))
        self.py_libname = self._read_libname(reader)
        self.offset = reader.tell() - self.size

        self.toc: list[PiTOCEntry] = []
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
            self.toc.append(entry)

        for entry in self.toc:
            name, _ = os.path.splitext(entry.name)
            if entry.type is PiType.PYZ and name == entry.name:
                entry.name = F'{name}.pyz'

        items = [(entry, self.extract(entry)) for entry in self.toc]
        self.files: list[PiMeta] = []
        pyz_entries: list[tuple[str, PYZ]] = []

        for entry, item in items:
            if entry.type is not PiType.PYZ:
                continue
            name, _ = os.path.splitext(entry.name)
            reader.seekset(self.offset + entry.offset)
            if entry.is_compressed:
                data = item.unpack()
            else:
                data = reader
            pyz_entries.append((name, PYZ.Parse(data, self.py_version)))

        magics = list({pyz.magic for _, pyz in pyz_entries})

        if not magics:
            xtpyi.logger.warning(
                'the archive contains no embedded pyzip archive from which to recover the magic '
                'signature that source file entries lack; it will not be possible to decompile '
                'them.')
        elif len(magics) > 1:
            xtpyi.logger.warning('more than one magic signature was recovered; this is unusual.')

        key: bytes | None = None

        for entry, extracted in items:
            self.files.append(extracted)
            if entry.type not in (PiType.SOURCE, PiType.MODULE):
                continue
            data = extracted.unpack()
            name, _ = os.path.splitext(extracted.name)
            extracted.name = F'{name}.pyc'
            if not magics:
                continue
            is_crypto_key = name.endswith('crypto_key')

            if len(magics) == 1 and data[:4] != magics[0][:4]:
                extracted.data = magics[0] + data

            if is_crypto_key or self.decompile:
                decompiled = make_decompiled_item(name, data, *magics)

                if entry.type is PiType.SOURCE:
                    decompiled.type = PiType.USERCODE
                self.files.append(decompiled)

                if is_crypto_key:
                    with decompiled.unpack() | carve('string', decode=True) as candidates:
                        key = next((bytes(c) for c in candidates if len(c) == 0x10), None)
                    if key is not None:
                        xtpyi.logger.info(F'found key: {key.decode(xtpyi.codec)}')

        if unmarshal is Unmarshal.No:
            return

        names = number_repeated_names([name for name, _ in pyz_entries])
        for name, (_, pyz) in zip(names, pyz_entries):
            pyz.unpack(unmarshal is Unmarshal.YesAndDecompile, key)
            for unpacked in pyz.entries:
                unpacked.name = F'{name}/{unpacked.name}'
                self.files.append(unpacked)

    def extract(self, entry: PiTOCEntry) -> PiMeta:
        with StreamDetour(self.reader, self.offset + entry.offset):
            data = self.reader.read(entry.size_of_compressed_data)
        if entry.is_compressed:
            def extracted(d=data):
                return zlib.decompress(d)
        else:
            extracted = data
        return PiMeta(entry.type, entry.name, extracted)


class xtpyi(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extracts and decompiles files from a Python Installer (aka PyInstaller) archive.
    """
    def __init__(
        self, *paths,
        decompile: Param[bool, Arg.Switch('-c', help='Attempt to decompile PYC files.')] = False,
        user_code: Param[bool, Arg.Switch('-u', group='FILTER', help=(
            'Extract only source code files from the root of the archive. These usually implement '
            'the actual domain logic. This implies the --decompile option.'))] = False,
        unmarshal: Param[int, Arg('-y', action='count', group='FILTER', help=(
            '(DANGEROUS) Unmarshal embedded PYZ archives. Warning: Maliciously crafted packages can '
            'potentially exploit this to execute code. It is advised to only use this option inside '
            'an isolated environment. Specify twice to decompile unmarshalled Python bytecode.'
        ))] = 0,
        **kwargs
    ):
        super().__init__(
            *paths,
            decompile=decompile,
            unmarshal=unmarshal,
            user_code=user_code,
            **kwargs
        )

    def _search_pyi_start(self, data: memoryview):
        if not is_likely_pe(data):
            return None
        from refinery.lib import lief
        pe = lief.load_pe_fast(data)
        overlay = get_pe_size(pe, certificate=False)
        size = len(data)
        view = data[overlay:]
        size_bytes = size.to_bytes(4, 'big')
        size_options = []
        for k, b in enumerate(size_bytes):
            if not b:
                continue
            option = ''.join(F'\\x{h:02X}' for h in size_bytes[:k])
            option = F'{option}[\\0-\\x{b - 1:02X}]'
            option = option + (3 - k) * '.'
            size_options.append(option)
        size_pattern = '({})'.format('|'.join(size_options))
        pattern = F'(?s).(?=.{{7}}{size_pattern}{{3}}\\0\\0[\\0-\\x02].)'
        self.log_info(F'no signature found; searching for malformed headers starting at offset {overlay:#x}')
        reader = StructReader(view, bigendian=True)
        for candidate in re.finditer(pattern.encode('ascii'), view):
            offset = candidate.start()
            self.log_debug(F'at {offset:#x}: {reader.peek(24).hex(" ")}', clip=True)
            reader.seekset(offset + 8)
            pkg_len = reader.i32()
            toc_pos = reader.i32()
            toc_len = reader.i32()
            version = reader.i32()
            if not 0 < pkg_len < len(data):
                continue
            if not 0 < toc_pos + toc_len < pkg_len:
                continue
            if not 20 <= version <= 400:
                continue
            return offset + overlay

    def unpack(self, data):
        view = memoryview(data)
        mode = Unmarshal(min(2, int(self.args.unmarshal)))
        self.log_debug(F'unmarshal mode: {mode.name}')

        positions = [
            m.start() for m in re.finditer(
                re.escape(PyInstallerArchiveEpilogue.MagicSignature), view)]
        if not positions and (p := self._search_pyi_start(view)):
            positions = [p]
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
        self.log_info('Signature:', archive.signature)
        for file in archive.files:
            if self.args.user_code:
                if file.type != uc_target:
                    continue
                if file.name.startswith('pyiboot'):
                    continue
            yield self._pack(file.name, None, file.data, **{MV.TYPE: file.type.name})

    @classmethod
    def handles(cls, data: buf) -> bool | None:
        return PyInstallerArchiveEpilogue.MagicSignature in data
