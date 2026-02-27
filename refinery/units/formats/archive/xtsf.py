from __future__ import annotations

import lzma
import re
import zlib

from enum import Enum
from itertools import cycle
from pathlib import PureWindowsPath

from refinery.lib.id import buffer_offset, buffer_contains
from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.structures import StructReader
from refinery.lib.types import buf
from refinery.units.formats.archive import ArchiveUnit


_SCRIPT_FILE_NAME = b'irsetup.dat'

_SF6_MAGIC = B'\xE0\xE1\xE2\xE3\xE4\xE5\xE6'
_SF7_MAGIC = B'\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7'
_SF8_MAGIC = B'\xE0\xE0\xE1\xE1\xE2\xE2\xE3\xE3\xE4\xE4\xE5\xE5\xE6\xE6\xE7\xE7'


class _Compression(Enum):
    Uncompressed = 2
    PKWare = 3
    LZMA1 = 4
    LZMA2 = 5


def _decompress(compression: _Compression, data: buf) -> buf:
    if not data:
        return data
    if compression is _Compression.Uncompressed:
        return data
    if compression is _Compression.PKWare:
        from refinery.units.compression.pkw import pkw
        return pkw().process(data)
    if compression is _Compression.LZMA1:
        return lzma.decompress(data)
    if compression is _Compression.LZMA2:
        from refinery.lib.decompression import parse_lzma_properties
        filters = parse_lzma_properties(data, version=2)
        decompressor = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filters])
        return decompressor.decompress(bytes(data[9:]))
    raise ValueError(F'Invalid compression type: {compression!r}')


def _detect_compression(reader: StructReader) -> _Compression:
    a, b = reader.u8(peek=True), reader.peek(2)[1]
    if a == 0x00 and b == 0x06:
        return _Compression.PKWare
    if a == 0x5D and b == 0x00:
        return _Compression.LZMA1
    if a == 0x18:
        return _Compression.LZMA2
    raise LookupError('Unable to detect compression method.')


def _xor_special(data: buf) -> bytearray:
    key = bytes((data[0] ^ 0x4D, data[1] ^ 0x5A))
    out = bytearray(a ^ b for a, b in zip(data[:2000], cycle(key)))
    out.extend(data[2000:])
    return out


def _read_sf_string(reader: StructReader) -> bytes:
    data = reader.read_length_prefixed(8)
    data, _, _ = bytes(data).partition(B'\0')
    return data


def _get_sf_version(data: buf) -> tuple[int, int]:
    from refinery.lib import lief
    try:
        pe = lief.load_pe(
            data,
            parse_exports=False,
            parse_imports=False,
            parse_reloc=False,
            parse_rsrc=True,
            parse_signature=False
        )
    except Exception:
        return (-1, -1)
    if not pe.has_resources:
        return (-1, -1)
    check_bogus_manifest = False
    for node in pe.resources.childs:
        if node.id != 24:
            continue
        for rid in node.childs:
            for rlang in rid.childs:
                if not isinstance(rlang, lief.PE.ResourceData):
                    continue
                manifest = rlang.content
                if buffer_contains(manifest, b'<description>Setup Factory 8.0 Run-time</description>'):
                    return (8, 0)
                if any(buffer_contains(manifest, mark) for mark in (
                    b'<description>Setup Factory 9 Run-time</description>',
                    b'<description>Setup Factory Run-time</description>',
                )):
                    ai = buffer_offset(manifest, b'<assemblyIdentity')
                    if ai < 0:
                        return (-1, -1)
                    vi = buffer_offset(manifest[ai:], b'version=')
                    if vi < 0:
                        return (-1, -1)
                    v = re.match(rb'(\d+)\.(\d+)\.(\d+)\.(\d+)', manifest[ai + vi + 9:])
                    if v and int(v[1]) == 9:
                        return (int(v[1]), int(v[2]))
                    return (-1, -1)
                if b'<description>Setup</description>' in manifest:
                    check_bogus_manifest = True
    if check_bogus_manifest and isinstance((rsrc := pe.resources_manager), lief.PE.ResourcesManager):
        for ver in rsrc.version:
            fv = ver.file_info.file_version_ms
            major = (fv >> 0x10) & 0xFFFF
            minor = (fv >> 0x00) & 0xFFFF
            if major != 9:
                continue
            for table in ver.string_file_info.children:
                for entry in table.entries:
                    if entry.key == 'ProductName' and entry.value == 'Setup Factory Runtime':
                        return (major, minor)
    return (-1, -1)


class xtsf(ArchiveUnit):
    """
    Extract files from Setup Factory installer executables (versions 4 through 9).
    """

    def unpack(self, data):
        from refinery.units.formats.pe import get_pe_size
        from refinery.lib.lief import load_pe_fast
        pe = load_pe_fast(data)
        overlay_offset = get_pe_size(pe)
        overlay = memoryview(data)[overlay_offset:]
        reader = StructReader(overlay)
        if bytes(reader.peek(n := len(_SF8_MAGIC))) == _SF8_MAGIC:
            reader.skip(n)
            version = _get_sf_version(data)
            if version[0] == -1:
                self.log_warn('unable to determine SF version from PE; assuming version 8.0')
                version = (8, 0)
            self.log_info(F'parsing SF8, version {version}')
            yield from self._unpack_sf8(reader, version)
            return
        if bytes(reader.peek(n := len(_SF7_MAGIC))) == _SF7_MAGIC:
            self.log_info('parsing SF7')
            reader.skip(n)
            yield from self._unpack_sf7(reader)
            return
        if bytes(reader.peek(n := len(_SF6_MAGIC))) == _SF6_MAGIC:
            self.log_info('parsing SF6')
            reader.skip(n)
            yield from self._unpack_sf6(reader)
            return
        raise ValueError('Unable to find Setup Factory signature in overlay.')

    def _unpack_sf7(self, reader: StructReader):
        reader.seekrel(1)
        size = reader.u32()
        exe_data = reader.read_exactly(size)
        yield self._pack('irsetup.exe', None, lambda d=exe_data: _xor_special(d))
        num_files = reader.u32()
        script_data_list = []
        for _ in range(num_files):
            name = bytes(reader.read_exactly(260))
            name, _, _ = name.partition(B'\0')
            name = name.decode('utf-8', errors='replace')
            size = reader.u32()
            crc = reader.u32()
            compressed = reader.read_exactly(size)
            is_script = name.encode() == _SCRIPT_FILE_NAME
            if is_script:
                decompressed = _decompress(_Compression.PKWare, compressed)
                if crc and crc != zlib.crc32(decompressed) & 0xFFFFFFFF:
                    self.log_warn(F'CRC mismatch for {name}')
                yield self._pack(name, None, decompressed)
                script_data_list.append((decompressed, _Compression.PKWare))
            else:
                def extract(c=compressed, k=crc):
                    return self._decompress(_Compression.PKWare, c, k, -1)
                yield self._pack(name, None, extract)
        for script_bytes, compression in script_data_list:
            yield from self._parse_script_v7(script_bytes, compression, reader)

    def _unpack_sf6(self, reader: StructReader):
        num_files = reader.u8()
        script_data = None
        for _ in range(num_files):
            name = bytes(reader.read_exactly(16))
            name, _, _ = name.partition(B'\0')
            name = name.decode('utf-8', errors='replace')
            size = reader.u32()
            crc = reader.u32()
            compressed = reader.read_exactly(size)
            is_script = name.encode() == _SCRIPT_FILE_NAME
            if is_script:
                decompressed = _decompress(_Compression.PKWare, compressed)
                if crc and crc != zlib.crc32(decompressed) & 0xFFFFFFFF:
                    self.log_warn(F'CRC mismatch for {name}')
                yield self._pack(name, None, decompressed)
                script_data = decompressed
            else:
                def extract(c=compressed, k=crc):
                    return self._decompress(_Compression.PKWare, c, k, -1)
                yield self._pack(name, None, extract)
        if script_data is not None:
            yield from self._parse_script_v6(script_data, reader)

    def _parse_script_v7(self, script_bytes, compression: _Compression, reader: StructReader):
        data = bytes(script_bytes)
        marker = data.find(b'CSetupFileData')
        if marker < 8:
            return
        sd = StructReader(memoryview(script_bytes))
        sd.seekset(marker - 8)
        num_entries = sd.u16()
        sd.seekrel(4)
        class_name_length = sd.u16()
        class_name = bytes(sd.read_exactly(min(class_name_length, 127)))
        class_name, _, _ = class_name.partition(B'\0')
        if class_name != b'CSetupFileData':
            return
        sd.seekrel(5)
        for _ in range(num_entries):
            _read_sf_string(sd)
            basename = _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            sd.seekrel(2)
            decompressed_size = sd.u32()
            sd.u8()
            sd.seekrel(37)
            dest_dir = _read_sf_string(sd)
            sd.seekrel(10)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            sd.seekrel(1)
            _read_sf_string(sd)
            sd.seekrel(8)
            _read_sf_string(sd)
            sd.seekrel(3)
            is_compressed = bool(sd.u8())
            sd.u8()
            sd.u8()
            sd.seekrel(10)
            skip_val = sd.u16()
            sd.seekrel(skip_val * 2)
            _read_sf_string(sd)
            sd.seekrel(2)
            _read_sf_string(sd)
            _read_sf_string(sd)
            package_num = sd.u16()
            for _ in range(package_num):
                _read_sf_string(sd)
            _read_sf_string(sd)
            compressed_size = sd.u32()
            crc = sd.u32()
            sd.seekrel(8)
            file_compression = compression if is_compressed else _Compression.Uncompressed
            path = PureWindowsPath(dest_dir.decode('utf-8', errors='replace')) / basename.decode('utf-8', errors='replace')
            compressed_data = reader.read_exactly(compressed_size)

            def extract(c=compressed_data, m=file_compression, k=crc, s=decompressed_size):
                return self._decompress(m, c, k, s)

            yield self._pack(path.as_posix(), None, extract)

    def _parse_script_v6(self, script_bytes: buf, reader: StructReader[memoryview]):
        marker = buffer_offset(script_bytes, b'CFileInfo')
        if marker < 8:
            return
        sd = StructReader(memoryview(script_bytes))
        sd.seekset(marker - 8)
        num_entries = sd.u16()
        sd.seekrel(4)
        class_name_length = sd.u16()
        class_name = bytes(sd.read_exactly(min(class_name_length, 127)))
        class_name, _, _ = class_name.partition(B'\0')
        if class_name != b'CFileInfo':
            return
        for k in range(num_entries):
            if k > 0:
                sd.seekrel(2)
            compressed_size = sd.u32()
            crc = sd.u32()
            source_path = _read_sf_string(sd)
            sd.seekrel(24)
            decompressed_size = sd.u32()
            sd.u8()
            dest_dir = _read_sf_string(sd)
            sd.seekrel(37)
            basename = PureWindowsPath(source_path.decode('utf-8', errors='replace')).name
            path = PureWindowsPath(dest_dir.decode('utf-8', errors='replace')) / basename
            compressed_data = reader.read_exactly(compressed_size)

            def extract(c=compressed_data, k=crc, s=decompressed_size):
                return self._decompress(_Compression.PKWare, c, k, s)

            yield self._pack(path.as_posix(), None, extract)

    def _unpack_sf8(
        self,
        reader: StructReader[memoryview],
        version: tuple[int, int]
    ):
        reader.seekrel(10)
        size = reader.i64()
        exe_data = reader.read_exactly(size)
        yield self._pack('irsetup.exe', None, lambda d=exe_data: _xor_special(d))
        num_files = reader.u32()
        if num_files > 1000:
            reader.seekrel(-4)
            lua_size = reader.i64()
            lua_data = reader.read_exactly(lua_size)
            yield self._pack('lua5.1.dll', None, lua_data)
            num_files = reader.u32()
        script_data_list: list[tuple[buf, _Compression]] = []
        for _ in range(num_files):
            name = bytes(reader.read_exactly(264))
            name, _, _ = name.partition(B'\0')
            name = name.decode('utf-8', errors='replace')
            file_size = reader.i64()
            file_crc = reader.u32()
            reader.seekrel(4)
            is_script = name.encode() == _SCRIPT_FILE_NAME
            compression = _detect_compression(reader)
            compressed_data = reader.read_exactly(file_size)
            if is_script:
                decompressed = _decompress(compression, compressed_data)
                if file_crc and file_crc != zlib.crc32(decompressed) & 0xFFFFFFFF:
                    self.log_warn(F'CRC mismatch for {name}')
                yield self._pack(name, None, decompressed)
                script_data_list.append((decompressed, compression))
            else:
                def extract(c=compressed_data, m=compression, k=file_crc):
                    return self._decompress(m, c, k, -1)
                yield self._pack(name, None, extract)
        for script_bytes, compression in script_data_list:
            yield from self._parse_script_v8(script_bytes, compression, version, reader)

    def _parse_script_v8(
        self,
        script_bytes: buf,
        compression: _Compression,
        version: tuple[int, int],
        reader: StructReader[memoryview]
    ):
        marker = buffer_offset(script_bytes, b'CSetupFileData')
        if marker < 8:
            return
        sd = StructReader(memoryview(script_bytes))
        sd.seekset(marker - 8)
        num_entries = sd.u16()
        sd.seekrel(4)
        class_name_length = sd.u16()
        class_name = bytes(sd.read_exactly(min(class_name_length, 127)))
        class_name, _, _ = class_name.partition(B'\0')
        if class_name != b'CSetupFileData':
            return
        sd.seekrel(5)
        for _ in range(num_entries):
            _read_sf_string(sd)
            basename = _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            sd.seekrel(2)
            decompressed_size = sd.i64()
            sd.u8()
            sd.seekrel(4)
            sd.i64()
            sd.seekrel(16)
            sd.i64()
            sd.seekrel(25)
            dest_dir = _read_sf_string(sd)
            if version[0] == 9 and version[1] >= 3:
                sd.seekrel(11)
            else:
                sd.seekrel(10)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            _read_sf_string(sd)
            sd.seekrel(1)
            _read_sf_string(sd)
            sd.seekrel(8)
            _read_sf_string(sd)
            sd.seekrel(3)
            is_compressed = bool(sd.u8())
            sd.u8()
            sd.u8()
            sd.seekrel(10)
            skip_val = sd.u16()
            sd.seekrel(skip_val * 2)
            _read_sf_string(sd)
            sd.seekrel(2)
            _read_sf_string(sd)
            _read_sf_string(sd)
            package_num = sd.u16()
            for _ in range(package_num):
                _read_sf_string(sd)
            _read_sf_string(sd)
            compressed_size = sd.i64()
            crc = sd.u32()
            sd.seekrel(8)
            file_compression = compression if is_compressed else _Compression.Uncompressed
            path = PureWindowsPath(dest_dir.decode('utf-8', errors='replace')) / basename.decode('utf-8', errors='replace')
            compressed_data = reader.read_exactly(compressed_size)

            def extract(c=compressed_data, m=file_compression, k=crc, s=decompressed_size):
                return self._decompress(m, c, k, s)

            yield self._pack(path.as_posix(), None, extract)

    def _decompress(self, compression: _Compression, data: buf, crc: int, size: int) -> buf:
        decompressed = _decompress(compression, data)
        if size > 0 and size != (n := len(decompressed)):
            raise RefineryPartialResult(F'Expected {size} bytes, got {n} instead.', data)
        if crc and crc != (_crc := zlib.crc32(decompressed) & 0xFFFFFFFF):
            raise RefineryPartialResult(F'Expected {crc:08X} as checksum, got {_crc:08X} instead.', data)
        return decompressed

    @classmethod
    def handles(cls, data) -> bool:
        if data[:2] != B'MZ':
            return False
        try:
            from refinery.units.formats.pe import get_pe_size
            offset = get_pe_size(data)
        except Exception:
            return False
        if offset >= len(data):
            return False
        overlay = data[offset:]
        if overlay[:len(_SF8_MAGIC)] == _SF8_MAGIC:
            return True
        if overlay[:len(_SF7_MAGIC)] == _SF7_MAGIC:
            return True
        if overlay[:len(_SF6_MAGIC)] == _SF6_MAGIC:
            return True
        return False
