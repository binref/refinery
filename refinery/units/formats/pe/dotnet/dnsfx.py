from __future__ import annotations

from refinery.lib.dotnet.header import DotNetStructReader
from refinery.lib.id import buffer_contains
from refinery.lib.meta import SizeInt
from refinery.units.compression.zl import zl
from refinery.units.formats import PathExtractorUnit, UnpackResult


class dnsfx(PathExtractorUnit):
    """
    Extracts files from .NET single file applications.
    """
    _SIGNATURE = bytes([
        # 32 bytes represent the bundle signature: SHA-256 for '.net core bundle'
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    ])

    def unpack(self, data):
        reader = DotNetStructReader(memoryview(data))
        reader.seek(self._find_bundle_manifest_offset(data))

        major_version = reader.u32()
        minor_version = reader.u32()
        self.log_info(F'version {major_version}.{minor_version}')

        count = reader.u32()
        bhash = reader.read_dn_string_primitive()
        self.log_info(F'bundle {bhash} contains {count} files')

        if major_version >= 2:
            reader.u64() # depsOffset
            reader.u64() # depsSize
            reader.u64() # runtimeConfigOffset
            reader.u64() # runtimeConfigSize
            reader.u64() # flags

        for _ in range(count):
            try:
                offset = reader.u64()
                size = reader.u64()
                compressed_size = 0
                if major_version >= 6:
                    compressed_size = reader.u64()
                type = reader.u8()
                path = reader.read_dn_string_primitive()

                def _logmsg():
                    _log = F'read item at offset 0x{offset:08X}, type 0x{type:02X}, size {SizeInt(size)!r}'
                    if compressed_size:
                        return F'{_log}, compressed to size {SizeInt(compressed_size)!r}'
                    return F'{_log}, uncompressed'

                self.log_debug(_logmsg)

                with reader.detour():
                    reader.seek(offset)
                    if compressed_size:
                        item_data = reader.read(compressed_size) | zl | bytearray
                    else:
                        item_data = reader.read(size)

                yield UnpackResult(path, item_data)
            except EOFError:
                self.log_warn('unexpected EOF while parsing bundle, terminating')
                break

    def _find_bundle_manifest_offset(self, data: bytearray) -> int:
        bundle_sig_offset = data.find(self._SIGNATURE, 0)
        if bundle_sig_offset < 0:
            raise ValueError('Cannot find valid Bundle Manifest offset. Is this a .NET Bundle?')
        return int.from_bytes(data[bundle_sig_offset - 8:bundle_sig_offset], 'little')

    @classmethod
    def handles(cls, data):
        return buffer_contains(data, cls._SIGNATURE)
