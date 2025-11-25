from __future__ import annotations

import ntpath

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from refinery.lib.shared import pefile
from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import ArchiveUnit, UnpackResult

if TYPE_CHECKING:
    from minidump.minidumpfile import (
        MinidumpFile,
        MinidumpMemorySegment,
        MinidumpModule,
    )


class xtdmp(ArchiveUnit):
    """
    Extract modules and memory segments from Minidump files. All extracted PE modules are unmapped
    by overwriting their section offsets with virtual section offsets.
    """
    @ArchiveUnit.Requires('minidump==0.0.24', ['formats', 'default', 'extended'])
    def _minidump():
        import minidump
        import minidump.minidumpfile
        import minidump.streams
        return minidump

    def unpack(self, data):
        mdmp = self._minidump.minidumpfile.MinidumpFile.parse_buff(
            MemoryFile(data, output=bytearray)
        )

        # This is a workaround for a parsing bug in minidump, see this PR:
        #   https://github.com/skelsec/minidump/pull/48
        # When this is fixed and minidump upgraded beyond 0.0.24, the below needs to be adjusted to
        # access mdmp.header.TimeDateStamp instead.
        date = datetime.fromtimestamp(mdmp.header.Reserved, timezone.utc)
        PA = self._minidump.streams.PROCESSOR_ARCHITECTURE

        address_width = 16 if mdmp.sysinfo.ProcessorArchitecture in (
            PA.AARCH64, PA.AMD64, PA.IA64
        ) else 8

        def read(mdmp: MinidumpFile, addr, size):
            result = bytearray()
            while size > 0:
                ok = False
                for arch in (
                    mdmp.memory_segments_64,
                    mdmp.memory_segments,
                ):
                    if arch is None:
                        continue
                    segments: list[MinidumpMemorySegment] = arch.memory_segments
                    for segment in segments:
                        if segment.inrange(addr):
                            end = segment.end_virtual_address
                            assert isinstance(end, int)
                            n = min(end - addr, size)
                            result.extend(segment.read(addr, n, mdmp.file_handle))
                            addr += n
                            size -= n
                            ok = True
                if not ok:
                    raise ValueError(F'Failed to read {size:#x} bytes from {addr:#x}.')
            return result

        modules: list[MinidumpModule] = mdmp.modules.modules
        unpacked_modules: dict[str, UnpackResult] = {}
        for module in modules:
            def _module(d=mdmp, m=module):
                module_data = read(d, m.baseaddress, m.size)
                pe = pefile.PE(data=module_data, fast_load=True)
                last = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage')
                for section in pe.sections:
                    va = section.VirtualAddress
                    vs = section.Misc_VirtualSize
                    section.PointerToRawData = va
                    section.SizeOfRawData = vs
                    last = va + vs
                setattr(pe.OPTIONAL_HEADER, 'SizeOfImage', last)
                if (unmapped := pe.write()) is None:
                    raise RuntimeError(F'Failed to unmap module {ntpath.basename(path)}')
                return unmapped
            drive, rest = ntpath.splitdrive(str(module.name))
            rest = rest.replace(ntpath.sep, '/').lstrip('/')
            path = F'module/{drive[:1]}/{rest}'
            unpacked_modules[path] = self._pack(path, date, _module)
        for path in sorted(unpacked_modules):
            yield unpacked_modules[path]

        for arch in (
            mdmp.memory_segments_64,
            mdmp.memory_segments,
        ):
            if arch is None:
                continue
            segments: list[MinidumpMemorySegment] = arch.memory_segments
            for segment in segments:
                def _segment(d=mdmp, s=segment):
                    return read(d, s.start_virtual_address, s.size)
                yield self._pack(
                    F'memory/{segment.start_virtual_address:0{address_width}X}', date, _segment)

    @classmethod
    def handles(cls, data):
        return data[:4] == B'MDMP'
