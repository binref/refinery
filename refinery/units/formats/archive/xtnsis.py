from __future__ import annotations

import itertools
import re

from refinery.lib.id import buffer_contains
from refinery.lib.nsis.archive import NSArchive
from refinery.lib.nsis.decompiler import NSDisassembler
from refinery.units.formats.archive import ArchiveUnit


class xtnsis(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from NSIS archives. Nullsoft Scriptable Install System is a Windows installer
    framework often used for software distribution.
    """

    @classmethod
    def _find_archive_offset(cls, data: bytearray, before: int = -1, flawmax=2):
        def signatures(*magics):
            for changes in range(flawmax + 1):
                for magic in magics:
                    if not changes:
                        yield 0, magic
                        continue
                    for positions in itertools.permutations(range(len(magic)), r=changes):
                        signature = bytearray(magic)
                        for p in positions:
                            signature[p] = 0x2E
                        yield changes, bytes(signature)
        best_guess = None
        search_space = memoryview(data)
        for flaws, sig in signatures(*NSArchive.MAGICS):
            if flaws > 1:
                search_space = search_space[:0x20_000]
            matches = [m.start() - 4 for m in re.finditer(sig, search_space, flags=re.DOTALL)]
            if before >= 0:
                matches = [match for match in matches if match < before]
            matches.reverse()
            archive = None
            for match in matches:
                if match % 0x200 == 0:
                    archive = match
                    break
            if not archive:
                if matches and not best_guess:
                    best_guess = matches[-1]
            else:
                msg = F'Archive signature was found at offset 0x{archive:X}'
                if flaws > 0:
                    msg = F'{msg}; it has {flaws} imperfections and was likely modified'
                cls.log_info(F'{msg}.')
                return archive
        if best_guess:
            cls.log_info(F'A signature was found at offset 0x{best_guess:08X}; it is not properly aligned.')
            return best_guess
        return None

    def unpack(self, data):
        memory = memoryview(data)
        before = -1
        _error = None
        while True:
            offset = self._find_archive_offset(data, before)
            if offset is None:
                _error = _error or ValueError('Unable to find an NSIS archive marker.')
                raise _error
            try:
                arc = NSArchive.Parse(memory[offset:], log=self.log_debug)
            except Exception as e:
                _error = e
                before = offset
            else:
                break

        def info():
            yield F'{arc.header.type.name} archive'
            yield F'compression type {arc.method.value}'
            yield F'mystery value 0x{arc.header.unknown_value:X}'
            yield 'solid archive' if arc.solid else 'fragmented archive'
            yield '64-bit header' if arc.header.is64bit else '32-bit header'
            yield 'unicode' if arc.header.unicode else 'ascii'

        self.log_info(', '.join(info()))

        for item in arc.header.items:
            path = item.path or F'item-0x{item.offset:X}'
            yield self._pack(path, item.mtime, lambda i=item: arc._extract_item(i).data)

        yield self._pack('setup.bin', None, arc.header_data)
        yield self._pack('setup.nsis', None, arc.script.encode(self.codec))

    @classmethod
    def handles(cls, data) -> bool:
        return any(buffer_contains(data, magic) for magic in NSArchive.MAGICS)
