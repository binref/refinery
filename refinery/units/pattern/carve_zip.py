from __future__ import annotations

from refinery.lib.zip import ZipCentralDirectory, ZipEndOfCentralDirectory
from refinery.units import Unit


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """

    def process(self, data: bytearray):
        end = len(data)
        mem = memoryview(data)
        rev = []
        while True:
            end = data.rfind(ZipEndOfCentralDirectory.Signature, 0, end)
            if end < 0:
                break
            try:
                end_marker = ZipEndOfCentralDirectory.Parse(mem[end:])
            except ValueError as e:
                self.log_info(F'error parsing end of central directory at 0x{end:X}: {e!s}')
                continue
            else:
                self.log_info(F'successfully parsed end of central directory at 0x{end:X}')
            start = end - end_marker.directory_size
            shift = start - end_marker.directory_offset
            if start < 0:
                self.log_debug('end of central directory size is invalid')
                continue
            try:
                central_directory = ZipCentralDirectory.Parse(mem[start:])
            except ValueError:
                self.log_debug('computed location of central directory is invalid')
                end = end - len(ZipEndOfCentralDirectory.Signature)
                continue
            start = central_directory.header_offset + shift
            if mem[start:start + 4] not in (B'PK\x03\x04', B'\0\0\0\0'):
                # SFX payloads seem to have a nulled header, so we permit this.
                self.log_debug('computed start of ZIP archive does not have the correct signature bytes')
                continue
            rev.append((start, end + len(end_marker)))
            end = start
        for start, end in reversed(rev):
            zip = mem[start:end]
            yield self.labelled(zip, offset=start)
