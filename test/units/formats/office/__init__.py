from __future__ import annotations

import io
import warnings
import zipfile

from typing import Callable

from refinery.lib.ole.file import OleFile

from ... import TestUnitBase

DOC = '4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08'
XLS = '8168819cb693a3a04f771ee119ca00e631a74f09419ad295c5088f1e7a430e98'
DOCM = 'ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394'
STOMPED_DOCM = '6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d'
DOCX = '36c856d2bf531eb27745f04afe89b9a86035fb6808966001cec9fb751e3e90e3'


def rename_vba_project(container: bytes | bytearray, dir_path: str, name: bytes, new_name: bytes) -> bytes:
    """
    Writes a new name over the name of the VBA project whose dir stream has the given path in the
    given compound file. The new name has the same length as the name, and the compressed dir
    stream stores the name once, as a run of literal bytes; the bytes around it identify the place
    of the name in the compound file.
    """
    if len(name) != len(new_name):
        raise ValueError('The new name must have the length of the name.')
    stream = bytes(OleFile(bytes(container)).openstream(dir_path).read())
    if stream.count(name) != 1:
        raise LookupError(F'The dir stream does not store {name!r} exactly once.')
    position = stream.index(name)
    start = max(position - 8, 0)
    context = stream[start:position + len(name) + 8]
    if container.count(context) != 1:
        raise LookupError('The place of the name in the compound file is not unique.')
    offset = container.index(context) + position - start
    renamed = bytearray(container)
    renamed[offset:offset + len(name)] = new_name
    return bytes(renamed)


def list_part_twice(
    document: bytes | bytearray,
    name: str,
    alter: Callable[[bytes], bytes],
    copy_name: str | None = None,
) -> bytes:
    """
    Repacks the given document with the zip writer of the standard library, keeping the order and
    compression of its parts, and lists the part with the given name a second time right after it,
    with its content altered by the given function and under the given copy name, if any.
    """
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(document)) as source, zipfile.ZipFile(output, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            copies = [(info.filename, content)]
            if info.filename == name:
                if (altered := alter(content)) == content:
                    raise ValueError(F'The second copy of {name} does not differ from the first.')
                copies.append((copy_name or name, altered))
            for filename, copy in copies:
                entry = zipfile.ZipInfo(filename, info.date_time)
                entry.compress_type = info.compress_type
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    target.writestr(entry, copy)
    return output.getvalue()


def invert_checksum(document: bytes | bytearray, name: str) -> bytes:
    """
    Inverts the CRC-32 of the part with the given name in its local header and in its entry of the
    central directory; every other byte of the document stays as it is.
    """
    data = bytearray(document)
    with zipfile.ZipFile(io.BytesIO(document)) as archive:
        offsets = [archive.getinfo(name).header_offset + 14]
    encoded = name.encode('utf8')
    position = data.find(B'PK\x01\x02')
    while position >= 0:
        length = int.from_bytes(data[position + 28:position + 30], 'little')
        if data[position + 46:position + 46 + length] == encoded:
            offsets.append(position + 16)
        position = data.find(B'PK\x01\x02', position + 1)
    for offset in offsets:
        data[offset:offset + 4] = bytes(byte ^ 0xFF for byte in data[offset:offset + 4])
    return bytes(data)


class VBAModuleUnitTestBase(TestUnitBase):
    """
    Helpers for the tests of the units that extract the modules of VBA projects.
    """

    def _project(self, sample: str) -> bytes:
        with zipfile.ZipFile(io.BytesIO(self.download_sample(sample))) as archive:
            return archive.read('word/vbaProject.bin')

    def _modules(self, data, *args, **kwargs) -> dict[str, bytes]:
        return {str(chunk.meta['path']): bytes(chunk) for chunk in data | self.load(*args, **kwargs)}

    def _streams(self, data) -> list[str]:
        return [str(chunk.meta['stream']) for chunk in data | self.load()]

    def _logged_modules(self, data) -> tuple[dict[str, bytes], list[str]]:
        with self.load_logged() as (unit, log):
            modules = {str(chunk.meta['path']): bytes(chunk) for chunk in data | unit}
        return modules, log

    def _with_embedded(self, part: bytes | bytearray) -> bytes:
        return list_part_twice(self.download_sample(DOCM), 'word/vbaProject.bin', lambda _: bytes(part), 'word/embeddings/oleObject1.bin')
