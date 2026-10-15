from __future__ import annotations

import io
import warnings
import zipfile

from typing import Callable


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
