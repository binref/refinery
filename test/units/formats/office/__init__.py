from __future__ import annotations

import io
import warnings
import zipfile

from typing import Callable


def list_part_twice(document: bytes | bytearray, name: str, alter: Callable[[bytes], bytes]) -> bytes:
    """
    Repacks the given document with the zip writer of the standard library, keeping the order and
    compression of its parts, and lists the part with the given name a second time right after it,
    with its content altered by the given function.
    """
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(document)) as source, zipfile.ZipFile(output, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            copies = [content]
            if info.filename == name:
                if (altered := alter(content)) == content:
                    raise ValueError(F'The second copy of {name} does not differ from the first.')
                copies.append(altered)
            for copy in copies:
                entry = zipfile.ZipInfo(info.filename, info.date_time)
                entry.compress_type = info.compress_type
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    target.writestr(entry, copy)
    return output.getvalue()
