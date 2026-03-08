"""
Library for parsing ISO 9660 and UDF disk images.
"""
from __future__ import annotations

import datetime
import enum

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.iso.iso9660 import ISORef
    from refinery.lib.iso.udf import UDFRef


class FileSystemType(enum.Enum):
    AUTO = 'auto'
    ISO = 'iso'
    JOLIET = 'joliet'
    RR = 'rr'
    UDF = 'udf'


class ISOFile:
    """
    Represents a single file entry within an ISO image.
    """
    __slots__ = ('path', 'size', 'date', 'is_dir', 'extents', '_inline', 'key')

    def __init__(
        self,
        path: str,
        size: int,
        date: datetime.datetime | None,
        is_dir: bool,
        extents: list[tuple[int, int]],
        key: tuple[FileSystemType, ISORef | UDFRef],
        inline: bytes | None = None,
    ):
        self.path = path
        self.size = size
        self.date = date
        self.is_dir = is_dir
        self.extents = extents
        self._inline = inline
        self.key = key


class ISOArchive:
    """
    Unified ISO/UDF archive reader. Tries UDF first, falls back to ISO 9660.
    """

    def __init__(self, data):
        from refinery.lib.iso.udf import ANCHOR_SECTOR, UDFArchive, _verify_tag

        self._data = data
        self._iso = None
        self._udf = None
        self._type = FileSystemType.ISO

        udf_found = False

        dv = memoryview(self._data)
        for ss in (2048, 512, 4096):
            anchor_pos = ANCHOR_SECTOR * ss
            if anchor_pos + 16 <= len(dv):
                tag_id = _verify_tag(dv, anchor_pos)
                if tag_id == 2:
                    udf_found = True
                    break

        if udf_found:
            udf = UDFArchive()
            try:
                udf.open(self._data)
            except Exception:
                udf = None
            if udf is not None and udf.refs:
                self._udf = udf
                self._type = FileSystemType.UDF
                return

        from refinery.lib.iso.iso9660 import ISO9660Archive
        iso = ISO9660Archive()
        iso.open(self._data)
        self._iso = iso
        self._type = iso.filesystem_type

    @property
    def filesystem_type(self) -> str:
        return self._type.value

    def select_filesystem(self, fs: FileSystemType) -> None:
        if fs is FileSystemType.UDF:
            if self._udf is not None:
                self._type = FileSystemType.UDF
                return
            from refinery.lib.iso.udf import UDFArchive
            udf = UDFArchive()
            try:
                udf.open(self._data)
            except Exception:
                return
            if udf.refs:
                self._udf = udf
                self._type = FileSystemType.UDF
        elif fs in (FileSystemType.JOLIET, FileSystemType.RR, FileSystemType.ISO):
            if self._iso is None:
                from refinery.lib.iso.iso9660 import ISO9660Archive
                self._iso = ISO9660Archive()
                self._iso.open(self._data)
            self._iso.select_filesystem(fs)
            self._type = self._iso.filesystem_type

    def entries(self):
        if self._type is FileSystemType.UDF and self._udf is not None:
            for ref in self._udf.entries():
                yield ISOFile(
                    path=ref.path,
                    size=ref.total_size,
                    date=ref.date,
                    is_dir=ref.is_dir,
                    extents=ref.extents,
                    inline=ref.inline_data,
                    key=(FileSystemType.UDF, ref),
                )
        elif self._iso is not None:
            for ref in self._iso.entries():
                yield ISOFile(
                    path=ref.path,
                    size=ref.total_size,
                    date=ref.date,
                    is_dir=ref.is_dir,
                    extents=ref.extents,
                    key=(FileSystemType.ISO, ref),
                )

    def extract(self, entry: ISOFile) -> bytes | bytearray:
        from refinery.lib.iso.iso9660 import ISORef
        from refinery.lib.iso.udf import UDFRef
        backend_id, ref = entry.key
        if isinstance(ref, ISORef) and (iso := self._iso):
            if backend_id != FileSystemType.ISO:
                raise ValueError(F'File System Inconsistency; expected ISO, got {backend_id.name}.')
            return iso.extract(ref)
        if isinstance(ref, UDFRef) and (udf := self._udf):
            if backend_id != FileSystemType.UDF:
                raise ValueError(F'File System Inconsistency; expected UDF, got {backend_id.name}.')
            return udf.extract(ref)
        return b''
