from __future__ import annotations

import collections
import datetime
import functools

from typing import Iterator

from refinery.lib.meta import MV
from refinery.lib.tools import exception_to_string
from refinery.lib.types import Param
from refinery.lib.vhd import VirtualDisk, is_vhd, is_vhdx
from refinery.lib.vhd.disk import Partition, VolumeView, partitions
from refinery.lib.vhd.fat import FatError, FatFile, FatVolume, is_fat
from refinery.lib.vhd.ntfs import NtfsError, NtfsFile, NtfsVolume, is_ntfs
from refinery.units import Arg, Chunk
from refinery.units.formats.archive import ArchiveUnit, UnpackResult


class xtvhd(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from VHD and VHDX virtual hard disk images.

    The virtual disk is reconstructed from the container, scanned for an MBR or GPT partition table,
    and the FAT or NTFS file systems contained in its partitions are extracted. Both the legacy VHD
    format (fixed, dynamic, and differencing) and the newer VHDX format are supported. Forensically
    relevant metadata such as the creation, access, and modification timestamps and the file
    attributes are attached to each extracted file. For NTFS volumes, the timestamps from the
    `$FILE_NAME` attribute are also exposed when they differ from those in `$STANDARD_INFORMATION`,
    which is a common indicator of timestamp manipulation. A volume without a readable file system
    is extracted as a raw image after all files, unless the container stores no data for it. When
    such a volume is larger than the input, each block of it that the container stores is extracted
    as a separate item instead, named by its offset in the volume and carrying the variables start
    and end.
    """
    def __init__(
        self, *paths,
        recover: Param[bool, Arg.Switch('-u', help=(
            'Recover deleted files. Output chunks receive a boolean meta variable named "deleted". '
            'The contents of deleted files may be stale or corrupt because the underlying clusters '
            'can have been reallocated.'))] = False,
        meta: Param[int, Arg.Counts('-m', help=(
            'Extract more metadata for files: btime (birth), ctime (creation), mtime (modified), '
            'atime (access). Specify twice to include even more metadata: attributes, file record, '
            'and $FILE_NAME dates when they differ from the $STANDARD_INFORMATION values.'))] = 0,
        **kwargs
    ):
        super().__init__(*paths, recover=recover, meta=meta, **kwargs)

    def unpack(self, data: Chunk):
        disk = VirtualDisk(data)
        for warning in disk.warnings:
            self.log_warn(warning)
        parts = list(partitions(disk))
        names = self._names(parts)
        volumes: list[tuple[Partition, VolumeView, NtfsVolume | FatVolume]] = []
        images: list[tuple[Partition, VolumeView]] = []
        for part in parts:
            view = VolumeView(disk, part)
            if fs := self._volume(part, view):
                volumes.append((part, view, fs))
            elif disk.allocated(part.offset, part.size):
                images.append((part, view))
            else:
                self.log_info(F'partition {part.index}: no data stored, skipped')
        multiple = len(volumes) > 1
        for part, view, fs in volumes:
            prefix = F'{names[part.index]}/' if multiple else ''
            try:
                yield from self._files(fs, prefix)
            except Exception as error:
                if not self._tolerated(part, error):
                    raise
                images.append((part, view))
            for warning in fs.warnings:
                self.log_warn(F'partition {part.index}: {warning}')
        for part, view in images:
            name = 'disk' if part.whole_disk else names[part.index]
            if part.size <= len(data):
                yield self._pack(F'{name}.img', None, functools.partial(view.read, 0, part.size))
                continue
            self.log_info(F'partition {part.index} exceeds the input, extracting stored blocks')
            w = len(hex(part.size))
            for start, end in view.stored(0, part.size):
                yield self._pack(
                    F'{name}.img/{start:#0{w}x}',
                    None,
                    functools.partial(view.read, start, end - start),
                    **{MV.START: start, MV.END: end},
                )

    def _files(self, fs: NtfsVolume | FatVolume, prefix: str) -> Iterator[UnpackResult]:
        for file in fs.files(recover=self.args.recover):
            if file.is_dir:
                continue
            path = F'{prefix}{file.path}' if prefix else file.path
            date = file.date
            meta = self._metadata(file)
            if MV.MTIME in meta:
                date = None
            yield self._pack(path, date, file.extract, **meta)

    def _volume(self, part: Partition, view: VolumeView) -> NtfsVolume | FatVolume | None:
        try:
            boot = view.read(0, 512)
            if is_ntfs(boot):
                return NtfsVolume(view)
            if is_fat(boot):
                return FatVolume(view)
        except Exception as error:
            if not self._tolerated(part, error):
                raise
            return None
        self.log_info(F'partition {part.index}: unrecognized file system')
        return None

    def _tolerated(self, part: Partition, error: Exception) -> bool:
        """
        Decides whether the extraction goes on after reading the given partition failed, and if
        so, logs the error.
        """
        if isinstance(error, MemoryError):
            return False
        if self.log_debug() and not isinstance(error, (FatError, NtfsError)):
            return False
        self.log_warn(F'partition {part.index}: {exception_to_string(error)}')
        return True

    @staticmethod
    def _iso(value: datetime.datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat(' ', 'seconds')

    def _metadata(self, file: FatFile | NtfsFile) -> dict:
        meta = {}
        if self.args.recover:
            meta.update(deleted=file.deleted)
        if (_m := self.args.meta) < 1:
            return meta
        meta.update(
            **{
                MV.BTIME: self._iso(file.btime),
                MV.CTIME: self._iso(file.ctime),
                MV.MTIME: self._iso(file.mtime),
                MV.ATIME: self._iso(file.atime),
            }
        )
        if _m < 2:
            return meta
        meta.update(attributes=(file.attributes or None))
        if isinstance(file, NtfsFile):
            meta.update(record=file.record, allocated=file.allocated or None)
            for t in 'abcm':
                si = getattr(file, F'{t}time')
                fn = getattr(file, F'fn_{t}time')
                if fn is not None and fn != si:
                    meta[F'fn_{t}time'] = self._iso(fn)
        return meta

    @staticmethod
    def _names(parts: list[Partition]) -> dict[int, str]:
        names = {part.index: part.label or F'partition{part.index}' for part in parts}
        while True:
            counts = collections.Counter(names.values())
            clashes = [index for index, name in names.items() if counts[name] > 1]
            if not clashes:
                return names
            for index in clashes:
                names[index] = F'{names[index]}.{index}'

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_vhd(data) or is_vhdx(data)
