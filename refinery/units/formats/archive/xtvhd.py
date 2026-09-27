from __future__ import annotations

import datetime
import functools

from refinery.lib.meta import MV
from refinery.lib.types import Param
from refinery.lib.vhd import VirtualDisk, is_vhd, is_vhdx
from refinery.lib.vhd.disk import Partition, VolumeView, partitions
from refinery.lib.vhd.fat import FatError, FatFile, FatVolume, is_fat
from refinery.lib.vhd.ntfs import NtfsError, NtfsFile, NtfsVolume, is_ntfs
from refinery.units import Arg, Chunk
from refinery.units.formats.archive import ArchiveUnit


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
    is extracted as a raw image after all files, unless the container stores no data for it.
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
        recover = self.args.recover
        volumes: list[tuple[Partition, NtfsVolume | FatVolume]] = []
        images: list[tuple[Partition, VolumeView]] = []
        for part in partitions(disk):
            view = VolumeView(disk, part)
            if fs := self._volume(part, view):
                volumes.append((part, fs))
            elif disk.allocated(part.offset, part.size):
                images.append((part, view))
            else:
                self.log_info(F'partition {part.index}: no data stored, skipped')
        multiple = len(volumes) > 1
        for part, fs in volumes:
            prefix = self._prefix(part) if multiple else ''
            for file in fs.files(recover=recover):
                if file.is_dir:
                    continue
                path = F'{prefix}{file.path}' if prefix else file.path
                date = file.date
                meta = self._metadata(file)
                if MV.MTIME in meta:
                    date = None
                yield self._pack(path, date, file.extract, **meta)
        for part, view in images:
            path = 'disk.img' if part.whole_disk else F'{self._name(part)}.img'
            yield self._pack(path, None, functools.partial(view.read, 0, part.size))

    def _volume(self, part: Partition, view: VolumeView) -> NtfsVolume | FatVolume | None:
        boot = view.read(0, 512)
        try:
            if is_ntfs(boot):
                return NtfsVolume(view)
            if is_fat(boot):
                return FatVolume(view)
        except (FatError, NtfsError) as error:
            self.log_warn(F'partition {part.index}: {error!s}')
            return None
        self.log_info(F'partition {part.index}: unrecognized file system')
        return None

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
    def _name(part: Partition) -> str:
        return part.label or F'partition{part.index}'

    @classmethod
    def _prefix(cls, part: Partition) -> str:
        return F'{cls._name(part)}/'

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_vhd(data) or is_vhdx(data)
