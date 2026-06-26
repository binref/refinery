from __future__ import annotations

import datetime

from refinery.lib.vhd.disk import Partition, VolumeView, partitions
from refinery.lib.vhd.fat import FatFile, FatVolume, is_fat
from refinery.lib.vhd.ntfs import NtfsFile, NtfsVolume, is_ntfs
from refinery.lib.vhd import VirtualDisk, is_vhd, is_vhdx
from refinery.lib.types import Param
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
    which is a common indicator of timestamp manipulation.
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
        for part in partitions(disk):
            view = VolumeView(disk, part)
            boot = view.read(0, 512)
            if is_ntfs(boot):
                volumes.append((part, NtfsVolume(view)))
            elif is_fat(boot):
                volumes.append((part, FatVolume(view)))
            else:
                self.log_info(F'partition {part.index}: unrecognized file system')
        multiple = len(volumes) > 1
        for part, fs in volumes:
            prefix = self._prefix(part) if multiple else ''
            for file in fs.files(recover=recover):
                if file.is_dir:
                    continue
                path = F'{prefix}{file.path}' if prefix else file.path
                date = file.date
                meta = self._metadata(file)
                if 'mtime' in meta:
                    date = None
                yield self._pack(path, date, file.extract, **meta)

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
            btime=self._iso(file.btime),
            ctime=self._iso(file.ctime),
            mtime=self._iso(file.mtime),
            atime=self._iso(file.atime),
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
    def _prefix(part: Partition) -> str:
        label = part.label or F'partition{part.index}'
        return F'{label}/'

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_vhd(data) or is_vhdx(data)
