from __future__ import annotations

from refinery.lib.iso import FileSystemType, ISOArchive
from refinery.lib.types import Param
from refinery.units.formats.archive import ArchiveUnit, Arg


class xtiso(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a ISO archive.
    """
    def __init__(
        self,
        *paths, list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', date=b'date',
        fs: Param[str, Arg.Option('-s', metavar='TYPE', choices=FileSystemType, help=(
            'Specify a file system ({choices}) extension to use. The default setting {default} will automatically '
            'detect the first of the other available options and use it.'))] = 'auto'
    ):
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            path=path,
            date=date,
            fs=Arg.AsOption(fs, FileSystemType),
        )

    def unpack(self, data):
        if not self.handles(data):
            self.log_warn('The data does not look like an ISO file.')
        iso = ISOArchive(data)
        if (fs := self.args.fs) != FileSystemType.AUTO:
            iso.select_filesystem(fs)
        self.log_info(F'using format: {iso.filesystem_type}')
        for entry in iso.entries():
            def extract(e=entry):
                return iso.extract(e)
            yield self._pack(entry.path, entry.date, extract)

    @classmethod
    def handles(cls, data) -> bool:
        return any(data[k] == B'CD001' for k in (
            slice(0x8001, 0x8006),
            slice(0x8801, 0x8806),
            slice(0x9001, 0x9006),
        ))
