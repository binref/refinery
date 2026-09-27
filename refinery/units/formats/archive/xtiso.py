from __future__ import annotations

from refinery.lib.iso import FileSystemType, ISOArchive, is_disc_image
from refinery.lib.types import Param
from refinery.units.formats.archive import ArchiveUnit, Arg


class xtiso(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from ISO 9660 and UDF disc images. This includes raw CD images, often with the
    extension `.bin` or `.img`, which store 2352 or 2448 bytes per sector: the 2048 bytes of user
    data together with the sync pattern, sector header, and error correction data.
    """
    def __init__(
        self, *paths,
        fs: Param[str, Arg.Option('-s', metavar='TYPE', choices=FileSystemType, help=(
            'Specify a file system ({choices}) extension to use. The default setting {default} will automatically '
            'detect the first of the other available options and use it.'))] = 'auto',
        **kwargs
    ):
        super().__init__(*paths, fs=Arg.AsOption(fs, FileSystemType), **kwargs)

    def unpack(self, data):
        if not self.handles(data):
            self.log_warn('The data does not look like an ISO file.')
        iso = ISOArchive(data)
        if (layout := iso.sector_layout).raw:
            self.log_info(F'reading raw sectors of {layout.sector_size} bytes')
        if (fs := self.args.fs) != FileSystemType.AUTO and not iso.select_filesystem(fs):
            self.log_warn(F'The image has no {fs.value} file system; using {iso.filesystem_type} instead.')
        self.log_info(F'using format: {iso.filesystem_type}')
        for entry in iso.entries():
            def extract(e=entry):
                return iso.extract(e)
            yield self._pack(entry.path, entry.date, extract)

    @classmethod
    def handles(cls, data) -> bool:
        return is_disc_image(data)
