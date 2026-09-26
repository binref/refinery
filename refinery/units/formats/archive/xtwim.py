from __future__ import annotations

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.types import Callable, buf
from refinery.lib.wim import (
    WimArchive,
    WimBlob,
    WimDirectoryEntry,
    WimHashMismatch,
    WimHeader,
    WimStream,
    WimStreamKind,
    walk_image,
)
from refinery.units import Chunk
from refinery.units.formats.archive import ArchiveUnit


class xtwim(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files and NTFS alternate data streams from Windows Imaging Format (WIM) files.

    WIM is the file-based disk image format of Windows setup media written by DISM, ImageX, and
    wimlib. ESD files use the same format with solid LZMS compression. An alternate data stream
    (ADS) of a file or directory is extracted as a separate item, whose path is the path of the
    file followed by a colon and the name of the stream: The stream `secret` of `a.txt` has the
    path `a.txt:secret`.

    When a WIM file contains more than one image, each path begins with the index of its image.
    Reparse data, such as the target of a symbolic link or a junction, is not extracted, and links
    without data yield no items. Encrypted files are extracted in the raw EFS format.
    """
    def unpack(self, data: Chunk):
        wim = WimArchive(data)
        header = wim.header
        if header.part_number != 1:
            raise ValueError(
                F'This is part {header.part_number} of a split WIM with {header.total_parts} '
                F'parts; only the first part lists the files.'
            )
        multiple = len(wim.images) > 1
        for index, image in enumerate(wim.images, 1):
            prefix = F'{index}/' if multiple else ''
            for entry in walk_image(self._metadata(index, image)):
                path = prefix + '/'.join(entry.path)
                for stream in entry.streams:
                    if not self._is_item(entry, stream):
                        continue
                    item = F'{path}:{stream.name}' if stream.name else path
                    yield self._pack(item, entry.write_time, self._extractor(wim, stream))

    @staticmethod
    def _is_item(entry: WimDirectoryEntry, stream: WimStream) -> bool:
        if stream.kind == WimStreamKind.REPARSE:
            return False
        if stream.name or any(stream.hash):
            return True
        return not entry.is_directory and entry.reparse_tag is None

    def _metadata(self, index: int, image: WimBlob) -> buf:
        try:
            return image.data()
        except WimHashMismatch as mismatch:
            if not self.leniency:
                raise
            self.log_warn(F'the metadata of image {index} fails its hash check; paths may be wrong')
            return mismatch.data

    @staticmethod
    def _extractor(wim: WimArchive, stream: WimStream) -> Callable[[], buf]:
        def extract():
            if not any(digest := stream.hash):
                return B''
            if (blob := wim.blobs.get(digest)) is None:
                raise LookupError(F'The WIM file contains no data with the SHA-1 hash {digest.hex()}.')
            try:
                return blob.data()
            except WimHashMismatch as mismatch:
                raise RefineryPartialResult(str(mismatch), mismatch.data) from mismatch
        return extract

    @classmethod
    def handles(cls, data) -> bool:
        return data[:len(WimHeader.MAGIC)] == WimHeader.MAGIC
