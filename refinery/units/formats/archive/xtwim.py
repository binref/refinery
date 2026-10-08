from __future__ import annotations

from uuid import UUID

from refinery.lib.exceptions import RefineryPartialResult
from refinery.lib.tools import exception_to_string
from refinery.lib.types import Callable, Iterable, buf
from refinery.lib.wim import (
    WimArchive,
    WimBlob,
    WimDirectoryEntry,
    WimHashMismatch,
    WimHeader,
    WimPart,
    WimStream,
    WimStreamKind,
    walk_image,
)
from refinery.units import Chunk
from refinery.units.formats.archive import ArchiveUnit

_SEPARATOR_REPLACEMENTS = str.maketrans({0x2F: 0xFFFD, 0x5C: 0xFFFD})


class xtwim(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files and NTFS alternate data streams from Windows Imaging Format (WIM) files.

    WIM is the file-based disk image format of Windows setup media written by DISM, ImageX, and
    wimlib. ESD files use the same format with solid LZMS compression. An alternate data stream
    (ADS) of a file or directory is extracted as a separate item, whose path is the path of the
    file followed by a colon and the name of the stream: The stream `secret` of `a.txt` has the
    path `a.txt:secret`.

    When a WIM file contains more than one image, each path begins with the index of its image.
    An image whose directory tree cannot be read is skipped with a warning. A slash or backslash
    within the name of a file or stream is replaced by the character U+FFFD. Reparse data, such
    as the target of a symbolic link or a junction, is not extracted, and links without data
    yield no items. Encrypted files are extracted in the raw EFS format; the EFS data of an
    encrypted directory is not extracted.

    Multi-volume archives can be extracted if all required disks are present as chunks within the
    current frame.
    """
    def unpack(self, data: Chunk):
        header = WimHeader.Parse(memoryview(data))
        if header.part_number != 1:
            raise ValueError(
                F'Part {header.part_number} of a split WIM with {header.total_parts} parts is '
                F'given without part 1, which lists the files.'
            )
        others: list[tuple[int, Chunk]] = data.temp or []
        parts = [WimPart(data)]
        for number, chunk in others:
            try:
                parts.append(WimPart(chunk))
            except MemoryError:
                raise
            except Exception as error:
                if self.log_debug():
                    raise
                self.log_warn(
                    F'failed to read part {number} of the split WIM: {exception_to_string(error)}'
                )
        wim = WimArchive(*parts)
        if wim.missing_parts:
            self.log_warn(
                F'the split WIM has {header.total_parts} parts, of which {len(parts)} can be read; '
                F'files whose data is stored in the others cannot be extracted'
            )
        multiple = len(wim.images) > 1
        for index, image in enumerate(wim.images, 1):
            try:
                yield from self._image_items(wim, index, image, F'{index}/' if multiple else '')
            except Exception as error:
                if self.log_debug():
                    raise
                self.log_warn(F'failed to list image {index}: {exception_to_string(error)}')

    def filter(self, chunks: Iterable[Chunk]):
        incomplete: dict[tuple[UUID, int], list[dict[int, Chunk]]] = {}
        for chunk in chunks:
            if (ready := self._gather(chunk, incomplete)) is not None:
                yield ready
        for sets in incomplete.values():
            while sets:
                if 1 in sets[0]:
                    yield self._combine(sets.pop(0))
                else:
                    yield from sets.pop(0).values()

    @classmethod
    def _gather(
        cls,
        chunk: Chunk,
        incomplete: dict[tuple[UUID, int], list[dict[int, Chunk]]],
    ) -> Chunk | None:
        if (position := cls._split_position(chunk)) is None:
            return chunk
        split_id, number = position
        sets = incomplete.setdefault(split_id, [])
        index = next((k for k, parts in enumerate(sets) if number not in parts), len(sets))
        if index == len(sets):
            sets.append({})
        parts = sets[index]
        parts[number] = chunk
        _, total = split_id
        if len(parts) < total:
            return None
        return cls._combine(sets.pop(index))

    @classmethod
    def _split_position(cls, chunk: Chunk) -> tuple[tuple[UUID, int], int] | None:
        if not chunk.visible or not cls.handles(chunk):
            return None
        try:
            header = WimHeader.Parse(memoryview(chunk))
        except (ValueError, EOFError):
            return None
        if header.total_parts == 1:
            return None
        return header.split_id, header.part_number

    @staticmethod
    def _combine(parts: dict[int, Chunk]) -> Chunk:
        (_, first), *others = sorted(parts.items())
        first.temp = others
        return first

    def _image_items(self, wim: WimArchive, index: int, image: WimBlob, prefix: str):
        for entry in walk_image(self._metadata(index, image)):
            path = prefix + '/'.join(name.translate(_SEPARATOR_REPLACEMENTS) for name in entry.path)
            for stream in entry.streams:
                if not self._is_item(entry, stream):
                    continue
                if stream_name := stream.name.translate(_SEPARATOR_REPLACEMENTS):
                    item = F'{path}:{stream_name}'
                else:
                    item = path
                yield self._pack(item, entry.write_time, self._extractor(wim, stream))

    @staticmethod
    def _is_item(entry: WimDirectoryEntry, stream: WimStream) -> bool:
        if stream.name:
            return True
        if stream.kind == WimStreamKind.REPARSE or entry.is_directory:
            return False
        return any(stream.hash) or entry.reparse_tag is None

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
        if not any(digest := stream.hash):
            return bytes
        if (blob := wim.blobs.get(digest)) is None:
            return lambda: wim.blob(digest).data()
        read = blob.extractor()

        def extract():
            try:
                return read()
            except WimHashMismatch as mismatch:
                raise RefineryPartialResult(str(mismatch), mismatch.data) from mismatch
        return extract

    @classmethod
    def handles(cls, data) -> bool:
        return data[:len(WimHeader.MAGIC)] == WimHeader.MAGIC
