from __future__ import annotations

from refinery.lib.cab import CabDisk, Cabinet, CabSequenceMismatch
from refinery.units import Chunk
from refinery.units.formats.archive import ArchiveUnit


class xtcab(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from CAB (cabinet) archives. Multi-volume archives can be extracted if all
    required disks are present as chunks within the current frame.
    """
    def unpack(self, data: Chunk):
        if (arc := data.temp) is None:
            arc = Cabinet()
            arc.append(memoryview(data))
        try:
            arc.check()
        except CabSequenceMismatch as ce:
            self.log_info(str(ce))
        arc.process()
        one = len(arc.files) == 1
        self.log_info(F'processing CAB with {len(arc)} disk{"s" * (1 - one)}')
        for id, files in arc.files.items():
            for file in files:
                path = file.name
                if not one:
                    path = F'CAB{id:04X}/{path}'
                yield self._pack(path, file.timestamp, lambda f=file: f.decompress())

    def filter(self, chunks):
        box = None
        cab = Cabinet()
        for chunk in chunks:
            if not self.handles(chunk):
                yield chunk
                continue
            if box is None:
                box = chunk
                box.temp = cab
            if cab.needs_more_disks():
                cab.append(memoryview(chunk))
            else:
                yield box
                box = chunk
                cab = box.temp = Cabinet()
        if box:
            yield box

    @classmethod
    def handles(cls, data):
        return data[:4] == CabDisk.MAGIC
