from __future__ import annotations

from refinery import perc, xtcab
from refinery.lib.id import buffer_contains, is_likely_pe
from refinery.lib.tools import exception_to_string
from refinery.lib.types import buf
from refinery.units import Chunk
from refinery.units.formats.archive import ArchiveUnit


class xtiex(xtcab, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from IExpress setup self-extracting archive. If the archive contains more than one
    resource named CABINET, the files of each cabinet are listed below the path of its resource.
    """
    def unpack(self, data: buf):
        with data | perc('RCDATA/CABINET/*') as resources:
            cabinets = [Chunk.Wrap(resource) for resource in resources]
        if not cabinets:
            raise ValueError('no RCDATA resource named CABINET was found')
        if len(cabinets) == 1:
            yield from super().unpack(cabinets[0])
            return
        readable = 0
        for cabinet in cabinets:
            resource = str(cabinet.meta['path'])
            try:
                results = list(super().unpack(cabinet))
            except Exception as error:
                self.log_warn(F'failed to read the resource {resource}: {exception_to_string(error)}')
                continue
            readable += 1
            for result in results:
                result.path = F'{resource}/{result.path}'
                yield result
        if not readable:
            raise ValueError(F'none of the {len(cabinets)} resources named CABINET could be read')

    def filter(self, chunks):
        yield from super(ArchiveUnit, self).filter(chunks)

    @classmethod
    def handles(cls, data: buf) -> bool:
        if not is_likely_pe(data):
            return False
        return buffer_contains(data, B'CABINET')
