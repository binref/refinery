#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats.archive import ArchiveUnit
from refinery.units import Chunk
from refinery.lib.cab import Cabinet, CabDisk


class xtcab(ArchiveUnit):
    """
    Extract files from CAB (cabinet) archives. The unit can also handle multi-volume cab archives
    if all required disks are present as chunks within the current frame.
    """
    def unpack(self, data: Chunk):
        arc: Cabinet = data.temp
        arc.check()
        arc.process()
        one = len(arc.files) == 1
        self.log_info(F'processing CAB with {len(arc)} disks')
        for id, files in arc.files.items():
            for file in files:
                path = file.name
                if not one:
                    path = F'CAB{id:04X}/{path}'
                yield self._pack(path, file.timestamp, lambda f=file: f.decompress())

    def filter(self, inputs):
        box = None
        cab = Cabinet()
        for chunk in inputs:
            if box is None:
                box = chunk
                box.temp = cab
            if cab.needs_more_disks():
                cab.append(chunk)
            else:
                yield box
                box = chunk
                cab = box.temp = Cabinet()
        if box:
            yield box

    @classmethod
    def handles(cls, data: bytearray):
        return data.startswith(CabDisk.MAGIC)
