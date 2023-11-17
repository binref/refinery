#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import UnpackResult, PathExtractorUnit, Arg
from refinery.lib.executable import Executable


class vsect(PathExtractorUnit):
    """
    Extract sections/segments from PE, ELF, and MachO executables.
    """
    def __init__(
        self, *paths,
        meta: Arg.Switch('-m', help=(
            'Populates the metadata variables vaddr and vsize containing the virtual address and size '
            'of each section, respectively.')) = False,
        synthetic: Arg.Switch('-s', help=(
            'Include synthesized sections: These represent data regions that are outside the sections '
            'as listed by the executable metadata, such as headers and overlays.')) = False,
        **keywords
    ):
        super().__init__(*paths, meta=meta, synthetic=synthetic, **keywords)

    def unpack(self, data):
        exe = Executable.Load(data)
        mv = memoryview(data)
        for section in exe.sections():
            if section.synthetic and not self.args.synthetic:
                continue
            start = section.physical.lower
            end = section.physical.upper
            va = section.virtual.lower
            vs = len(section.virtual)
            kwargs = {'offset': start}
            if self.args.meta:
                if va is not None:
                    kwargs['vaddr'] = va
                if vs is not None:
                    kwargs['vsize'] = vs
            yield UnpackResult(section.name, mv[start:end], **kwargs)
