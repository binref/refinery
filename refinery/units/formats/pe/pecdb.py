#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class pecdb(Unit):
    """
    Short for "PE: Clear Dynamic Base"; this unit will clear the bit in the PE header that allows
    for address space layout randomization. It will also set the integrity flag. With both bits
    set, this DLL when loaded into memory will usually be loaded at its header-defined base address,
    which can make debugging easier.
    """
    @Unit.Requires('pefile', 'default', 'extended')
    def _pefile():
        import pefile
        return pefile

    def process(self, data: bytearray):
        pe = self._pefile.PE(data=data, fast_load=True)
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        dc = dc & ~0x40 # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        dc = dc & +0x80 # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        pe.OPTIONAL_HEADER.DllCharacteristics = dc
        return pe.write()
