#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lief

from refinery.units import Unit
from refinery.lib.structures import MemoryFileRO


class pesig(Unit):
    """
    Extracts the contents of the IMAGE_DIRECTORY_ENTRY_SECURITY entry of a PE file,
    i.e. the digital signatures in DER format.
    """

    def __init__(self): pass

    def process(self, data: bytearray) -> bytearray:
        with MemoryFileRO(data) as stream:
            pe = lief.PE.parse(stream)
        for signature in pe.signatures:
            yield bytearray(signature.raw_der)
