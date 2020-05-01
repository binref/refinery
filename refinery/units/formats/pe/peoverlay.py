#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import get_pe_size
from ... import Unit


class peoverlay(Unit):
    """
    Returns the overlay of a PE file, i.e. anything that may have been appended to the file.
    This does not include digital signatures. Use `refinery.pestrip` to obtain only the body
    of the PE file after removing the overlay.
    """
    def __init__(self, ): pass

    def process(self, data: bytearray) -> bytearray:
        size = get_pe_size(data)
        if isinstance(data, bytearray):
            data[:size] = []
            return data
        return data[size:]
