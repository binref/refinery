#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import get_pe_size
from ... import Unit


class pestrip(Unit):
    """
    Removes the overlay of a PE file and returns the stipped executable. Use `refinery.peoverlay`
    to extract the overlay.
    """
    def __init__(self): pass

    def process(self, data: bytearray) -> bytearray:
        size = get_pe_size(data)
        if isinstance(data, bytearray):
            data[size:] = []
            return data
        return data[:size]
