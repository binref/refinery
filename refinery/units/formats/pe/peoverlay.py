#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import OverlayUnit


class peoverlay(OverlayUnit):
    """
    Returns the overlay of a PE file, i.e. anything that may have been appended to the file.
    This does not include digital signatures. Use `refinery.pestrip` to obtain only the body
    of the PE file after removing the overlay.
    """
    def process(self, data: bytearray) -> bytearray:
        size = self._get_size(data)
        if isinstance(data, bytearray):
            data[:size] = []
            return data
        return data[size:]
