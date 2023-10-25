#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats.pe import OverlayUnit


class peoverlay(OverlayUnit):
    """
    Returns the overlay of a PE file, i.e. anything that may have been appended to the file.
    This does not include digital signatures. Use `refinery.pestrip` to obtain only the body
    of the PE file after removing the overlay.
    """
    def process(self, data: bytearray) -> bytearray:
        size = self._get_size(data)
        try:
            data[:size] = []
        except Exception:
            return data[size:]
        else:
            return data
