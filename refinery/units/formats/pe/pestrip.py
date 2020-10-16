#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import OverlayUnit


class pestrip(OverlayUnit):
    """
    Removes the overlay of a PE file and returns the stipped executable. Use `refinery.peoverlay`
    to extract the overlay.
    """
    def process(self, data: bytearray) -> bytearray:
        size = self._get_size(data)
        if isinstance(data, bytearray):
            data[size:] = []
            return data
        return data[:size]
