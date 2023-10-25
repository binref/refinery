#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats.pe import OverlayUnit


class pestrip(OverlayUnit):
    """
    Removes the overlay of a PE file and returns the main executable. Use `refinery.peoverlay` to
    extract the overlay.
    """

    def process(self, data: bytearray) -> bytearray:
        size = self._get_size(data)
        try:
            data[size:] = []
        except Exception:
            data = data[:size]
        else:
            return data
