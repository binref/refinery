#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import TYPE_CHECKING
from itertools import islice

from refinery.units import Unit
from refinery.lib.structures import MemoryFile

if TYPE_CHECKING:
    from PIL.Image import Image


class imgdb(Unit):
    """
    Provides access to the direct bytes of an image file. Each row of pixels is emitted as an
    individual chunk.
    """
    @Unit.Requires('Pillow', 'formats')
    def _image():
        from PIL import Image
        return Image

    def _get_rows(self, image: Image):
        width = image.width
        pixels = iter(image.getdata())
        while row := list(islice(pixels, 0, width)):
            yield row

    def process(self, data):
        try:
            image = self._image.open(MemoryFile(data, read_as_bytes=True))
        except Exception:
            raise ValueError('input could not be parsed as an image')
        test = image.getpixel((0, 0))
        if isinstance(test, int):
            for row in self._get_rows(image):
                yield bytearray(row)
        else:
            count = len(test)
            total = count * image.width
            out = bytearray(total)
            for row in self._get_rows():
                for pixel, offset in zip(row, range(0, total, count)):
                    out[offset:offset + count] = pixel
            yield out
