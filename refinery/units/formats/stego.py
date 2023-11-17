#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntEnum

from refinery.units import Unit, Arg
from refinery.lib.structures import MemoryFile


class PIXEL_PART(IntEnum):
    r = 0
    g = 1
    b = 2
    a = 3


class stego(Unit):
    """
    Decodes the RGBA (red/green/blue/alpha) values of the pixels of a given image file and outputs
    these values as bytes. Each row of the image is transformed and output as an individual chunk.
    """
    def __init__(
        self,
        transpose: Arg.Switch('-t', help='Return the columns of the image rather than the rows.'),
        parts: Arg('parts', nargs='?', type=str, help=(
            'A string containing any ordering of the letters R, G, B, and A (case-insensitive). '
            'These pixel components will be extracted from every pixel in the given order. The '
            'default value is {default}.'
        )) = 'RGB'
    ):
        super().__init__(
            transpose=transpose,
            parts=tuple(Arg.AsOption(p, PIXEL_PART) for p in parts)
        )

    @Unit.Requires('Pillow', 'formats')
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        parts = self.args.parts
        image = self._image.open(MemoryFile(data))
        if self.args.transpose:
            image = image.transpose(self._image.Transpose.ROTATE_90)
        width, height = image.size
        chunk_size = len(parts)
        buffer = bytearray(chunk_size * width)
        for y in range(height):
            offset = 0
            for x in range(width):
                pixel = image.getpixel((x, y))
                next_offset = offset + chunk_size
                buffer[offset:next_offset] = (pixel[p] for p in parts)
                offset = next_offset
            yield buffer
