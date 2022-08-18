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
    these values as bytes. Each row of the image is transformed and output as and individual chunk.
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

    @Unit.Requires('Pillow', optional=False)
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        image = self._image.open(MemoryFile(data))
        if self.args.transpose:
            image = image.transpose(self._image.Transpose.ROTATE_90)
        width, height = image.size
        for y in range(height):
            yield bytearray(
                image.getpixel((x, y))[p]
                for x in range(width)
                for p in self.args.parts
            )
