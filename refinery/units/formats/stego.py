#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import IntEnum

from .. import Unit, arg
from ...lib.structures import MemoryFile


class PIXEL_PART(IntEnum):
    r = 0
    g = 1
    b = 2
    a = 3


class stego(Unit):
    """
    Decodes the RGBA (red/green/blue/alpha) values of the pixels of a given image file and
    outputs these values as bytes. Each row of the image is transformed and output as and
    individual chunk. To obtain the data in columns, the `refinery.transpose` unit can be
    used.
    """
    def __init__(
        self,
        parts: arg('parts', nargs='?', type=str, help=(
            'A string containing any ordering of the letters R, G, B, and A (case-insensitive). '
            'These pixel components will be extracted from every pixel in the given order. The '
            'default value is {default}.'
        )) = 'RGB'
    ):
        super().__init__(
            parts=tuple(arg.as_option(p, PIXEL_PART) for p in parts)
        )

    def process(self, data):
        from PIL import Image
        image = Image.open(MemoryFile(data))
        width, height = image.size
        for y in range(height):
            yield bytearray(
                image.getpixel((x, y))[p]
                for x in range(width)
                for p in self.args.parts
            )
