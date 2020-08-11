#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import PIL.Image

from .. import Unit
from ...lib.structures import MemoryFile


class binpng(Unit):
    """
    Decodes the RGBT (red/green/blue/transparency) values of the pixels
    of a given PNG image file and outputs these values as bytes.
    """
    def process(self, data):
        image = PIL.Image.open(MemoryFile(data))
        pixelmap, width, height = image.load(), *image.size
        return bytes(code
            for i in range(width)
            for j in range(height)
            for code in pixelmap[i, j])
