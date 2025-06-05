#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import enum

from refinery.units import Unit, Arg
from refinery.lib.structures import MemoryFile


class T(enum.IntEnum):
    V = 0
    H = 1
    R = 2


class imgtp(Unit):
    """
    Perform a number of transpositions on an input image. The transformation string must be a
    sequence composed of the letters H, V, and R. Each letter represents an operation:

    - R rotates the image to the left by 90 degrees.
    - V flips the image top to bottom (vertically).
    - H flips the image left to right (horizontally).

    These transpositions are performed in the order in which they are specified.
    """
    def __init__(
        self,
        transformation: Arg.String(help='The transformation sequence; default is {default}.') = 'R'
    ):
        transformation = [Arg.AsOption(t, T) for t in transformation]
        super().__init__(transformation=transformation)

    @Unit.Requires('Pillow', 'formats')
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        imglib = self._image

        try:
            image = imglib.open(MemoryFile(data, read_as_bytes=True))
        except Exception:
            raise ValueError('input could not be parsed as an image')
        else:
            format = image.format
        conversion = {
            T.V: imglib.Transpose.FLIP_TOP_BOTTOM,
            T.H: imglib.Transpose.FLIP_LEFT_RIGHT,
            T.R: imglib.Transpose.ROTATE_90,
        }
        for tf in self.args.transformation:
            image = image.transpose(conversion[tf])
        with io.BytesIO() as out:
            image.save(out, format)
            return out.getvalue()
