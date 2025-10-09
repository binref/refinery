from __future__ import annotations

from itertools import islice
from typing import TYPE_CHECKING

from refinery.lib.id import get_image_format
from refinery.lib.structures import MemoryFile
from refinery.units import Unit

if TYPE_CHECKING:
    from PIL.Image import Image


class imgdb(Unit):
    """
    Provides access to the direct bytes of an image file. Each row of pixels is emitted as an
    individual chunk.
    """
    @Unit.Requires('Pillow', ['formats'])
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
            image = self._image.open(MemoryFile(data, output=bytes))
        except Exception:
            raise ValueError('input could not be parsed as an image')
        test = image.getpixel((0, 0))
        if isinstance(test, int):
            self.log_info('reading each pixel as an integer')
            for row in self._get_rows(image):
                yield bytearray(row)
        else:
            self.log_info('reading each pixel as a color value tuple')
            count = len(test)
            total = count * image.width
            out = bytearray(total)
            for row in self._get_rows():
                for pixel, offset in zip(row, range(0, total, count)):
                    out[offset:offset + count] = pixel
            yield out

    @classmethod
    def handles(cls, data) -> bool | None:
        if get_image_format(data) is not None:
            return True
