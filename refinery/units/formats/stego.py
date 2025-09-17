from __future__ import annotations

from enum import IntEnum

from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class PIXEL_PART(IntEnum):
    r = 0
    g = 1
    b = 2
    a = 3


class stego(Unit):
    """
    Decodes the RGBA (red/green/blue/alpha) values of the pixels of a given image file and outputs
    these values as bytes. By default, the pixels are converted left to right, top to bottom. When
    the input image is grayscale, the color channels are ignored. Colored images are converted to
    RGBA mode.
    """
    def __init__(
        self,
        split: Param[bool, Arg.Switch('-m', help='Emit the individual rows or columns as separate outputs.')] = False,
        parts: Param[str, Arg.String('parts', nargs='?', help=(
            'A string containing any ordering of the letters R, G, B, and A (case-insensitive). '
            'These pixel components will be extracted from every pixel in the given order. The '
            'default value is {default}.'
        ))] = 'RGB'
    ):
        super().__init__(
            split=split,
            parts=tuple(Arg.AsOption(p, PIXEL_PART) for p in parts)
        )

    @Unit.Requires('Pillow', ['formats'])
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        split = self.args.split
        parts = self.args.parts
        image = self._image.open(MemoryFile(data, output=bytes))

        grayscale = image.mode.startswith('L')
        bw_bitmap = image.mode.startswith('1')
        no_colors = grayscale or bw_bitmap

        if not no_colors:
            image = image.convert('RGBA')

        width, height = image.size
        chunk_size = 1 if no_colors else len(parts)
        output = MemoryFile()
        buffer = bytearray(chunk_size * width)
        pixels = iter(image.getdata())

        for _ in range(height):
            offset = 0
            for _ in range(width):
                pixel = next(pixels)
                next_offset = offset + chunk_size
                if no_colors:
                    buffer[offset] = pixel
                else:
                    buffer[offset:next_offset] = (pixel[p] for p in parts)
                offset = next_offset
            if split:
                yield buffer
            else:
                output.write(buffer)
        if not split:
            yield output.getvalue()
