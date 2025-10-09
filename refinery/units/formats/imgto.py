from __future__ import annotations

import io

from refinery.lib.id import get_image_format
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class imgto(Unit):
    """
    Convert an image to a given format.
    """
    def __init__(
        self,
        format: Param[str, Arg.String(
            help='An image file format like png, jpg, or bmp. The default is {default}.')] = 'png'
    ):
        super().__init__(format=format)

    @Unit.Requires('Pillow', ['formats'])
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        try:
            image = self._image.open(MemoryFile(data, output=bytes))
        except ImportError:
            raise
        except Exception:
            raise ValueError('input could not be parsed as an image')
        with io.BytesIO() as out:
            image.save(out, self.args.format)
            return out.getvalue()

    @classmethod
    def handles(cls, data) -> bool | None:
        if get_image_format(data) is not None:
            return True
