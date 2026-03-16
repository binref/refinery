from __future__ import annotations

from refinery.lib.structures import MemoryFile
from refinery.units import Unit


class qr(Unit):
    """
    Decode QR codes from images.

    This unit uses a pure-Python QR decoder that supports standard QR codes (versions 1-40,
    all error correction levels and encoding modes). The only external dependency is Pillow
    for image loading.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import get_image_format
        if get_image_format(data) is not None:
            return True

    @Unit.Requires('Pillow', ['formats', 'extended', 'all'])
    def _image():
        from PIL import Image
        return Image

    def process(self, data):
        from refinery.lib.qr import decode as decode_qr
        try:
            img = self._image.open(MemoryFile(data, output=bytes))
        except ImportError:
            raise
        except Exception:
            raise ValueError('the input data is not recognized as an image')
        for payload in decode_qr(img):
            yield payload
