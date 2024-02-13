#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import TYPE_CHECKING

from refinery.units import Unit
from refinery.lib.structures import MemoryFile

if TYPE_CHECKING:
    from qrcode.image.pil import PilImage


class qr(Unit):
    """
    Encode and decode data as Quick Response Codes (QR-Codes).
    """

    @Unit.Requires('qrcode[pil]', 'formats')
    def _qrcode():
        import qrcode
        return qrcode

    @Unit.Requires('pyzbar', 'formats')
    def _pyzbar():
        import pyzbar
        import pyzbar.pyzbar
        return pyzbar.pyzbar

    @Unit.Requires('Pillow', 'formats')
    def _image():
        from PIL import Image
        return Image

    def reverse(self, data: bytearray):
        img: PilImage = self._qrcode.make(data)
        with MemoryFile() as stream:
            img.save(stream)
            return stream.getbuffer()

    def process(self, data):
        with MemoryFile(data) as stream:
            img = self._image.open(stream)
        for _data, *_ in self._pyzbar.decode(img):
            yield _data
