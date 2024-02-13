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
        import qrcode.util
        import qrcode.constants
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
        _util = self._qrcode.util
        _data = self._qrcode.util.QRData(data)
        _mode = {
            _util.MODE_KANJI     : 'kanji',
            _util.MODE_8BIT_BYTE : 'byte',
            _util.MODE_ALPHA_NUM : 'alphanumeric',
            _util.MODE_NUMBER    : 'numeric',
        }[_data.mode]
        self.log_info(F'encoding data in {_mode} mode')
        try:
            img: PilImage = self._qrcode.make(_data)
        except ValueError:
            raise ValueError('input data size exceeds QR code limits')
        with MemoryFile() as stream:
            img.save(stream)
            return stream.getbuffer()

    def process(self, data):
        with MemoryFile(data) as stream:
            img = self._image.open(stream)
        for _data, *_ in self._pyzbar.decode(img):
            yield _data
