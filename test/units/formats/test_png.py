import struct
import zlib

from refinery.lib import json

from .. import TestUnitBase


def _make_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
    return (
        struct.pack('>I', len(chunk_data))
        + chunk_type
        + chunk_data
        + struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
    )


def _make_ihdr(width=1, height=1, bit_depth=8, color_type=2) -> bytes:
    ihdr_data = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
    return _make_chunk(b'IHDR', ihdr_data)


def _make_minimal_png(**kwargs) -> bytes:
    signature = b'\x89PNG\r\n\x1A\n'
    ihdr = _make_ihdr(**kwargs)
    raw_scanline = b'\x00\xFF\x00\x00'
    compressed = zlib.compress(raw_scanline)
    idat = _make_chunk(b'IDAT', compressed)
    iend = _make_chunk(b'IEND', b'')
    return signature + ihdr + idat + iend


class TestPNG(TestUnitBase):

    def test_basic_chunk_extraction(self):
        data = _make_minimal_png()
        unit = self.load()
        results = data | unit | []
        paths = [self._path(r) for r in results]
        self.assertIn('chunks/0.IHDR', paths)
        self.assertIn('chunks/1.IDAT', paths)
        self.assertIn('chunks/2.IEND', paths)

    def test_dimensions_json(self):
        data = _make_minimal_png(width=320, height=240)
        unit = self.load('meta/dimensions.json')
        result = data | unit | bytes
        parsed = json.loads(result)
        self.assertEqual(parsed['width'], 320)
        self.assertEqual(parsed['height'], 240)
        self.assertEqual(parsed['bit_depth'], 8)
        self.assertEqual(parsed['color_type'], 2)

    def test_text_chunk_extraction(self):
        text_payload = b'Author\x00John Doe'
        text_chunk = _make_chunk(b'tEXt', text_payload)
        signature = b'\x89PNG\r\n\x1A\n'
        ihdr = _make_ihdr()
        idat = _make_chunk(b'IDAT', zlib.compress(b'\x00\xFF\x00\x00'))
        iend = _make_chunk(b'IEND', b'')
        data = signature + ihdr + text_chunk + idat + iend
        unit = self.load('text/*')
        result = data | unit | bytes
        self.assertEqual(result, b'John Doe')

    def test_ztxt_chunk_extraction(self):
        keyword = b'Comment'
        raw_text = b'This is compressed text'
        compressed_text = zlib.compress(raw_text)
        ztxt_payload = keyword + b'\x00\x00' + compressed_text
        ztxt_chunk = _make_chunk(b'zTXt', ztxt_payload)
        signature = b'\x89PNG\r\n\x1A\n'
        ihdr = _make_ihdr()
        idat = _make_chunk(b'IDAT', zlib.compress(b'\x00\xFF\x00\x00'))
        iend = _make_chunk(b'IEND', b'')
        data = signature + ihdr + ztxt_chunk + idat + iend
        unit = self.load('text/*')
        result = data | unit | bytes
        self.assertEqual(result, raw_text)

    def test_meta_chunk_extraction(self):
        gama_data = struct.pack('>I', 45455)
        gama_chunk = _make_chunk(b'gAMA', gama_data)
        signature = b'\x89PNG\r\n\x1A\n'
        ihdr = _make_ihdr()
        idat = _make_chunk(b'IDAT', zlib.compress(b'\x00\xFF\x00\x00'))
        iend = _make_chunk(b'IEND', b'')
        data = signature + ihdr + gama_chunk + idat + iend
        unit = self.load('meta/*.gAMA')
        result = data | unit | bytes
        self.assertEqual(result, gama_data)

    def test_handles_png(self):
        from refinery.units.formats.png import png as PngUnit
        data = _make_minimal_png()
        self.assertTrue(PngUnit.handles(data))

    def test_handles_not_png(self):
        from refinery.units.formats.png import png as PngUnit
        self.assertFalse(PngUnit.handles(b'\xFF\xD8\xFF' + b'\x00' * 100))

    @staticmethod
    def _path(chunk) -> str:
        return chunk.meta.get('path', '')
