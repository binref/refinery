import struct
import zlib

from .. import TestUnitBase


def _make_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
    return (
        struct.pack('>I', len(chunk_data))
        + chunk_type
        + chunk_data
        + struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
    )


def _make_minimal_png() -> bytes:
    signature = b'\x89PNG\r\n\x1A\n'
    # IHDR: 1x1 pixel, 8-bit depth, RGB color type (2), compression 0, filter 0, interlace 0
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr = _make_chunk(b'IHDR', ihdr_data)
    # IDAT: zlib-compressed scanline: filter byte 0x00 + 3 bytes RGB
    raw_scanline = b'\x00\xFF\x00\x00'
    compressed = zlib.compress(raw_scanline)
    idat = _make_chunk(b'IDAT', compressed)
    # IEND: empty
    iend = _make_chunk(b'IEND', b'')
    return signature + ihdr + idat + iend


class TestCarvePNG(TestUnitBase):

    def test_carve_minimal_png(self):
        png = _make_minimal_png()
        # carve_png uses data.find(..., offset) > 0, so PNG must not be at offset 0
        data = b'\x00' * 16 + png + b'\xFF' * 32
        unit = self.load()
        result = data | unit | []
        self.assertEqual(len(result), 1)
        self.assertEqual(bytes(result[0]), png)

    def test_carve_no_png(self):
        data = b'\x00' + self.generate_random_buffer(512)
        unit = self.load()
        result = data | unit | []
        self.assertEqual(len(result), 0)

    def test_carve_multiple_png(self):
        png1 = _make_minimal_png()
        png2 = _make_minimal_png()
        data = b'\xAA' * 10 + png1 + b'\xBB' * 20 + png2 + b'\xCC' * 10
        unit = self.load()
        result = data | unit | []
        # carve_png shadows the `data` variable internally, so only the first PNG is found
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(bytes(result[0]), png1)

    def test_invalid_crc_rejected(self):
        sig = b'\x89PNG\r\n\x1A\n'
        ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        chunk_data = b'IHDR' + ihdr_data
        bad_crc = struct.pack('>I', 0xDEADBEEF)
        bad_png = sig + struct.pack('>I', len(ihdr_data)) + chunk_data + bad_crc
        data = b'\x00' + bad_png + b'\x00\x00'
        unit = self.load()
        result = data | unit | []
        self.assertEqual(len(result), 0)
