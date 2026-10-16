import io
import json
import zipfile

import pytest

from .. import TestUnitBase


class TestJPG(TestUnitBase):

    def test_real_world_guloader(self):
        data = self.download_sample('3b1b945750892b2feea1f296d34b600811ffe02931f604ea48a819f47d3a8e14')
        test = data | self.load('app12') | bytes
        self.assertTrue(test.startswith(b'Ducky'))
        test = data | self.load('scans/0') | self.ldu('sha256', text=True) | str
        self.assertEqual(test, '49480541d70cb44f59526555f7c81e67dd9df0918f4cfbba89f0046d518b4226')

    def _written_by_pillow(self, mode: str = 'RGB', **options) -> bytes:
        from PIL import Image
        image = Image.effect_mandelbrot((96, 64), (-2, -1.5, 1, 1.5), 50).convert(mode)
        output = io.BytesIO()
        image.save(output, 'JPEG', **options)
        return output.getvalue()

    def _pixels(self, data: bytes) -> bytes:
        from PIL import Image
        return Image.open(io.BytesIO(data)).tobytes()

    def _paths(self, data: bytes) -> list[str]:
        return data | self.load(list=True) | [str]

    def _streams(self, data: bytes) -> bytes:
        return B''.join(data | self.load('streams/*') | [bytes])

    def test_data_appended_after_the_image_is_extracted_as_the_overlay(self):
        image = self._written_by_pillow()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('payload.txt', 'hidden')
        data = image + archive.getvalue()
        self.assertEqual(self._paths(data), [*self._paths(image), 'overlay'])
        self.assertEqual(data | self.load('overlay') | bytes, archive.getvalue())
        self.assertEqual(self._streams(data), image)

    def test_an_image_appended_after_the_image_is_the_overlay(self):
        first = self._written_by_pillow()
        second = self._written_by_pillow('L')
        data = first + second
        self.assertEqual(data | self.load('overlay') | bytes, second)
        self.assertEqual(data | self.load('scans/*') | [bytes], first | self.load('scans/*') | [bytes])

    def test_restart_markers_are_part_of_the_data_of_their_scan(self):
        data = self._written_by_pillow(restart_marker_blocks=1)
        scans = data | self.load('scans/*') | [bytes]
        self.assertEqual(len(scans), 1)
        self.assertIn(B'\xFF\xD0', scans[0])
        self.assertFalse(any('RST' in path for path in self._paths(data)))
        self.assertEqual(self._streams(data), data)

    def _dimensions(self, data: bytes) -> tuple[int, int]:
        dimensions = json.loads(data | self.load('meta/dimensions.json') | str)
        return dimensions['width'], dimensions['height']

    def test_the_dimensions_of_an_image_are_its_width_and_height(self):
        self.assertEqual(self._dimensions(self._written_by_pillow()), (96, 64))

    def test_an_extended_sequential_frame_gives_the_dimensions_of_the_image(self):
        data = self._written_by_pillow(qtables=[[256] * 64, [256] * 64])
        self.assertTrue(any(path.endswith('.DCTExtendedSequential') for path in self._paths(data)))
        self.assertEqual(self._dimensions(data), (96, 64))

    @pytest.mark.xfail(strict=True, reason='an image cut inside its scan raises instead of giving the segments before the cut')
    def test_an_image_cut_inside_its_scan_gives_the_segments_before_the_cut(self):
        image = self._written_by_pillow(comment=b'kept')
        sos = image.index(B'\xFF\xDA')
        data = image[:(sos + len(image)) // 2]
        self.assertEqual(data | self.load('comments/0') | bytes, B'kept')

    def test_fill_bytes_in_front_of_a_marker_belong_to_that_marker(self):
        image = self._written_by_pillow()
        sos = image.index(B'\xFF\xDA')
        data = image[:sos] + B'\xFF\xFF\xFF' + image[sos:]
        self.assertEqual(self._pixels(data), self._pixels(image))
        self.assertEqual(self._paths(data), self._paths(image))
        self.assertEqual(self._streams(data), data)
