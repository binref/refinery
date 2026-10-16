import io
import json
import time
import zipfile

from unittest.mock import patch

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

    def _scan_offset(self, image: bytes) -> int:
        sos = image.index(B'\xFF\xDA')
        return sos + 2 + int.from_bytes(image[sos + 2:sos + 4], 'big')

    def _warnings(self, data: bytes) -> list[str]:
        unit = self.load()
        with patch.object(unit, 'log_warn') as log_warn:
            list(data | unit)
        return [call.args[0] for call in log_warn.call_args_list]

    def test_an_image_cut_inside_its_scan_gives_the_segments_before_the_cut(self):
        image = self._written_by_pillow(comment=b'kept')
        sos = image.index(B'\xFF\xDA')
        data = image[:(sos + len(image)) // 2]
        self.assertEqual(data | self.load('comments/0') | bytes, B'kept')

    def test_the_scan_of_an_image_cut_inside_it_runs_to_the_cut(self):
        image = self._written_by_pillow()
        scan = self._scan_offset(image)
        data = image[:(scan + len(image)) // 2]
        self.assertEqual(data | self.load('scans/0') | bytes, data[scan:])
        self.assertEqual(self._streams(data), data)

    def test_an_image_cut_between_the_two_bytes_of_an_escaped_ff_keeps_that_ff_in_its_scan(self):
        image = self._written_by_pillow()
        scan = self._scan_offset(image)
        data = image[:image.index(B'\xFF\x00', scan) + 1]
        self.assertEqual(data | self.load('scans/0') | bytes, data[scan:])
        self.assertNotIn('junk/0', self._paths(data))

    def test_a_segment_cut_by_the_end_of_the_data_gives_the_bytes_in_front_of_the_cut(self):
        image = self._written_by_pillow(comment=b'kept and cut')
        data = image[:image.index(B'kept and cut') + 4]
        self.assertEqual(data | self.load('comments/0') | bytes, B'kept')

    def test_an_image_cut_inside_its_frame_header_has_no_dimensions(self):
        image = self._written_by_pillow()
        data = image[:image.index(B'\xFF\xC0') + 6]
        paths = self._paths(data)
        self.assertNotIn('meta/dimensions.json', paths)
        self.assertIn('meta/0.app00.jfif', paths)

    def test_an_image_cut_inside_the_length_of_a_segment_gives_the_rest_as_junk(self):
        image = self._written_by_pillow(comment=b'cut')
        com = image.index(B'\xFF\xFE')
        data = image[:com + 3]
        self.assertEqual(data | self.load('junk/0') | bytes, data[com:])
        self.assertNotIn('comments/0', self._paths(data))

    def test_bytes_between_segments_that_belong_to_none_are_junk_and_leave_the_image_intact(self):
        image = self._written_by_pillow()
        sos = image.index(B'\xFF\xDA')
        for junk in (B'junk', B'\xFF\x00', B'\xFF\xFF\x00'):
            data = image[:sos] + junk + image[sos:]
            self.assertEqual(self._pixels(data), self._pixels(image), junk)
            self.assertEqual(self._paths(data), [*self._paths(image), 'junk/0'], junk)
            self.assertEqual(data | self.load('junk/0') | bytes, junk)
            self.assertEqual(self._streams(data), image, junk)

    def test_data_in_front_of_the_start_of_the_image_is_refused(self):
        image = self._written_by_pillow()
        with self.assertRaises(ValueError):
            self._paths(B'junk' + image)

    def test_a_long_run_of_ff_bytes_does_not_stall_the_parser(self):
        image = self._written_by_pillow()
        run = B'\xFF' * (1 << 17) + B'\x00'
        sos = image.index(B'\xFF\xDA')
        scan = self._scan_offset(image)
        for name, data, junk, scans in (
            ('between segments', image[:sos] + run + image[sos:], [run], [image[scan:-2]]),
            ('inside the scan', image[:scan] + run + image[scan:], [], [run + image[scan:-2]]),
        ):
            start = time.perf_counter()
            self.assertEqual(data | self.load('junk/*') | [bytes], junk, name)
            self.assertEqual(data | self.load('scans/*') | [bytes], scans, name)
            self.assertLess(time.perf_counter() - start, 5, name)

    def test_a_complete_image_gives_no_warning(self):
        self.assertEqual(self._warnings(self._written_by_pillow()), [])

    def test_a_truncated_image_is_warned_about(self):
        image = self._written_by_pillow()
        self.assertEqual(self._warnings(image[:-2]), ['the data ends before the end of the image'])

    def test_junk_is_warned_about(self):
        image = self._written_by_pillow()
        sos = image.index(B'\xFF\xDA')
        data = image[:sos] + B'junk' + image[sos:]
        self.assertEqual(self._warnings(data), ['the image contains data that belongs to none of its segments'])

    def test_fill_bytes_in_front_of_a_marker_belong_to_that_marker(self):
        image = self._written_by_pillow()
        sos = image.index(B'\xFF\xDA')
        data = image[:sos] + B'\xFF\xFF\xFF' + image[sos:]
        self.assertEqual(self._pixels(data), self._pixels(image))
        self.assertEqual(self._paths(data), self._paths(image))
        self.assertEqual(self._streams(data), data)
