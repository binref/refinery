#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import os
import io
import pyperclip
import tempfile
import hashlib
import zlib

from contextlib import contextmanager
from refinery import emit, chop

from .. import TestUnitBase


@contextmanager
def temporary_clipboard():
    backup = pyperclip.paste()
    pyperclip.copy('')
    try:
        yield None
    finally:
        pyperclip.copy(backup)


class TestDump(TestUnitBase):

    def test_clipboard_copy(self):
        copy = self.load()
        with temporary_clipboard():
            emit('Too', 'much', 'technology')[copy]()
            self.assertEqual(pyperclip.paste(), 'Too')

    def test_clipboard_copy_multiple(self):
        copy = self.load()
        data = 'Too much technology, in too little time.'
        with temporary_clipboard():
            copy(data.encode(copy.codec))
            self.assertEqual(pyperclip.paste(), data)

    def test_stream_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'test')
            dump = self.load(path, stream=True)
            data = self.generate_random_buffer(1024)
            with io.BytesIO(data) as stream:
                list(stream | chop(32)[dump])
            self.assertTrue(os.path.exists(path))
            with open(path, 'rb') as result:
                self.assertEqual(result.read(), data)

    def test_invalid_arguments(self):
        with self.assertRaises(ValueError):
            self.load('foo', 'bar', stream=True)

    def test_auto_extension(self):
        examples = {
            'test.txt': B'\n'.join([
                B'var r = new XMLHttpRequest();'
                B'r.open("POST", "path/to/api", true);'
                B'r.onreadystatechange = function () {'
                B'  if (r.readyState != 4 || r.status != 200) return;'
                B'  alert("Success: " + r.responseText);'
                B'};'
                B'r.send("banana=yellow");'
            ]),
            'test.pdf': zlib.decompress(base64.b64decode(
                'eNptUsFO4zAQvVvyPwyHSnAgtpukpRJCKtBuJbqkanxZbRAy1C2BkqDYRbv79YydRGm7WLJlv3me9zzj'
                '3uJ2ei4CQYkADuXTKyWXl0AJMPn3QwO7UVZty40DFmqjDfSRtqTk6ooSXaz8BUr6R3fv8pWB3xA6Ljw4'
                '5KbcFRbEXuY63XGmsMt0SK2TFFYX1kBUmwA2HoMnAkuaDbApnGY4xKgfiMFF0I8DkWVWG5tl63yrz2rW'
                'LfrjSM6tN4hICuxHKcuJOzlT9YLiFWq27wa21KbcVc/ovVGeoqtOXLTb1rwLN0C6e7IecxHRgNfKaJ+C'
                'zfT2U9v8WfmIV++MHJYpOir4XBcb+wKC85pJibGVVu+UXEtKmBSPHIsv19hmdxUPEZIDzjkM4zAYDQcg'
                'kYwItLPCpp8mSbJIT+AXvhju5fwnzMbpDF6UgdedsTDX6k2vggDOQKKZifQeW+nO7p9KozSHGJduwCCO'
                'wxjWe6BAbR8q9sDhN6CIov/BKBx1ICW2Utjvqv1Ly7J0P7BpY5r/0xDV1TJWVbb2OBCI9XqTZPoFx5+0'
                'nw=='
            )),
            'test.tar.gz': bytes.fromhex(
                '1F 8B 08 00 41 9A 18 5E 00 03 ED CF 41 0A 80 30'
                '0C 04 C0 3C 25 2F 90 B4 A5 F1 01 7D 49 95 8A 82'
                '50 B0 11 7C BE F5 DA AB 28 28 99 CB DE 96 DD 29'
                'E7 4E 0E 81 27 11 11 33 E3 95 55 9B 95 65 34 8E'
                '89 8D F1 D4 5B 24 43 DE 3B 40 82 17 EC 45 E2 56'
                'A7 DC ED 69 CF 7D 44 C8 63 C4 90 D7 88 4B 41 99'
                '13 0E A9 48 07 4A 29 A5 7E 0D E0 04 5A 5F 99 D8'
                '00 08 00 00'
            ),
            'test.exe': bytes.fromhex(
                '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00'  # MZ..............
                'B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00'  # ........@.......
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00'  # ................
                '0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68'  # ........!..L.!Th
                '69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'  # is.program.canno
                '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20'  # t.be.run.in.DOS.
                '6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'  # mode....$.......
            ),
        }

        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'test.{ext}')
            dump = self.load(path, format=True)
            emit(*examples.values())[dump]()
            files = set(os.listdir(root))
            self.assertLessEqual(set(examples), files)
            for filename, data in examples.items():
                with open(os.path.join(root, filename), 'rb') as result:
                    self.assertEqual(result.read(), data)

    def test_dump_to_single_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'foo', 'bar')
            self.load(path)(b'Waffles')
            self.assertTrue(os.path.exists(path))
            with open(path, 'rb') as result:
                self.assertEqual(result.read(), b'Waffles')

    def test_dump_formatted(self):
        samples = [
            self.generate_random_buffer(124),
            self.generate_random_buffer(20128),
            self.generate_random_buffer(2049)
        ]
        filenames = [
            'file-{index:02d}-{{foobar}}-{crc32}-{md5}.bin'.format(
                index=index,
                crc32='{:08X}'.format(zlib.crc32(data) & 0xFFFFFFFF),
                md5=hashlib.md5(data).hexdigest()
            ) for index, data in enumerate(samples, 1)
        ]
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'file-{index:02d}-{foobar}-{crc32}-{md5}.{ext}')
            dump = self.load(path, format=True)
            emit(*samples)[dump]()
            for filename, data in zip(filenames, samples):
                result_path = os.path.join(root, filename)
                self.assertTrue(os.path.exists(result_path))
                with open(result_path, 'rb') as result:
                    self.assertEqual(result.read(), data)

    def test_dump_multiple(self):
        with tempfile.TemporaryDirectory() as root:
            words = ['coca', 'cola', 'code']
            paths = [os.path.join(root, word) for word in words]
            dump = self.load(*paths)
            emit(*words)[dump]()
            for word, path in zip(words, paths):
                self.assertTrue(os.path.exists(path))
                with open(path, 'r') as result:
                    self.assertEqual(result.read(), word)

    def test_forward_remaining_data(self):
        samples = [
            self.generate_random_buffer(124),
            self.generate_random_buffer(20128),
            self.generate_random_buffer(2049)
        ]
        with tempfile.TemporaryDirectory() as root:
            p1 = os.path.join(root, 'F1')
            p2 = os.path.join(root, 'F2')
            dump = self.load(p1, p2)
            result = emit(*samples)[dump]()
            self.assertEqual(result, samples[~0])
            self.assertTrue(os.path.exists(p1))
            self.assertTrue(os.path.exists(p2))
