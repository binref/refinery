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

from .. import TestUnitBase
from refinery.lib.loader import load_commandline as L


@contextmanager
def temporary_clipboard():
    backup = pyperclip.paste()
    pyperclip.copy('')
    try:
        yield None
    finally:
        pyperclip.copy(backup)


@contextmanager
def temporary_chwd(directory):
    old = os.getcwd()
    try:
        os.chdir(directory)
        yield directory
    finally:
        os.chdir(old)


class TestDump(TestUnitBase):

    def test_clipboard_copy(self):
        copy = self.load()
        with temporary_clipboard():
            L('emit Too much technology')[copy]()
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
                list(stream | L('chop 32')[dump])
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
            self.ldu('emit', *examples.values())[dump]()
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
            self.ldu('emit', *samples)[dump]()
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
            self.ldu('emit', *words)[dump]()
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
            result = self.ldu('emit', *samples)[dump]()
            self.assertEqual(result, samples[~0])
            self.assertTrue(os.path.exists(p1))
            self.assertTrue(os.path.exists(p2))

    def test_automatic_naming(self):
        archive = bytes.fromhex(
            '50 4B 03 04 14 00 00 00 00 00 DB 98 57 50 00 00'  # PK..........WP..
            '00 00 00 00 00 00 00 00 00 00 04 00 00 00 66 6F'  # ..............fo
            '6F 2F 50 4B 03 04 0A 00 00 00 00 00 DB 98 57 50'  # o/PK..........WP
            'D7 58 25 6C 03 00 00 00 03 00 00 00 07 00 00 00'  # .X%l............
            '66 6F 6F 2F 62 61 66 62 61 66 50 4B 03 04 0A 00'  # foo/bafbafPK....
            '00 00 00 00 DA 98 57 50 98 04 24 78 03 00 00 00'  # ......WP..$x....
            '03 00 00 00 07 00 00 00 66 6F 6F 2F 62 61 7A 62'  # ........foo/bazb
            '61 7A 50 4B 03 04 14 00 00 00 00 00 E4 98 57 50'  # azPK..........WP
            '00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00'  # ................
            '62 61 72 2F 50 4B 03 04 0A 00 00 00 00 00 E4 98'  # bar/PK..........
            '57 50 E4 09 17 8C 03 00 00 00 03 00 00 00 07 00'  # WP..............
            '00 00 62 61 72 2F 62 6F 6B 62 6F 6B 50 4B 01 02'  # ..bar/bokbokPK..
            '3F 00 14 00 00 00 00 00 DB 98 57 50 00 00 00 00'  # ?.........WP....
            '00 00 00 00 00 00 00 00 04 00 24 00 00 00 00 00'  # ..........$.....
            '00 00 10 00 00 00 00 00 00 00 66 6F 6F 2F 0A 00'  # ..........foo/..
            '20 00 00 00 00 00 01 00 18 00 A0 E7 09 07 74 EA'  # ..............t.
            'D5 01 A0 E7 09 07 74 EA D5 01 28 9E A0 FA 73 EA'  # ......t...(...s.
            'D5 01 50 4B 01 02 3F 00 0A 00 00 00 00 00 DB 98'  # ..PK..?.........
            '57 50 D7 58 25 6C 03 00 00 00 03 00 00 00 07 00'  # WP.X%l..........
            '24 00 00 00 00 00 00 00 20 00 00 00 22 00 00 00'  # $..........."...
            '66 6F 6F 2F 62 61 66 0A 00 20 00 00 00 00 00 01'  # foo/baf.........
            '00 18 00 3C 23 09 07 74 EA D5 01 3C 23 09 07 74'  # ...<#..t...<#..t
            'EA D5 01 54 70 A4 03 74 EA D5 01 50 4B 01 02 3F'  # ...Tp..t...PK..?
            '00 0A 00 00 00 00 00 DA 98 57 50 98 04 24 78 03'  # .........WP..$x.
            '00 00 00 03 00 00 00 07 00 24 00 00 00 00 00 00'  # .........$......
            '00 20 00 00 00 4A 00 00 00 66 6F 6F 2F 62 61 7A'  # .....J...foo/baz
            '0A 00 20 00 00 00 00 00 01 00 18 00 A3 13 7F 05'  # ................
            '74 EA D5 01 A3 13 7F 05 74 EA D5 01 59 92 91 02'  # t.......t...Y...
            '74 EA D5 01 50 4B 01 02 3F 00 14 00 00 00 00 00'  # t...PK..?.......
            'E4 98 57 50 00 00 00 00 00 00 00 00 00 00 00 00'  # ..WP............
            '04 00 24 00 00 00 00 00 00 00 10 00 00 00 72 00'  # ..$...........r.
            '00 00 62 61 72 2F 0A 00 20 00 00 00 00 00 01 00'  # ..bar/..........
            '18 00 42 FF 11 0F 74 EA D5 01 42 FF 11 0F 74 EA'  # ..B...t...B...t.
            'D5 01 C0 5A 8A FB 73 EA D5 01 50 4B 01 02 3F 00'  # ...Z..s...PK..?.
            '0A 00 00 00 00 00 E4 98 57 50 E4 09 17 8C 03 00'  # ........WP......
            '00 00 03 00 00 00 07 00 24 00 00 00 00 00 00 00'  # ........$.......
            '20 00 00 00 94 00 00 00 62 61 72 2F 62 6F 6B 0A'  # ........bar/bok.
            '00 20 00 00 00 00 00 01 00 18 00 BD 2D 11 0F 74'  # ............-..t
            'EA D5 01 BD 2D 11 0F 74 EA D5 01 DC 17 59 0C 74'  # ....-..t.....Y.t
            'EA D5 01 50 4B 05 06 00 00 00 00 05 00 05 00 B7'  # ...PK...........
            '01 00 00 BC 00 00 00 00 00'                       # .........
        )
        with tempfile.TemporaryDirectory() as root:
            with temporary_chwd(root) as root:
                dump = self.load(meta=True)
                self.ldu('xtzip')[dump](archive)

                self.assertTrue(os.path.exists(os.path.join(root, 'foo', 'baz')))
                self.assertTrue(os.path.exists(os.path.join(root, 'foo', 'baf')))
                self.assertTrue(os.path.exists(os.path.join(root, 'bar', 'bok')))

                for word in ('baz', 'baf'):
                    with open(os.path.join(root, 'foo', word), 'r') as stream:
                        self.assertEqual(stream.read(), word)
