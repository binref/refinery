#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import os
import io
import pyperclip
import tempfile
import time
import hashlib
import zlib

from contextlib import contextmanager

from .. import TestUnitBase
from refinery.lib.loader import load_detached as L


@contextmanager
def temporary_chwd(directory):
    old = os.getcwd()
    try:
        os.chdir(directory)
        yield directory
    finally:
        os.chdir(old)


class TestDump(TestUnitBase):

    def test_clipboard_copy_01(self):
        copy = self.load()
        L('emit Too Much Technology')[copy]()
        self.assertEqual(pyperclip.paste(), 'TooMuchTechnology')

    def test_clipboard_copy_02(self):
        copy = self.load()
        sep = self.ldu('sep', ' ')
        L('emit Too Much Technology')[sep | copy]()
        self.assertEqual(pyperclip.paste(), 'Too Much Technology')

    def test_clipboard_copy_multiple(self):
        copy = self.load()
        data = 'Too much technology, in too little time.'
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
                contents = result.read()
                self.assertEqual(contents, data)

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
                '00 00 00 00 00 00 00 00 00 00 00 00 C8 00 00 00'  # ................
                '0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68'  # ........!..L.!Th
                '69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'  # is.program.canno
                '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20'  # t.be.run.in.DOS.
                '6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'  # mode....$.......
                '43 63 F7 FD 07 02 99 AE 07 02 99 AE 07 02 99 AE'  # Cc..............
                '5C 6A 98 AF 02 02 99 AE 07 02 98 AE 04 02 99 AE'  # \j..............
                'C6 77 91 AF 06 02 99 AE C6 77 66 AE 06 02 99 AE'  # .w.......wf.....
                'C6 77 9B AF 06 02 99 AE 52 69 63 68 07 02 99 AE'  # .w......Rich....
                '00 00 00 00 00 00 00 00 50 45 00 00 4C 01 04 00'  # ........PE..L...
                '34 B1 D2 63 00 00 00 00 00 00 00 00 E0 00 02 01'  # 4..c............
                '0B 01 0E 1D 20 00 00 00 10 03 00 00 00 00 00 00'  # ................
                '60 02 00 00 60 02 00 00 80 02 00 00 00 00 40 00'  # `...`.........@.
                '10 00 00 00 10 00 00 00 06 00 00 00 00 00 00 00'  # ................
                '06 00 00 00 00 00 00 00 90 05 00 00 60 02 00 00'  # ............`...
                '00 00 00 00 03 00 40 85 00 00 10 00 00 10 00 00'  # ......@.........
                '00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 E4 03 00 00 3C 00 00 00'  # ............<...
                '80 04 00 00 F8 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 80 05 00 00 10 00 00 00'  # ................
                'B0 02 00 00 38 00 00 00 00 00 00 00 00 00 00 00'  # ....8...........
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '80 02 00 00 14 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 20 00 00 60 2E 72 64 61 74 61 00 00'  # .......`.rdata..
                'FC 01 00 00 80 02 00 00 00 02 00 00 80 02 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40'  # ............@..@
                '2E 72 73 72 63 00 00 00 F8 00 00 00 80 04 00 00'  # .rsrc...........
                '00 01 00 00 80 04 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 40 00 00 40 2E 72 65 6C 6F 63 00 00'  # ....@..@.reloc..
                '10 00 00 00 80 05 00 00 10 00 00 00 80 05 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42'  # ............@..B
                'FF 15 84 02 40 00 6A 40 68 94 02 40 00 50 6A 00'  # ....@.j@h..@.Pj.
                'FF 15 8C 02 40 00 6A 00 FF 15 80 02 40 00 CC 00'  # ....@.j.....@...
                '46 04 00 00 34 04 00 00 00 00 00 00 62 04 00 00'  # F...4.......b...
                '00 00 00 00 43 00 6F 00 6D 00 6D 00 61 00 6E 00'  # ....C.o.m.m.a.n.
                '64 00 20 00 4C 00 69 00 6E 00 65 00 00 00 00 00'  # d...L.i.n.e.....
                '00 00 00 00 34 B1 D2 63 00 00 00 00 0D 00 00 00'  # ....4..c........
                'E4 00 00 00 00 03 00 00 00 03 00 00 00 00 00 00'  # ................
                '34 B1 D2 63 00 00 00 00 0E 00 00 00 00 00 00 00'  # 4..c............
                '00 00 00 00 00 00 00 00 18 00 00 00 00 80 00 80'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '47 43 54 4C 60 02 00 00 1F 00 00 00 2E 74 65 78'  # GCTL`........tex
                '74 24 6D 6E 00 00 00 00 80 02 00 00 14 00 00 00'  # t$mn............
                '2E 69 64 61 74 61 24 35 00 00 00 00 94 02 00 00'  # .idata$5........
                '54 00 00 00 2E 72 64 61 74 61 00 00 E8 02 00 00'  # T....rdata......
                '18 00 00 00 2E 72 64 61 74 61 24 76 6F 6C 74 6D'  # .....rdata$voltm
                '64 00 00 00 00 03 00 00 E4 00 00 00 2E 72 64 61'  # d............rda
                '74 61 24 7A 7A 7A 64 62 67 00 00 00 E4 03 00 00'  # ta$zzzdbg.......
                '28 00 00 00 2E 69 64 61 74 61 24 32 00 00 00 00'  # (....idata$2....
                '0C 04 00 00 14 00 00 00 2E 69 64 61 74 61 24 33'  # .........idata$3
                '00 00 00 00 20 04 00 00 14 00 00 00 2E 69 64 61'  # .............ida
                '74 61 24 34 00 00 00 00 34 04 00 00 48 00 00 00'  # ta$4....4...H...
                '2E 69 64 61 74 61 24 36 00 00 00 00 80 04 00 00'  # .idata$6........
                '70 00 00 00 2E 72 73 72 63 24 30 31 00 00 00 00'  # p....rsrc$01....
                'F0 04 00 00 88 00 00 00 2E 72 73 72 63 24 30 32'  # .........rsrc$02
                '00 00 00 00 20 04 00 00 00 00 00 00 00 00 00 00'  # ................
                '54 04 00 00 80 02 00 00 2C 04 00 00 00 00 00 00'  # T.......,.......
                '00 00 00 00 70 04 00 00 8C 02 00 00 00 00 00 00'  # ....p...........
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '46 04 00 00 34 04 00 00 00 00 00 00 62 04 00 00'  # F...4.......b...
                '00 00 00 00 D7 01 47 65 74 43 6F 6D 6D 61 6E 64'  # ......GetCommand
                '4C 69 6E 65 57 00 5E 01 45 78 69 74 50 72 6F 63'  # LineW.^.ExitProc
                '65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C'  # ess.KERNEL32.dll
                '00 00 86 02 4D 65 73 73 61 67 65 42 6F 78 57 00'  # ....MessageBoxW.
                '55 53 45 52 33 32 2E 64 6C 6C 00 00 00 00 00 00'  # USER32.dll......
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00'  # ................
                '06 00 00 00 18 00 00 80 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 01 00 07 00 00 00 30 00 00 80'  # ............0...
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00'  # ................
                '07 00 00 00 50 00 00 00 09 04 00 00 60 00 00 00'  # ....P.......`...
                'F0 04 00 00 44 00 00 00 00 00 00 00 00 00 00 00'  # ....D...........
                '38 05 00 00 40 00 00 00 00 00 00 00 00 00 00 00'  # 8...@...........
                '00 00 00 00 00 00 00 00 00 00 12 00 42 00 69 00'  # ............B.i.
                '6E 00 E4 00 72 00 65 00 20 00 52 00 61 00 66 00'  # n...r.e...R.a.f.
                '66 00 69 00 6E 00 65 00 72 00 69 00 65 00 21 00'  # f.i.n.e.r.i.e.!.
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 10 00 42 00 69 00 6E 00 61 00 72 00 79 00'  # ....B.i.n.a.r.y.
                '20 00 52 00 65 00 66 00 69 00 6E 00 65 00 72 00'  # ..R.e.f.i.n.e.r.
                '79 00 21 00 00 00 00 00 00 00 00 00 00 00 00 00'  # y.!.............
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 10 00 00 00 62 32 69 32 72 32 7A 32'  # ........b2i2r2z2
            ),
        }

        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'test.{ext}')
            dump = self.load(path)
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
                crc32='{:08x}'.format(zlib.crc32(data) & 0xFFFFFFFF),
                md5=hashlib.md5(data).hexdigest()
            ) for index, data in enumerate(samples)
        ]
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'file-{index:02d}-{foobar}-{crc32}-{md5}.{ext}')
            dump = self.load(path)
            self.ldu('emit', *samples)[dump]()
            for filename, data in zip(filenames, samples):
                result_path = os.path.join(root, filename)
                self.assertTrue(os.path.exists(result_path), F'missing: {result_path}')
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
        listing = self.ldu('xtzip', list=True)
        self.assertEqual(listing(archive), B'\n'.join([
            B'foo/baf',
            B'foo/baz',
            B'bar/bok'
        ]))
        with tempfile.TemporaryDirectory() as root:
            paths = [
                os.path.join(root, 'foo', 'baz'),
                os.path.join(root, 'foo', 'baf'),
                os.path.join(root, 'bar', 'bok')
            ]
            with temporary_chwd(root) as root:
                dump = self.load('{path}')
                self.ldu('xtzip')[dump](archive)
                self.assertTrue(all(os.path.exists(p) for p in paths))
                for word in ('baz', 'baf'):
                    with open(os.path.join(root, 'foo', word), 'r') as stream:
                        self.assertEqual(stream.read(), word)
            for p in paths:
                os.unlink(p)
            os.rmdir(os.path.join(root, 'foo'))
            os.rmdir(os.path.join(root, 'bar'))
            time.sleep(.1)

    def test_force_mode(self):
        with tempfile.TemporaryDirectory() as root:
            with temporary_chwd(root) as root:
                dump = self.load('A', 'A/B', force=True)
                self.ldu('emit', 'A', 'B')[dump]()

                self.assertTrue(os.path.isdir(os.path.join(root, 'A')))
                self.assertTrue(os.path.exists(os.path.join(root, 'A', 'B')))
                with open(os.path.join(root, 'A', 'B'), 'r') as stream:
                    self.assertEqual(stream.read(), 'B')

    def test_duplicate_metavars(self):
        with tempfile.TemporaryDirectory() as root:
            with temporary_chwd(root) as root:
                dump = self.load('A{index}')
                pipeline = self.ldu('emit', 'data0', 'data1')[dump]
                pipeline()
                self.assertTrue(os.path.exists(os.path.join(root, 'A0')))
                self.assertTrue(os.path.exists(os.path.join(root, 'A1')))
                with open(os.path.join(root, 'A1'), 'r') as stream:
                    self.assertEqual(stream.read(), 'data1')

    def test_dump_listunroll(self):
        samples = [
            self.generate_random_buffer(124),
            self.generate_random_buffer(2049)
        ]
        filenames = ['F1', 'F2']
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'F{[1,2][index]}')
            dump = self.load(path)
            emit = self.ldu('emit', *samples)
            emit [ dump ] () # noqa
            for filename, data in zip(filenames, samples):
                result_path = os.path.join(root, filename)
                self.assertTrue(os.path.exists(result_path))
                with open(result_path, 'rb') as result:
                    self.assertEqual(result.read(), data)
