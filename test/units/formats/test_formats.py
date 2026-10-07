import gc
import lzma
import tracemalloc

from .. import TestUnitBase

from refinery.units.formats import PathPattern

_MALWARE_VHD = '2dd5a1f93e2a16e0c71ae12d211105e238239946269e1c095760b5fe24587a28'

#: The same 263 Python standard library sources (6 MB) in three archives: a CAB made with makecab,
#: and a 7z and a ZIP made with 7-Zip.
_STDLIB_ARCHIVES = {
    'xtcab': '36ef84b0a20d122e3d68c78f93dcf362639d09a68575b734e28c3b3855918ff2',
    'xt7z': '4950524235e3e594afe8b60ec3a7dc7ca9431b27e5c4bb728d166f403ef83131',
    'xtzip': 'dd8d2293bd1afa4a99ec161c150415ecd270f3b40e640cd556a19890e6c52c4d',
}


class TestFormats(TestUnitBase):

    def test_path_pattern_reach_check(self):
        T = self.assertTrue
        F = self.assertFalse

        F(PathPattern('foo/bar.exe').reach('/baz/bof'))
        T(PathPattern('foo-bar.exe').reach('/baz/bof'))
        T(PathPattern('???/bar.exe').reach('/baz/bof'))
        T(PathPattern('bof/bar.exe').reach('/baz/bof'))
        T(PathPattern('??f/bar.exe').reach('/baz/bof'))
        T(PathPattern('*of/bar.exe').reach('/baz/bof'))

        F(PathPattern('foo/*/bar.exe').reach('/baz/bof'))
        T(PathPattern('baz/*/bar.exe').reach('/baz/bof'))

    def test_path_pattern_reach_exclude(self):
        F = self.assertFalse
        paths = ['secret', 'public', 'secret/key', 'public/readme.txt', 'foo', 'foo/bar.exe']
        for query in ['secret', 'secret/*', 'foo/bar.exe', '*.dll']:
            pattern = PathPattern(query, exclude=True)
            for path in paths:
                F(pattern.reach(path), F'exclusion {query} claimed to reach {path}')

    def test_path_pattern_reach_regex(self):
        T = self.assertTrue
        F = self.assertFalse
        for query in ['foo', 'baz/bar']:
            include = PathPattern(query, regex=True)
            T(include.reach('/baz/bof'))
            self.assertEqual(repr(include), '<PathPattern:RE>')
            F(PathPattern(query, regex=True, exclude=True).reach('/baz/bof'))

    def test_path_pattern_negation(self):
        T = self.assertTrue
        F = self.assertFalse

        F(PathPattern('foo').exclude)
        T(PathPattern('foo').check('foo'))
        F(PathPattern('foo').check('bar'))

        T(PathPattern('foo', exclude=True).exclude)
        T(PathPattern('foo', exclude=True).check('foo'))
        F(PathPattern('foo', exclude=True).check('bar'))

        T(PathPattern('foo', regex=True, exclude=True).exclude)
        T(PathPattern('foo', regex=True, exclude=True).check('foo'))
        F(PathPattern('foo', regex=True, exclude=True).check('bar'))

    def test_path_pattern_reach_is_sound(self):
        cases = {
            'foo/bar.exe'     : ['foo/bar.exe', 'a/foo/bar.exe'],
            'baz/*/bar.exe'   : ['baz/x/bar.exe', 'baz/x/y/bar.exe'],
            '*.dll'           : ['a.dll', 'sub/b.dll', 'a/b/c.dll'],
        }
        for query, paths in cases.items():
            pattern = PathPattern(query)
            for path in paths:
                if not pattern.check(path):
                    continue
                parts = path.split('/')
                for k in range(1, len(parts)):
                    ancestor = '/'.join(parts[:k])
                    self.assertTrue(pattern.reach(ancestor),
                        F'{query} pruned {ancestor} but matches {path}')

    def test_extracted_files_are_freed_once_handed_out(self):
        data = lzma.decompress(self.download_sample(_MALWARE_VHD))
        unit = self.ldu('xtvhd')
        extracted = 0
        gc.collect()
        gc.disable()
        tracemalloc.start()
        try:
            start, _ = tracemalloc.get_traced_memory()
            held = start
            for chunk in data | unit:
                extracted += len(chunk)
                del chunk
                held, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            gc.enable()
        self.assertGreater(extracted, 0)
        self.assertLess(held - start - len(data), extracted // 8)

    def test_archive_keeps_no_file_after_handing_it_out(self):
        for name, sample in _STDLIB_ARCHIVES.items():
            with self.subTest(unit=name):
                data = self.download_sample(sample)
                unit = self.ldu(name)
                extracted = 0
                gc.collect()
                gc.disable()
                tracemalloc.start()
                try:
                    start, _ = tracemalloc.get_traced_memory()
                    held = start
                    for chunk in data | unit:
                        extracted += len(chunk)
                        del chunk
                        held = max(held, tracemalloc.get_traced_memory()[0])
                finally:
                    tracemalloc.stop()
                    gc.enable()
                self.assertGreater(extracted, 0)
                self.assertLess(held - start - len(data), extracted // 3)

    def test_extracted_file_is_freed_as_soon_as_it_is_dropped(self):
        data = lzma.decompress(self.download_sample(_MALWARE_VHD))
        unit = self.ldu('xtvhd')
        largest = 0
        held_after_largest = 0
        gc.collect()
        gc.disable()
        tracemalloc.start()
        try:
            start, _ = tracemalloc.get_traced_memory()
            for chunk in data | unit:
                size = len(chunk)
                del chunk
                held, _ = tracemalloc.get_traced_memory()
                if size > largest:
                    largest = size
                    held_after_largest = held - start - len(data)
        finally:
            tracemalloc.stop()
            gc.enable()
        self.assertGreater(largest, 0)
        self.assertLess(held_after_largest, largest // 8)
