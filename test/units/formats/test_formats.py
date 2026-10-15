from __future__ import annotations

import gc
import lzma
import time
import tracemalloc
import unittest

from .. import TestUnitBase

from refinery.lib.types import Callable, buf
from refinery.units.formats import PathExtractorUnit, PathPattern, UnpackResult

_MALWARE_VHD = '2dd5a1f93e2a16e0c71ae12d211105e238239946269e1c095760b5fe24587a28'

#: The same 263 Python standard library sources (6 MB) in three archives: a CAB made with makecab,
#: and a 7z and a ZIP made with 7-Zip.
_STDLIB_ARCHIVES = {
    'xtcab': '36ef84b0a20d122e3d68c78f93dcf362639d09a68575b734e28c3b3855918ff2',
    'xt7z': '4950524235e3e594afe8b60ec3a7dc7ca9431b27e5c4bb728d166f403ef83131',
    'xtzip': 'dd8d2293bd1afa4a99ec161c150415ecd270f3b40e640cd556a19890e6c52c4d',
}

#: The same sources in one solid 7z, made with the defaults of 7-Zip.
_STDLIB_SOLID_7Z = 'bac77b8b93f397e64a428e035b7453d0a9c115eca53ded2560b17bf237b8d573'


def _container(*entries: tuple[str, buf | Callable[[], buf]]) -> type[PathExtractorUnit]:
    """
    An extractor for a container that lists the given entries in the given order.
    """
    class xtlisted(PathExtractorUnit):
        def unpack(self, data):
            for path, content in entries:
                yield UnpackResult(path, content)
    return xtlisted


def _extract(unit: PathExtractorUnit) -> list[tuple[str, bytes]]:
    return [(str(chunk['path']), bytes(chunk)) for chunk in B'' | unit | [...]]


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

    def _assert_archive_keeps_no_file_after_handing_it_out(self, name: str, sample: str):
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

    def test_archive_keeps_no_file_after_handing_it_out(self):
        for name, sample in _STDLIB_ARCHIVES.items():
            with self.subTest(unit=name):
                self._assert_archive_keeps_no_file_after_handing_it_out(name, sample)

    @unittest.expectedFailure
    def test_solid_7z_keeps_no_file_after_handing_it_out(self):
        """
        A solid 7z folder is decompressed as one piece, which every file of the folder refers to,
        so the folder is kept until its last file is read.
        """
        self._assert_archive_keeps_no_file_after_handing_it_out('xt7z', _STDLIB_SOLID_7Z)

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


class TestRepeatedPaths(TestUnitBase):

    def test_every_copy_of_a_repeated_path_is_numbered_in_the_order_of_the_container(self):
        xt = _container(
            ('a.txt', B'abc'),
            ('b.txt', B'other'),
            ('a.txt', B'abc'),
            ('a.txt', B'xyz'),
        )
        self.assertEqual(_extract(xt()), [
            ('a.txt/1', B'abc'),
            ('b.txt', B'other'),
            ('a.txt/2', B'abc'),
            ('a.txt/3', B'xyz'),
        ])

    def test_listing_reads_no_file_whose_path_repeats(self):
        reads = []

        def content(data: bytes):
            def read():
                reads.append(data)
                return data
            return read

        xt = _container(('a.txt', content(B'one')), ('a.txt', content(B'two')))
        self.assertEqual([str(path) for path in B'' | xt(list=True)], ['a.txt/1', 'a.txt/2'])
        self.assertEqual(reads, [])

    def test_a_numbered_copy_does_not_take_the_path_of_another_file(self):
        xt = _container(
            ('a.txt', B'first'),
            ('a.txt', B'second'),
            ('a.txt/2', B'real'),
        )
        self.assertEqual(_extract(xt()), [
            ('a.txt/1', B'first'),
            ('a.txt/3', B'second'),
            ('a.txt/2', B'real'),
        ])

    def test_no_two_outputs_share_a_path_when_numbered_paths_repeat_as_well(self):
        xt = _container(
            ('a', B'a'),
            ('a', B'a'),
            ('a/1', B'a/1'),
            ('a/1', B'a/1'),
            ('a/2', B'real a/2'),
            ('a/1/1', B'real a/1/1'),
        )
        output = _extract(xt())
        paths = [path for path, _ in output]
        self.assertEqual(len(set(paths)), 6)
        self.assertIn(('a/2', B'real a/2'), output)
        self.assertIn(('a/1/1', B'real a/1/1'), output)

    def test_the_name_of_a_repeated_path_selects_every_copy_and_nothing_else(self):
        xt = _container(
            ('a.txt', B'first'),
            ('sub/a.txt', B'nested'),
            ('xa.txt', B'other'),
            ('a.txt', B'second'),
        )
        for exact in (False, True):
            with self.subTest(exact=exact):
                self.assertEqual(_extract(xt('a.txt', exact=exact)), [
                    ('a.txt/1', B'first'),
                    ('a.txt/2', B'second'),
                ])

    def test_a_wildcard_selects_every_copy_of_a_repeated_path(self):
        xt = _container(
            ('readme.exe', B'decoy'),
            ('payload.exe', B'MZ'),
            ('payload.exe', B'MZ'),
        )
        self.assertEqual(_extract(xt('*.exe')), [
            ('readme.exe', B'decoy'),
            ('payload.exe/1', B'MZ'),
            ('payload.exe/2', B'MZ'),
        ])

    def test_an_exclusion_excludes_every_copy_of_a_repeated_path(self):
        xt = _container(
            ('readme.txt', B'text'),
            ('payload.exe', B'MZ'),
            ('payload.exe', B'MZ'),
        )
        for query in ('*.exe', 'payload.exe'):
            with self.subTest(query=query):
                self.assertEqual(_extract(xt(exclude=[query])), [('readme.txt', B'text')])

    def test_a_numbered_path_selects_only_that_copy(self):
        xt = _container(('a.txt', B'first'), ('a.txt', B'second'))
        self.assertEqual(_extract(xt('a.txt/2')), [('a.txt/2', B'second')])

    def test_the_name_of_a_repeated_path_selects_its_copies_in_any_case(self):
        xt = _container(('a.txt', B'first'), ('a.txt', B'second'))
        self.assertEqual(_extract(xt('A.TXT')), [('a.txt/1', B'first'), ('a.txt/2', B'second')])

    def test_a_path_that_differs_only_in_case_from_a_repeated_path_selects_only_itself(self):
        xt = _container(
            ('A.txt', B'upper'),
            ('a.txt', B'first'),
            ('a.txt', B'second'),
        )
        self.assertEqual(_extract(xt('A.txt')), [('A.txt', B'upper')])
        self.assertEqual(_extract(xt('a.txt')), [('a.txt/1', B'first'), ('a.txt/2', B'second')])

    def test_many_copies_of_a_path_whose_numbers_are_taken_are_named_quickly(self):
        count = 10_000
        copies = [('a.txt', B'') for _ in range(count)]
        numbered = [(F'a.txt/{k}', B'') for k in range(1, count + 1)]
        xt = _container(*copies, *numbered)
        start = time.perf_counter()
        listing = [str(path) for path in B'' | xt(list=True)]
        self.assertLess(time.perf_counter() - start, 5)
        self.assertEqual(len(set(listing)), 2 * count)
