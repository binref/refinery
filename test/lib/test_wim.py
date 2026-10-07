import gc
import hashlib
import tracemalloc

from datetime import datetime, timezone
from unittest import mock

import pytest

from .. import TestBase

from refinery.lib.lnk.flags import FileAttributeFlags
from refinery.lib.lzms import lzms_decompress
from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.wim import (
    WimArchive,
    WimCompression,
    WimDecompressionError,
    WimHashMismatch,
    WimPartMissing,
    WimStreamKind,
    WimVersion,
    walk_image,
)

DATA = WimStreamKind.DATA
REPARSE = WimStreamKind.REPARSE

FIRST_OF_TWO_PARTS = 'b85f850c972b55807850e2eb6140ffd2ac276d20ede081842b759909fcab5234'
SECOND_OF_TWO_PARTS = '8bfe3fdebc1950dbd362b0203c59fa8d25fe064d48a59fef8480886c3d542f2c'
FIRST_OF_THREE_PARTS = 'c00add5959d58aeec7d6209d22573f5f32094632ef90ee5cf195595329222720'
SECOND_OF_THREE_PARTS = '1b62e77fa0d3520b5f27488e173007234c7b219ad749a395eb8ee0846f870fd8'
THIRD_OF_THREE_PARTS = 'c96142c64ec89036d1980a05d66424af3e4d806c5665c0c28c08cb023ba01de9'

DIRECTORY_ENTRY_ATTRIBUTES = 0x08
DIRECTORY_ENTRY_CHILDREN = 0x10
DIRECTORY_ENTRY_NAME = 0x66
HEADER_GUID = 0x18
HEADER_TOTAL_PARTS = 0x2A

TIMES_TABLE = '\n'.join(F'{a} x {b} = {a * b}' for a in range(1, 61) for b in range(1, 61)).encode()

FOLDER = {
    ((), '', DATA): B'',
    (('empty.bin',), '', DATA): B'',
    (('hello.txt',), '', DATA): B'Hello from a WIM image.\r\n',
    (('hello.txt',), 'secret', DATA): B'This text is hidden in an alternate data stream.\r\n',
    (('junction',), '', REPARSE): None,
    (('only_ads.txt',), '', DATA): B'',
    (('only_ads.txt',), 'payload', DATA): B'Only the alternate stream has content.\r\n',
    (('sub',), '', DATA): B'',
    (('sub',), 'dirstream', DATA): B'A stream on a directory.\r\n',
    (('sub', 'times.txt'), '', DATA): TIMES_TABLE,
    (('sub', 'ünïcødé.txt'), '', DATA): B'unicode name\r\n',
}

SUBFOLDER = {
    ((), '', DATA): B'',
    ((), 'dirstream', DATA): B'A stream on a directory.\r\n',
    (('times.txt',), '', DATA): TIMES_TABLE,
    (('ünïcødé.txt',), '', DATA): B'unicode name\r\n',
}


def streams(wim: WimArchive, image: int = 0):
    result = {}
    for entry in walk_image(wim.images[image].data()):
        for stream in entry.streams:
            key = entry.path, stream.name, stream.kind
            if stream.kind == REPARSE:
                result[key] = None
            elif not any(stream.hash):
                result[key] = B''
            elif (blob := wim.blobs.get(stream.hash)) is not None:
                result[key] = bytes(blob.data())
    return result


def entries(wim: WimArchive, image: int = 0):
    return list(walk_image(wim.images[image].data()))


def directory_entry(metadata: bytes | bytearray, name: str) -> int:
    return metadata.find(name.encode('utf-16le') + bytes(2)) - DIRECTORY_ENTRY_NAME


def live_lzx_decoders() -> int:
    gc.collect()
    return sum(isinstance(obj, LzxDecoder) for obj in gc.get_objects())


@pytest.mark.cythonized
class TestWimCapturesOfOneFolder(TestBase):
    """
    Each WIM file of these tests was captured with wimlib from the folder that `FOLDER` describes;
    the files differ in how they store the data. The junction in the folder points to `sub`.
    """

    def test_uncompressed(self):
        wim = WimArchive(self.download_sample('f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'))
        self.assertEqual(wim.header.compression, WimCompression.NONE)
        self.assertEqual(streams(wim), FOLDER)

    def test_xpress_in_chunks_of_4k(self):
        wim = WimArchive(self.download_sample('f57be775dffdd6758cf90065a83902a7c0ae1aefe6acbb94fe7810314a9611af'))
        self.assertEqual(wim.header.compression, WimCompression.XPRESS)
        self.assertEqual(wim.header.chunk_size, 0x1000)
        self.assertEqual(streams(wim), FOLDER)

    def test_lzx(self):
        wim = WimArchive(self.download_sample('4da6303a0a61a24d2ca12ae7348fc6de5573505aa451c7ca49cac9f964c3174f'))
        self.assertEqual(wim.header.compression, WimCompression.LZX)
        self.assertEqual(streams(wim), FOLDER)

    def test_lzms_in_chunks_of_32k(self):
        wim = WimArchive(self.download_sample('81cf3d5732adfa64d48d2d87fbfa7e37abaa7b18a3c93cda980ee22b253026b3'))
        self.assertEqual(wim.header.compression, WimCompression.LZMS)
        self.assertEqual(wim.header.chunk_size, 0x8000)
        self.assertEqual(streams(wim), FOLDER)

    def test_solid_lzms_in_chunks_of_32k(self):
        wim = WimArchive(self.download_sample('bc256467e8a453fd7ced99d297dbcbc13184d17f5cefd78dfe3fea99a8416b0b'))
        self.assertEqual(wim.header.version, WimVersion.SOLID)
        self.assertEqual(streams(wim), FOLDER)

    def test_second_image_captured_from_the_subfolder(self):
        wim = WimArchive(self.download_sample('4da6303a0a61a24d2ca12ae7348fc6de5573505aa451c7ca49cac9f964c3174f'))
        self.assertEqual(len(wim.images), 2)
        self.assertEqual(streams(wim, 1), SUBFOLDER)

    def test_junction_is_a_mount_point_whose_reparse_data_names_the_target(self):
        wim = WimArchive(self.download_sample('f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'))
        junction, = (entry for entry in entries(wim) if entry.path == ('junction',))
        self.assertEqual(junction.reparse_tag, 0xA0000003)
        reparse, = junction.streams
        self.assertEqual(reparse.kind, REPARSE)
        self.assertIn('sub'.encode('utf-16le'), bytes(wim.blobs[reparse.hash].data()))

    def test_last_write_time_as_listed_by_wimlib(self):
        wim = WimArchive(self.download_sample('f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'))
        hello, = (entry for entry in entries(wim) if entry.path == ('hello.txt',))
        write_time = hello.write_time or datetime.min
        self.assertEqual(write_time.replace(microsecond=0), datetime(2026, 9, 26, 21, 25, 30, tzinfo=timezone.utc))

    def test_lzx_resources_share_one_decoder(self):
        before = live_lzx_decoders()
        wim = WimArchive(self.download_sample('4da6303a0a61a24d2ca12ae7348fc6de5573505aa451c7ca49cac9f964c3174f'))
        for blob in [*wim.images, *wim.blobs.values()]:
            blob.data()
        self.assertEqual(live_lzx_decoders() - before, 1)

    def test_read_across_a_chunk_boundary_keeps_only_the_requested_bytes(self):
        wim = WimArchive(self.download_sample('f57be775dffdd6758cf90065a83902a7c0ae1aefe6acbb94fe7810314a9611af'))
        resource = wim.blobs[hashlib.sha1(TIMES_TABLE).digest()].resource
        data = resource.read(4000, 200)
        self.assertEqual(bytes(data), TIMES_TABLE[4000:4200])
        self.assertEqual(memoryview(memoryview(data).obj).nbytes, 200)

    def test_reading_a_file_of_many_chunks_keeps_one_copy_of_its_data(self):
        wim = WimArchive(self.download_sample('f57be775dffdd6758cf90065a83902a7c0ae1aefe6acbb94fe7810314a9611af'))
        blob = wim.blobs[hashlib.sha1(TIMES_TABLE).digest()]
        tracemalloc.start()
        try:
            data = blob.data()
            retained, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(bytes(data), TIMES_TABLE)
        self.assertLess(retained, 1.5 * len(TIMES_TABLE))

    def test_two_files_with_the_same_data_in_a_solid_resource_decompress_it_once(self):
        wim = WimArchive(self.download_sample('bc256467e8a453fd7ced99d297dbcbc13184d17f5cefd78dfe3fea99a8416b0b'))
        blob = wim.blobs[hashlib.sha1(TIMES_TABLE).digest()]
        first = blob.extractor()
        second = blob.extractor()
        with mock.patch('refinery.lib.wim.lzms_decompress', wraps=lzms_decompress) as decompress:
            self.assertEqual(bytes(first()), TIMES_TABLE)
            calls = decompress.call_count
            self.assertEqual(bytes(second()), TIMES_TABLE)
        self.assertGreater(calls, 0)
        self.assertEqual(decompress.call_count, calls)

    def test_out_of_memory_is_not_reported_as_a_corrupt_chunk(self):
        wim = WimArchive(self.download_sample('81cf3d5732adfa64d48d2d87fbfa7e37abaa7b18a3c93cda980ee22b253026b3'))
        blob = wim.blobs[hashlib.sha1(TIMES_TABLE).digest()]
        with mock.patch('refinery.lib.wim.lzms_decompress', side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                blob.data()
        self.assertEqual(bytes(blob.data()), TIMES_TABLE)

    def test_entry_reachable_from_two_directories_is_rejected(self):
        wim = WimArchive(self.download_sample('f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'))
        metadata = bytearray(wim.images[0].data())
        empty = directory_entry(metadata, 'empty.bin')
        unicode = directory_entry(metadata, 'ünïcødé.txt')
        children = empty + DIRECTORY_ENTRY_CHILDREN
        metadata[empty + DIRECTORY_ENTRY_ATTRIBUTES] |= FileAttributeFlags.Directory
        metadata[children:children + 8] = unicode.to_bytes(8, 'little')
        with self.assertRaises(ValueError):
            list(walk_image(metadata))

    def test_data_that_a_whole_wim_lacks_is_not_blamed_on_a_missing_part(self):
        wim = WimArchive(self.download_sample('f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'))
        self.assertEqual(wim.missing_parts, [])
        with self.assertRaises(LookupError) as context:
            wim.blob(hashlib.sha1(B'not stored').digest())
        self.assertNotIsInstance(context.exception, WimPartMissing)


@pytest.mark.cythonized
class TestWimSplitIntoTwoParts(TestBase):
    """
    The WIM file of `TestWimCapturesOfOneFolder.test_xpress_in_chunks_of_4k` was split with wimlib
    into two parts; the second part holds only the data of the largest file.
    """

    def test_first_part_lists_every_file_but_lacks_the_data_of_the_largest(self):
        wim = WimArchive(self.download_sample(FIRST_OF_TWO_PARTS))
        self.assertEqual((wim.header.part_number, wim.header.total_parts), (1, 2))
        listed = {(entry.path, stream.name, stream.kind) for entry in entries(wim) for stream in entry.streams}
        self.assertEqual(listed, set(FOLDER))
        self.assertNotIn(hashlib.sha1(TIMES_TABLE).digest(), wim.blobs)
        expected = dict(FOLDER)
        del expected[('sub', 'times.txt'), '', DATA]
        self.assertEqual(streams(wim), expected)

    def test_second_part_holds_the_data_of_the_largest_file_and_no_image(self):
        wim = WimArchive(self.download_sample(SECOND_OF_TWO_PARTS))
        self.assertEqual((wim.header.part_number, wim.header.total_parts), (2, 2))
        self.assertEqual(wim.images, [])
        self.assertEqual(bytes(wim.blobs[hashlib.sha1(TIMES_TABLE).digest()].data()), TIMES_TABLE)

    def test_both_parts_hold_every_file(self):
        wim = WimArchive(self.download_sample(FIRST_OF_TWO_PARTS), self.download_sample(SECOND_OF_TWO_PARTS))
        self.assertEqual(wim.missing_parts, [])
        self.assertEqual(streams(wim), FOLDER)

    def test_order_of_the_parts_does_not_matter(self):
        wim = WimArchive(self.download_sample(SECOND_OF_TWO_PARTS), self.download_sample(FIRST_OF_TWO_PARTS))
        self.assertEqual(streams(wim), FOLDER)

    def test_data_of_a_missing_part_names_that_part(self):
        wim = WimArchive(self.download_sample(FIRST_OF_TWO_PARTS))
        with self.assertRaises(WimPartMissing) as context:
            wim.blob(hashlib.sha1(TIMES_TABLE).digest())
        self.assertEqual(context.exception.missing, [2])

    def test_a_part_given_twice_is_rejected(self):
        first = self.download_sample(FIRST_OF_TWO_PARTS)
        with self.assertRaises(ValueError):
            WimArchive(first, first)


@pytest.mark.cythonized
class TestWimSplitIntoThreeParts(TestBase):
    """
    The WIM file of `TestWimCapturesOfOneFolder.test_lzx` was split with wimlib into three parts:
    the first part holds both images and no file data, the second part holds the data of every file
    except the largest, and the third part holds the data of the largest file.
    """

    def test_three_parts_hold_both_images(self):
        wim = WimArchive(
            self.download_sample(THIRD_OF_THREE_PARTS),
            self.download_sample(FIRST_OF_THREE_PARTS),
            self.download_sample(SECOND_OF_THREE_PARTS),
        )
        self.assertEqual(streams(wim), FOLDER)
        self.assertEqual(streams(wim, 1), SUBFOLDER)

    def test_missing_middle_part_loses_only_the_data_it_stores(self):
        wim = WimArchive(self.download_sample(FIRST_OF_THREE_PARTS), self.download_sample(THIRD_OF_THREE_PARTS))
        self.assertEqual(wim.missing_parts, [2])
        self.assertEqual(bytes(wim.blob(hashlib.sha1(TIMES_TABLE).digest()).data()), TIMES_TABLE)
        with self.assertRaises(WimPartMissing) as context:
            wim.blob(hashlib.sha1(B'unicode name\r\n').digest())
        self.assertEqual(context.exception.missing, [2])

    def test_parts_of_different_split_wims_are_rejected(self):
        with self.assertRaises(ValueError):
            WimArchive(self.download_sample(FIRST_OF_THREE_PARTS), self.download_sample(SECOND_OF_TWO_PARTS))

    def test_part_with_another_guid_is_rejected(self):
        second = self.download_sample(SECOND_OF_THREE_PARTS)
        second[HEADER_GUID] ^= 0xFF
        with self.assertRaises(ValueError):
            WimArchive(self.download_sample(FIRST_OF_THREE_PARTS), second)

    def test_forged_number_of_parts_names_every_run_of_missing_parts(self):
        first = self.download_sample(FIRST_OF_THREE_PARTS)
        third = self.download_sample(THIRD_OF_THREE_PARTS)
        for part in (first, third):
            part[HEADER_TOTAL_PARTS:HEADER_TOTAL_PARTS + 2] = (0xFFFF).to_bytes(2, 'little')
        with self.assertRaises(WimPartMissing) as context:
            WimArchive(first, third).blob(hashlib.sha1(B'unicode name\r\n').digest())
        self.assertEqual(context.exception.missing, [2, *range(4, 0x10000)])
        self.assertIn('parts 2, 4-65535', str(context.exception))


@pytest.mark.cythonized
class TestWimlibTestSuiteFiles(TestBase):
    """
    The WIM files of these tests are part of the test suite of wimlib, which is licensed under the
    GPLv3. The expected paths, sizes, and hashes are those that wimlib lists for them.
    """

    def test_file_whose_data_does_not_match_its_hash(self):
        wim = WimArchive(self.download_sample('881881069a0d17c1f4c96237af2230fa03adc3f6c6360871a38061638d4db4b5'))
        _, file = entries(wim)
        self.assertEqual(file.path, ('file',))
        stream, = file.streams
        with self.assertRaises(WimHashMismatch) as context:
            wim.blobs[stream.hash].data()
        self.assertEqual(len(context.exception.data), 12)

    def test_file_whose_data_fails_to_decompress(self):
        wim = WimArchive(self.download_sample('f90e6d6c45d96b294e6f5b673d97948b7cf65dc0f8a49f0cb7efb3442686b334'))
        _, file = entries(wim)
        stream, = file.streams
        with self.assertRaises(WimDecompressionError):
            wim.blobs[stream.hash].data()

    def test_chunk_that_fails_to_decompress_is_not_decompressed_again(self):
        wim = WimArchive(self.download_sample('f90e6d6c45d96b294e6f5b673d97948b7cf65dc0f8a49f0cb7efb3442686b334'))
        _, file = entries(wim)
        stream, = file.streams
        blob = wim.blobs[stream.hash]
        with self.assertRaises(WimDecompressionError) as first:
            blob.data()
        with self.assertRaises(WimDecompressionError) as second:
            blob.data()
        self.assertIs(second.exception.error, first.exception.error)

    def test_cyclic_directory_tree_is_rejected(self):
        wim = WimArchive(self.download_sample('4ce27c8422b4b1f32a3d02ae35fb87504ae71e640f2a812ab02c27bd8ba4d54b'))
        with self.assertRaises(ValueError):
            entries(wim)

    def test_path_through_dot_dot_is_not_listed(self):
        wim = WimArchive(self.download_sample('59b2c65b18d97617511d85547de93c15046509669a3b64e2b61448c690aaafae'))
        self.assertEqual([entry.path for entry in entries(wim)], [()])

    def test_every_file_with_a_duplicate_name_is_listed(self):
        wim = WimArchive(self.download_sample('12c78400902e78713ad0b2032b7422acfa1a0e2617034a176012d38be39ac238'))
        _, first, *others = entries(wim)
        self.assertEqual([entry.path for entry in (first, *others)], [('1',), ('1',), ('1',)])
        stream, = first.streams
        self.assertEqual(bytes(wim.blobs[stream.hash].data()), B'1\n')

    def test_file_after_a_security_descriptor_with_an_empty_access_list(self):
        wim = WimArchive(self.download_sample('442e1ad8e2e48cc374d0b5c73c05192067ebbace81a255230dd92c35a170fd2b'))
        self.assertEqual(streams(wim), {
            ((), '', DATA): B'',
            (('file',), '', DATA): B'1\n',
        })

    def test_file_with_linux_extended_attributes_in_the_old_format(self):
        wim = WimArchive(self.download_sample('450a3e285fd38dede3768524469ed17c6394b4467667767bc0c44b8bf19403fa'))
        self.assertEqual(streams(wim), {
            ((), '', DATA): B'',
            (('file',), '', DATA): B'',
        })

    def test_paths_longer_than_the_windows_limit(self):
        wim = WimArchive(self.download_sample('5b07128c6fc36c1e19746b9feba8d54f7dd34ae954e3c55e1468c41fd9db276a'))
        listed = entries(wim)
        self.assertEqual(len(listed), 204)
        self.assertEqual(max(len('/'.join(entry.path)) + 1 for entry in listed), 584)

    def test_hard_links_share_their_group_and_data(self):
        wim = WimArchive(self.download_sample('5b07128c6fc36c1e19746b9feba8d54f7dd34ae954e3c55e1468c41fd9db276a'))
        links = [entry for entry in entries(wim) if entry.path in (('link',), ('5link',))]
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0].hard_link_group, links[1].hard_link_group)
        for link in links:
            stream, = link.streams
            self.assertEqual(bytes(wim.blobs[stream.hash].data()), B'5\n')

