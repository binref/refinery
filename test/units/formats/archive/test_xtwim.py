import hashlib
import unittest

from typing import Callable

import pytest

from refinery.lib.lnk.flags import FileAttributeFlags
from refinery.lib.wim import WimArchive
from refinery.units import Chunk
from refinery.units.formats.archive.xtwim import xtwim

from ... import TestUnitBase

UNCOMPRESSED = 'f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'
XPRESS = 'f57be775dffdd6758cf90065a83902a7c0ae1aefe6acbb94fe7810314a9611af'
LZX_WITH_TWO_IMAGES = '4da6303a0a61a24d2ca12ae7348fc6de5573505aa451c7ca49cac9f964c3174f'
SPLIT2_1ST = 'b85f850c972b55807850e2eb6140ffd2ac276d20ede081842b759909fcab5234'
SPLIT2_2ND = '8bfe3fdebc1950dbd362b0203c59fa8d25fe064d48a59fef8480886c3d542f2c'
SPLIT3_1ST = 'c00add5959d58aeec7d6209d22573f5f32094632ef90ee5cf195595329222720'
SPLIT3_2ND = '1b62e77fa0d3520b5f27488e173007234c7b219ad749a395eb8ee0846f870fd8'
SPLIT3_3RD = 'c96142c64ec89036d1980a05d66424af3e4d806c5665c0c28c08cb023ba01de9'

HEADER_SIZE = 208

DIRECTORY_ENTRY_ATTRIBUTES = 0x08
DIRECTORY_ENTRY_HASH = 0x40
DIRECTORY_ENTRY_NAME = 0x66


def directory_entry(metadata: bytes | bytearray, name: str) -> int:
    return metadata.find(name.encode('utf-16le') + bytes(2)) - DIRECTORY_ENTRY_NAME


def with_modified_metadata(data: bytearray, modify: Callable[[bytearray], None]) -> bytearray:
    """
    Modify the metadata of the first image of an uncompressed WIM file and store the new SHA-1
    hash of the metadata in the blob table.
    """
    image = WimArchive(data).images[0]
    start = image.resource.offset
    end = start + image.size
    metadata = data[start:end]
    modify(metadata)
    data[start:end] = metadata
    return data.replace(image.hash, hashlib.sha1(metadata).digest())


@pytest.mark.cythonized
class TestWimExtractor(TestUnitBase):
    """
    The WIM files of these tests were captured with wimlib; `test.lib.test_wim` describes what they
    contain.
    """

    def _items(self, *frame: bytes | bytearray) -> list[tuple[str, bytes]]:
        return sorted((str(chunk.meta['path']), bytes(chunk)) for chunk in list(frame) | self.load() | [...])

    def _listing_with_empty_file_renamed(self, name: str) -> list[str]:
        def rename(metadata: bytearray):
            empty = directory_entry(metadata, 'empty.bin') + DIRECTORY_ENTRY_NAME
            metadata[empty:empty + 2 * len(name)] = name.encode('utf-16le')
        assert len(name) == len('empty.bin')
        data = with_modified_metadata(bytearray(self.download_sample(UNCOMPRESSED)), rename)
        return data | self.load(list=True) | [str]

    def test_corrupt_second_image_does_not_hide_the_first(self):
        data = bytearray(self.download_sample(LZX_WITH_TWO_IMAGES))
        intact = data | self.load(list=True) | [str]
        second = WimArchive(data).images[1].resource
        data[second.offset + second.stored_size // 2] ^= 0xFF
        listed = data | self.load(list=True) | [str]
        self.assertEqual(listed, [path for path in intact if path.startswith('1/')])

    def test_encrypted_directory_yields_no_item_of_its_own(self):
        def encrypt_sub(metadata: bytearray):
            sub = directory_entry(metadata, 'sub')
            flags = sub + DIRECTORY_ENTRY_ATTRIBUTES
            attributes = FileAttributeFlags(int.from_bytes(metadata[flags:flags + 4], 'little'))
            attributes |= FileAttributeFlags.Encrypted
            metadata[flags:flags + 4] = attributes.to_bytes(4, 'little')
            sub_hash = sub + DIRECTORY_ENTRY_HASH
            times_hash = directory_entry(metadata, 'times.txt') + DIRECTORY_ENTRY_HASH
            assert any(metadata[times_hash:times_hash + 20])
            metadata[sub_hash:sub_hash + 20] = metadata[times_hash:times_hash + 20]
        data = with_modified_metadata(bytearray(self.download_sample(UNCOMPRESSED)), encrypt_sub)
        listed = data | self.load(list=True) | [str]
        self.assertIn('sub/times.txt', listed)
        self.assertNotIn('sub', listed)

    def test_slash_in_a_file_name_does_not_create_a_directory(self):
        listed = self._listing_with_empty_file_renamed('sub/x.bin')
        self.assertIn(F'sub{chr(0xFFFD)}x.bin', listed)
        self.assertNotIn('sub/x.bin', listed)

    def test_backslash_in_a_file_name_does_not_create_a_directory(self):
        listed = self._listing_with_empty_file_renamed(F'sub{chr(0x5C)}x.bin')
        self.assertIn(F'sub{chr(0xFFFD)}x.bin', listed)
        self.assertNotIn('sub/x.bin', listed)

    def test_xt_extracts_the_other_files_when_the_first_file_has_no_data(self):
        def lose_data_of_empty_file(metadata: bytearray):
            empty_hash = directory_entry(metadata, 'empty.bin') + DIRECTORY_ENTRY_HASH
            metadata[empty_hash:empty_hash + 20] = hashlib.sha1(B'not stored').digest()
        data = with_modified_metadata(bytearray(self.download_sample(UNCOMPRESSED)), lose_data_of_empty_file)
        secret = B'This text is hidden in an alternate data stream.\r\n'
        extracted = data | self.load() | [bytes]
        self.assertIn(secret, extracted)
        self.assertEqual(data | self.ldu('xt') | [bytes], extracted)

    def test_data_stored_in_another_part_of_a_split_wim(self):
        data = Chunk(self.download_sample(SPLIT2_1ST))
        item, = (item for item in xtwim().unpack(data) if item.path == 'sub/times.txt')
        with self.assertRaises(LookupError) as context:
            item.get_data()
        self.assertIn('split WIM', str(context.exception))

    def test_split_wim_extracts_like_the_wim_before_the_split(self):
        expected = self._items(self.download_sample(LZX_WITH_TWO_IMAGES))
        self.assertIn('1/sub/times.txt', dict(expected))
        extracted = self._items(
            self.download_sample(SPLIT3_3RD),
            self.download_sample(SPLIT3_1ST),
            self.download_sample(SPLIT3_2ND),
        )
        self.assertEqual(extracted, expected)

    def test_split_wims_and_a_whole_wim_in_one_frame_are_extracted_separately(self):
        extracted = self._items(
            self.download_sample(SPLIT3_3RD),
            self.download_sample(SPLIT2_1ST),
            self.download_sample(UNCOMPRESSED),
            self.download_sample(SPLIT3_1ST),
            self.download_sample(SPLIT2_2ND),
            self.download_sample(SPLIT3_2ND),
        )
        expected = sorted(
            item for original in (LZX_WITH_TWO_IMAGES, XPRESS, UNCOMPRESSED)
            for item in self._items(self.download_sample(original))
        )
        self.assertEqual(extracted, expected)

    def test_files_of_a_missing_part_are_not_extracted(self):
        expected = [
            (path, data) for path, data in self._items(self.download_sample(LZX_WITH_TWO_IMAGES))
            if not data or path.endswith('times.txt')
        ]
        extracted = self._items(
            self.download_sample(SPLIT3_1ST),
            self.download_sample(SPLIT3_3RD),
        )
        self.assertEqual(extracted, expected)

    def test_damaged_part_does_not_hide_the_files_of_the_other_parts(self):
        third = self.download_sample(SPLIT3_3RD)
        expected = [
            (path, data) for path, data in self._items(self.download_sample(LZX_WITH_TWO_IMAGES))
            if not path.endswith('times.txt')
        ]
        extracted = self._items(
            self.download_sample(SPLIT3_1ST),
            self.download_sample(SPLIT3_2ND),
            third[:len(third) // 2],
        )
        self.assertEqual(extracted, expected)

    def test_split_wim_without_its_first_part_is_refused(self):
        with self.assertRaises(ValueError):
            self._items(
                self.download_sample(SPLIT3_2ND),
                self.download_sample(SPLIT3_3RD),
            )

    def test_two_copies_of_every_part_are_extracted_as_two_complete_split_wims(self):
        parts = [SPLIT3_1ST, SPLIT3_2ND, SPLIT3_3RD]
        extracted = self._items(*(self.download_sample(part) for part in parts for _ in range(2)))
        expected = sorted(self._items(self.download_sample(LZX_WITH_TWO_IMAGES)) * 2)
        self.assertEqual(extracted, expected)

    def test_hidden_part_is_not_combined_with_the_visible_parts(self):
        first, second, third = (
            self.download_sample(part)
            for part in (SPLIT3_1ST, SPLIT3_2ND, SPLIT3_3RD)
        )
        output = [first, second, third] | self.load_pipeline('scope -n 1 | xtwim') | [...]
        passed = [chunk for chunk in output if 'path' not in chunk.meta]
        extracted = sorted((str(chunk.meta['path']), bytes(chunk)) for chunk in output if 'path' in chunk.meta)
        self.assertEqual(passed, [second])
        self.assertEqual(extracted, self._items(first, third))

    def test_damaged_wim_passed_through_by_lenient_mode_joins_its_frame(self):
        damaged = self.download_sample(UNCOMPRESSED)[:1000]
        joined = damaged + B'junk' | self.load_pipeline('chop 1000 [[| xtwim -L ]| nop ]') | bytes
        self.assertEqual(joined, damaged + B'junk')

    def test_try_mode_returns_every_part_of_a_split_wim_without_its_first_part(self):
        frame = [
            self.download_sample(SPLIT3_2ND),
            self.download_sample(SPLIT3_3RD),
        ]
        self.assertEqual(frame | self.load_pipeline('xtwim -T') | [bytes], frame)

    @unittest.expectedFailure
    def test_try_mode_returns_every_part_of_a_split_wim_whose_first_part_is_damaged(self):
        frame = [
            self.download_sample(SPLIT3_1ST)[:HEADER_SIZE],
            self.download_sample(SPLIT3_2ND),
            self.download_sample(SPLIT3_3RD),
        ]
        self.assertEqual(frame | self.load_pipeline('xtwim -T') | [bytes], frame)

    @unittest.expectedFailure
    def test_argument_that_consumes_a_variable_is_read_once_for_a_split_wim_after_another_wim(self):
        frame = [
            self.download_sample(SPLIT3_1ST),
            self.download_sample(UNCOMPRESSED),
            self.download_sample(SPLIT3_2ND),
            self.download_sample(SPLIT3_3RD),
        ]
        listed = frame | self.load_pipeline('put name x | xtwim -l -P eat:name') | [str]
        expected = [
            *(self.download_sample(LZX_WITH_TWO_IMAGES) | self.load(list=True) | [str]),
            *(self.download_sample(UNCOMPRESSED) | self.load(list=True) | [str]),
        ]
        self.assertEqual(sorted(listed), sorted(expected))
