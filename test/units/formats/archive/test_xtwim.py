import hashlib

from typing import Callable

import pytest

from refinery.lib.lnk.flags import FileAttributeFlags
from refinery.lib.wim import WimArchive
from refinery.units import Chunk, RefineryException
from refinery.units.formats.archive.xtwim import xtwim

from ... import TestUnitBase

UNCOMPRESSED = 'f589d49d144f08cf8bbca6dd1026e4e3b57692a3f55d37f7140b30f13b3d5029'
LZX_WITH_TWO_IMAGES = '4da6303a0a61a24d2ca12ae7348fc6de5573505aa451c7ca49cac9f964c3174f'
FIRST_OF_TWO_PARTS = 'b85f850c972b55807850e2eb6140ffd2ac276d20ede081842b759909fcab5234'

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
    resource = image.resource
    assert resource is not None
    start = resource.offset
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
        assert second is not None
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

    @pytest.mark.xfail(
        strict=True,
        raises=RefineryException,
        reason='xt drops a handler whose first item fails to extract',
    )
    def test_xt_extracts_the_other_files_when_the_first_file_has_no_data(self):
        def lose_data_of_empty_file(metadata: bytearray):
            empty_hash = directory_entry(metadata, 'empty.bin') + DIRECTORY_ENTRY_HASH
            metadata[empty_hash:empty_hash + 20] = hashlib.sha1(B'not stored').digest()
        data = with_modified_metadata(bytearray(self.download_sample(UNCOMPRESSED)), lose_data_of_empty_file)
        secret = B'This text is hidden in an alternate data stream.\r\n'
        self.assertIn(secret, data | self.load() | [bytes])
        self.assertIn(secret, data | self.ldu('xt') | [bytes])

    def test_data_stored_in_another_part_of_a_split_wim(self):
        data = Chunk(self.download_sample(FIRST_OF_TWO_PARTS))
        item, = (item for item in xtwim().unpack(data) if item.path == 'sub/times.txt')
        with self.assertRaises(LookupError) as context:
            item.get_data()
        self.assertIn('split WIM', str(context.exception))
