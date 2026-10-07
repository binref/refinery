import hashlib
import random
import struct
import tracemalloc

from unittest import mock

from refinery.lib.cab import Cabinet, cab_data_checksum
from refinery.lib.seven.lzx import LzxDecoder
from .. import TestBase

THREE_FILES_IN_ONE_LZX_FOLDER = '55e0e9167fa3612135815ed01119a91281373c08c257efc8f7cc36bcc08734d2'
STDLIB_SOURCES_IN_ONE_MSZIP_FOLDER = '36ef84b0a20d122e3d68c78f93dcf362639d09a68575b734e28c3b3855918ff2'
FIRST_FOLDER_BLOCK_COUNT = 40
FILE_ENTRIES_OFFSET = 16
FILE_ENTRY_NAME = 16


def _reference(content: bytes, checksum: int = 0) -> int:
    # The CAB data-block checksum is the XOR of all little-endian 32-bit words, XOR the
    # big-endian value of the trailing one to three bytes.
    n = len(content)
    for j in range(0, n - n % 4, 4):
        checksum ^= int.from_bytes(content[j:j + 4], 'little')
    if k := n % 4:
        checksum ^= int.from_bytes(content[-k:], 'big')
    return checksum


class TestCabChecksum(TestBase):

    def test_empty_returns_seed(self):
        self.assertEqual(cab_data_checksum(memoryview(B''), 0x12345678), 0x12345678)

    def test_single_word_little_endian(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03\x04')), 0x04030201)

    def test_trailing_bytes_big_endian(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03')), 0x010203)

    def test_word_and_tail(self):
        self.assertEqual(cab_data_checksum(memoryview(B'\x01\x02\x03\x04\x05')), 0x04030204)

    def test_matches_reference_for_many_lengths(self):
        rng = random.Random(0xC4B5)
        for n in (*range(0, 40), 255, 256, 257, 1023, 4096, 32767, 32768, 65535):
            data = bytes(rng.getrandbits(8) for _ in range(n))
            seed = rng.getrandbits(32)
            self.assertEqual(cab_data_checksum(memoryview(data), seed), _reference(data, seed))


class TestCabFolders(TestBase):

    def files(self, data):
        return Cabinet(memoryview(data)).process().get_files()

    def test_files_of_one_folder_read_in_reverse_decompress_each_block_once(self):
        files = self.files(self.download_sample(THREE_FILES_IN_ONE_LZX_FOLDER))
        folder, = {id(file.folder): file.folder for file in files}.values()
        extractors = [file.extractor() for file in files]
        with mock.patch.object(LzxDecoder, 'decompress', autospec=True, side_effect=LzxDecoder.decompress) as lzx:
            sizes = [len(extract()) for extract in reversed(extractors)]
        self.assertEqual(sizes, [file.size for file in reversed(files)])
        self.assertEqual(lzx.call_count, len(folder.blocks))

    def test_file_cut_short_by_the_end_of_its_folder_reports_its_size(self):
        data = self.download_sample(THREE_FILES_IN_ONE_LZX_FOLDER)
        intact = [hashlib.sha256(file.decompress()).hexdigest() for file in self.files(data)]
        cut = bytearray(data)
        blocks, = struct.unpack_from('<H', cut, FIRST_FOLDER_BLOCK_COUNT)
        struct.pack_into('<H', cut, FIRST_FOLDER_BLOCK_COUNT, blocks - 1)
        first, second, third = (file.extractor() for file in self.files(cut))
        self.assertEqual(hashlib.sha256(first()).hexdigest(), intact[0])
        self.assertEqual(hashlib.sha256(second()).hexdigest(), intact[1])
        with self.assertRaisesRegex(RuntimeError, 'does not have the correct size'):
            third()

    def test_a_file_whose_stated_size_is_far_too_large_holds_no_more_than_the_decoded_data(self):
        data = bytearray(self.download_sample(STDLIB_SOURCES_IN_ONE_MSZIP_FOLDER))
        intact = [hashlib.sha256(file.decompress()).digest() for file in self.files(data)]
        oversized = len(intact) // 2
        position, = struct.unpack_from('<I', data, FILE_ENTRIES_OFFSET)
        for _ in range(oversized):
            position = data.index(0, position + FILE_ENTRY_NAME) + 1
        struct.pack_into('<I', data, position, 1 << 30)
        extractors = [file.extractor() for file in self.files(data)]
        tracemalloc.start()
        try:
            for k, (extract, digest) in enumerate(zip(extractors, intact)):
                if k == oversized:
                    with self.assertRaisesRegex(RuntimeError, 'does not have the correct size'):
                        extract()
                else:
                    self.assertEqual(hashlib.sha256(extract()).digest(), digest)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 64 << 20)

    def test_a_damaged_block_fails_the_files_from_its_start_on_and_shifts_no_data(self):
        data = self.download_sample(STDLIB_SOURCES_IN_ONE_MSZIP_FOLDER)
        files = self.files(data)
        extractors = [file.extractor() for file in files]
        intact = [hashlib.sha256(extract()).digest() for extract in extractors]
        folder = files[0].folder
        middle = len(folder.blocks) // 2
        damaged_block = folder.blocks[middle]
        damage_start = sum(block.decompressed_size for block in folder.blocks[:middle])
        damaged = bytearray(data)
        offset = damaged.find(bytes(damaged_block.data))
        damaged[offset + len(damaged_block.data) // 2] ^= 0xFF
        seed, = struct.unpack_from('<I', damaged, offset - 4)
        checksum = cab_data_checksum(memoryview(damaged)[offset:offset + len(damaged_block.data)], seed)
        struct.pack_into('<I', damaged, offset - 8, checksum)
        files = self.files(damaged)
        extractors = [file.extractor() for file in files]
        for file, extract, digest in zip(files, extractors, intact):
            if file.offset + file.size <= damage_start:
                self.assertEqual(hashlib.sha256(extract()).digest(), digest, file.name)
            else:
                with self.assertRaises(RuntimeError, msg=file.name):
                    extract()
