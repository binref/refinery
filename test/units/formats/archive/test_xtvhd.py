import datetime
import functools
import itertools
import lzma
import uuid

from unittest.mock import patch

from refinery.lib.vhd.fat import FatVolume

from ... import TestUnitBase

_DISK_HASHES = {
    'malware.vhd' : '2dd5a1f93e2a16e0c71ae12d211105e238239946269e1c095760b5fe24587a28',
    'deleted.vhd' : '4172218fe84561cbbecb4a59fbd7a6cf40a69f14b9b919eb76caedf52a1d4d95',
    'fixed.vhd'   : 'b3de5df4a7bc9c276da6050814002757200eeef3c67b2a2d2d3a6acb1c11bbe1',
    'ntfs.vhd'    : '33fb4858d5470591af07ed9939d17e40c25d174932452ece7daf789e96e749b8',
    'vhdx.vhdx'   : '74c7459a3f7fbb3f533eabb0adaeadbcc4861e65ba53ba97fe2b45063969f598',
}

_FILE_HASHES = {
    'big.txt'    : '55f6aaf579f8c600f49db8437e91ae8bea2ba9b27121bb18960811bd3b7e1048',
    'kadath1.txt': 'bc7524d2cda09cd533e738650592ed1e8e5442bae3969a730a835dcba780c8f2',
    'kadath2.txt': 'f33d62b175ffbb183cadee08873b03dca7aaf1dfc7035a32203996e309d9aed6',
    'small.txt'  : '3fcdaaca3594525c037d2f83d20d5e21d3f5b5264b7ab99351eed1d552ccac51',
}

_VHDX_REGION_TABLE = 0x30000
_VHDX_REGION_BAT = uuid.UUID('2DC27766-F623-4200-9D64-115E9BFD4A08').bytes_le


class TestVHDExtractor(TestUnitBase):

    @functools.lru_cache(maxsize=10)
    def _sample(self, name: str):
        return lzma.decompress(self.download_sample(_DISK_HASHES[name]))

    def _file_offset(self, data: bytes | bytearray, offset: int) -> int:
        footer = data[-512:]
        kind = int.from_bytes(footer[0x3C:0x40], 'big')
        if kind == 2:
            return offset
        self.assertEqual(kind, 3)
        header = int.from_bytes(footer[0x10:0x18], 'big')
        table = int.from_bytes(data[header + 0x10:header + 0x18], 'big')
        block_size = int.from_bytes(data[header + 0x20:header + 0x24], 'big')
        bitmap_size = (block_size // 512 // 8 + 511) // 512 * 512
        block, offset = divmod(offset, block_size)
        sector = int.from_bytes(data[table + 4 * block:table + 4 * block + 4], 'big')
        self.assertNotEqual(sector, 0xFFFFFFFF)
        return sector * 512 + bitmap_size + offset

    def _payload(self, data: bytes, meta: int = 0):
        chunks = data | self.load(meta=meta) | {'path': ...}
        for name, digest in _FILE_HASHES.items():
            self.assertEqual(repr(chunks[name]['sha256']), digest)
        return chunks

    def test_fixed_vhd_fat32(self):
        self._payload(self._sample('fixed.vhd'))

    def test_vhdx_ntfs(self):
        self._payload(self._sample('vhdx.vhdx'))

    def test_ntfs_compressed_file_roundtrip(self):
        chunks = self._payload(self._sample('ntfs.vhd'), meta=2)
        body = bytes(chunks['big.txt'])
        self.assertEqual(len(body), 511488)
        self.assertEqual(repr(chunks['big.txt']['sha256']), _FILE_HASHES['big.txt'])
        entry = chunks['big.txt']
        self.assertIsInstance(entry['record'], int)
        self.assertGreaterEqual(entry['record'], 16)
        self.assertEqual(entry['allocated'], 524288)
        for key in ('mtime', 'btime', 'ctime', 'atime'):
            value = bytes(entry[key]).decode('ascii')
            self.assertRegex(value, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
            datetime.datetime.fromisoformat(value)

    def test_ntfs_resident_file_has_no_allocation(self):
        chunks = self._payload(self._sample('ntfs.vhd'))
        self.assertNotIn('allocated', chunks['small.txt'].meta)

    def test_ntfs_filename_timestamps_exposed_on_mismatch(self):
        chunks = self._payload(self._sample('ntfs.vhd'), meta=2)
        entry = chunks['big.txt']
        self.assertIn('fn_mtime', entry.meta)
        self.assertNotEqual(
            bytes(entry['mtime']).decode('ascii'),
            bytes(entry['fn_mtime']).decode('ascii'),
        )

    def test_no_deleted_files_without_recover(self):
        data = self._sample('ntfs.vhd')
        for chunk in data | self.load():
            self.assertNotIn('deleted', chunk.meta)

    def test_ntfs_deleted_absent_without_recover(self):
        data = self._sample('deleted.vhd')
        paths = {str(chunk.meta.path) for chunk in data | self.load()}
        self.assertNotIn('kadath2.txt', paths)
        self.assertIn('kadath1.txt', paths)

    def test_ntfs_recover_reveals_deleted(self):
        data = self._sample('deleted.vhd')
        recovered = {}
        for chunk in data | self.load(recover=True):
            if chunk.meta.deleted:
                recovered[chunk['path']] = chunk
        self.assertEqual(set(recovered), {'kadath2.txt'})
        entry = recovered['kadath2.txt']
        self.assertTrue(entry.meta['deleted'])
        self.assertEqual(repr(entry['sha256']), _FILE_HASHES['kadath2.txt'])

    def test_malware_sample(self):
        data = self._sample('malware.vhd')
        chunks = data | self.load(meta=2) | {'path': ...}
        self.assertSetEqual(set(chunks), {
            '$RECYCLE.BIN/$I4CCXNO.pdf',
            '$RECYCLE.BIN/$IC32JRY.pdf',
            '$RECYCLE.BIN/$ICW8PHQ.pdf',
            '$RECYCLE.BIN/$IETCMOD.pdf',
            '$RECYCLE.BIN/$IHZE7DR.pdf',
            '$RECYCLE.BIN/$ISZLWN9.doc',
            '$RECYCLE.BIN/$IW9D1Q6.pdf',
            '$RECYCLE.BIN/$IZWM7BO.pdf',
            '$RECYCLE.BIN/$R4CCXNO.pdf',
            '$RECYCLE.BIN/$RC32JRY.pdf',
            '$RECYCLE.BIN/$RCW8PHQ.pdf',
            '$RECYCLE.BIN/$RETCMOD.pdf',
            '$RECYCLE.BIN/$RHZE7DR.pdf',
            '$RECYCLE.BIN/$RSZLWN9.doc',
            '$RECYCLE.BIN/$RW9D1Q6.pdf',
            '$RECYCLE.BIN/$RZWM7BO.pdf',
            '$RECYCLE.BIN/desktop.ini',
            'System Volume Information/IndexerVolumeGuid',
            'System Volume Information/WPSettings.dat',
            'TrainingAnnouncement.pdf.lnk',
            '_/TrainingAnnouncement.pdf',
            '_/_/j/_/_/_/_/_/_',
            '_/_/j/_/_/_/_/_/_rels/body.doc',
            '_/_/j/_/_/_/_/_/_rels/header.doc',
        })
        self.assertEqual(repr(chunks['TrainingAnnouncement.pdf.lnk']['sha256']),
            'daeac66441b88ba22806f6617058a2dbf1ea0ddcc6c94f291542ea853ac6f9d3')
        self.assertEqual(repr(chunks['_/TrainingAnnouncement.pdf']['sha256']),
            '575305cdaeb1d2187ca6d5ebe32f4c3e3fb53f5ccbe1c0cc257a7f71d84e6f35')
        self.assertEqual(repr(chunks['$RECYCLE.BIN/$RSZLWN9.doc']['sha256']),
            'b1fd6a1cfa78429b3bf5adf64f69d35998f54577df486b2a1acdf854d11a12a6')
        entry = chunks['TrainingAnnouncement.pdf.lnk']
        for key in ('mtime', 'btime', 'atime'):
            value = bytes(entry[key]).decode('ascii')
            self.assertRegex(value, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
            datetime.datetime.fromisoformat(value)
        self.assertEqual(entry['attributes'], 0x20)

    def test_fat_recover_disabled_by_default(self):
        data = self._sample('malware.vhd')
        for chunk in data | self.load():
            self.assertNotIn('deleted', chunk.meta)

    def test_fat_recover_reveals_deleted(self):
        data = self._sample('malware.vhd')
        normal = data | self.load() | {'path': ...}
        recovered = {}
        for chunk in data | self.load(recover=True):
            if chunk.meta.deleted:
                recovered[chunk['path']] = chunk
        self.assertEqual(len(recovered), 48)
        self.assertTrue(set(recovered).isdisjoint(normal))

    def test_fat_recovered_content(self):
        data = self._sample('malware.vhd')
        recovered = {}
        for chunk in data | self.load(recover=True):
            if chunk['deleted']:
                recovered[chunk['path']] = chunk
        self.assertEqual(repr(recovered['$RECYCLE.BIN/_R9ORL1K.pdf']['sha256']),
            '203426bbab2c9b5f73e894282c896802bd03e30a869aaa91c4a9c76ef2ced136')
        self.assertEqual(repr(recovered['$RECYCLE.BIN/_RK8OTOU.pdf']['sha256']),
            '796d1ae687ed252aaf129c7ad2361c4c6cfc1150ed05536921f3f7cd8196883c')

    def test_disk_without_partition_table_or_file_system_is_extracted_as_raw_image(self):
        data = lzma.decompress(self.download_sample(
            '2c0d61aee8b3db82fb023fa5592c6dec996259129a0e9d4490da34517851b8cb'))
        chunks = data | self.load() | {'path': ...}
        self.assertEqual(set(chunks), {'disk.img'})
        self.assertEqual(chunks['disk.img'], data[:-512])

    def test_mbr_partition_with_invalid_fat_is_extracted_as_raw_image(self):
        data = bytearray(self._sample('fixed.vhd'))
        offset = int.from_bytes(data[0x1C6:0x1CA], 'little') * 512
        size = int.from_bytes(data[0x1CA:0x1CE], 'little') * 512
        data[offset + 0x10] = 0
        chunks = data | self.load() | {'path': ...}
        self.assertEqual(set(chunks), {'partition0.img'})
        self.assertEqual(chunks['partition0.img'], data[offset:offset + size])

    def test_gpt_partition_without_file_system_is_extracted_as_raw_image(self):
        data = bytearray(self._sample('malware.vhd'))
        boot = data.find(B'\xEB\x3C\x90MSDOS5.0')
        self.assertGreater(boot, 0)
        size = int.from_bytes(data[boot + 0x13:boot + 0x15], 'little') * 512
        data[boot + 0x1FE:boot + 0x200] = bytes(2)
        chunks = data | self.load() | {'path': ...}
        self.assertEqual(set(chunks), {'Basic data partition.img'})
        image = chunks['Basic data partition.img']
        self.assertEqual(len(image), size)
        self.assertEqual(image[:512], data[boot:boot + 512])

    def test_raw_image_of_unreadable_partition_follows_files_of_readable_partition(self):
        data = bytearray(self._sample('fixed.vhd'))
        start = int.from_bytes(data[0x1C6:0x1CA], 'little')
        entry = 0x1BE + 16
        data[entry + 4] = 0x83
        data[entry + 8:entry + 12] = (1).to_bytes(4, 'little')
        data[entry + 12:entry + 16] = (start - 1).to_bytes(4, 'little')
        chunks = data | self.load() | []
        paths = [str(chunk['path']) for chunk in chunks]
        self.assertEqual(paths[-1], 'partition1.img')
        self.assertTrue(set(_FILE_HASHES) <= set(paths[:-1]))
        self.assertEqual(chunks[-1], data[512:start * 512])

    def test_dynamic_vhd_partition_without_stored_sectors_yields_nothing(self):
        data = bytearray(self._sample('ntfs.vhd'))
        header = int.from_bytes(data[-512 + 0x10:-512 + 0x18], 'big')
        table = int.from_bytes(data[header + 0x10:header + 0x18], 'big')
        count = int.from_bytes(data[header + 0x1C:header + 0x20], 'big')
        block_size = int.from_bytes(data[header + 0x20:header + 0x24], 'big')
        bitmap_size = (block_size // 512 // 8 + 511) // 512 * 512
        data[table + 4:table + 4 * count] = B'\xFF' * (4 * (count - 1))
        block = int.from_bytes(data[table:table + 4], 'big') * 512
        mbr = block + bitmap_size
        start = int.from_bytes(data[mbr + 0x1C6:mbr + 0x1CA], 'little')
        self.assertEqual(start % 8, 0)
        data[block + start // 8:block + bitmap_size] = bytes(bitmap_size - start // 8)
        self.assertEqual(set(data | self.load() | {'path': ...}), set())

    def test_dynamic_vhd_without_stored_blocks_yields_nothing(self):
        data = bytearray(self._sample('ntfs.vhd'))
        header = int.from_bytes(data[-512 + 0x10:-512 + 0x18], 'big')
        table = int.from_bytes(data[header + 0x10:header + 0x18], 'big')
        count = int.from_bytes(data[header + 0x1C:header + 0x20], 'big')
        data[table:table + 4 * count] = B'\xFF' * (4 * count)
        self.assertEqual(set(data | self.load() | {'path': ...}), set())

    def test_vhdx_without_stored_blocks_yields_nothing(self):
        data = bytearray(self._sample('vhdx.vhdx'))
        entry = data.find(_VHDX_REGION_BAT, _VHDX_REGION_TABLE)
        offset = int.from_bytes(data[entry + 16:entry + 24], 'little')
        length = int.from_bytes(data[entry + 24:entry + 28], 'little')
        for position in range(offset, offset + length, 8):
            data[position] &= 0xF8
        self.assertEqual(set(data | self.load() | {'path': ...}), set())

    def test_raw_volume_larger_than_the_input_is_split_into_stored_blocks(self):
        data = bytearray(self._sample('ntfs.vhd'))
        header = int.from_bytes(data[-512 + 0x10:-512 + 0x18], 'big')
        table = int.from_bytes(data[header + 0x10:header + 0x18], 'big')
        count = int.from_bytes(data[header + 0x1C:header + 0x20], 'big')
        block_size = int.from_bytes(data[header + 0x20:header + 0x24], 'big')
        bitmap_size = block_size // 512 // 8
        blocks = {}
        for index in range(count):
            sector = int.from_bytes(data[table + 4 * index:table + 4 * index + 4], 'big')
            if sector != 0xFFFFFFFF:
                blocks[index] = sector * 512 + bitmap_size
        mbr = blocks[0]
        offset = int.from_bytes(data[mbr + 0x1C6:mbr + 0x1CA], 'little') * 512
        size = int.from_bytes(data[mbr + 0x1CA:mbr + 0x1CE], 'little') * 512
        self.assertGreater(size, len(data))
        data[mbr + offset + 0x1FE:mbr + offset + 0x200] = bytes(2)
        expected = {}
        for index, position in blocks.items():
            lower = max(index * block_size, offset)
            upper = min((index + 1) * block_size, offset + size)
            if lower < upper:
                start = position + lower - index * block_size
                expected[lower - offset, upper - offset] = data[start:start + upper - lower]
        chunks = data | self.load() | []
        self.assertEqual(chunks[0]['path'], 'partition0.img/0x0000000')
        self.assertEqual(len(chunks), len(expected))
        self.assertEqual({(chunk['start'], chunk['end']): chunk for chunk in chunks}, expected)

    def test_raw_volume_claiming_2_tb_yields_only_the_stored_blocks(self):
        data = bytearray(self._sample('vhdx.vhdx'))
        entry = data.find(_VHDX_REGION_BAT, _VHDX_REGION_TABLE)
        table = int.from_bytes(data[entry + 16:entry + 24], 'little')
        mbr = int.from_bytes(data[table:table + 8], 'little') & ~0xFFFFF
        offset = int.from_bytes(data[mbr + 0x1C6:mbr + 0x1CA], 'little') * 512
        data[mbr + 0x1CA:mbr + 0x1CE] = B'\xFF' * 4
        data[mbr + offset + 0x1FE:mbr + offset + 0x200] = bytes(2)
        chunks = data | self.load() | []
        block_size = 32 << 20
        self.assertEqual([(chunk['start'], chunk['end']) for chunk in chunks], [
            (0, block_size - offset),
            (block_size - offset, 2 * block_size - offset),
        ])
        self.assertEqual(chunks[0], data[mbr + offset:mbr + block_size])
        second = int.from_bytes(data[table + 8:table + 16], 'little') & ~0xFFFFF
        self.assertEqual(chunks[1], data[second:second + block_size])
        self.assertEqual([chunk['path'] for chunk in chunks], [
            'partition0.img/0x00000000000',
            'partition0.img/0x00001ff0000',
        ])

    def _malware_with_its_partition_copied_under(self, *labels: str):
        data = bytearray(self._sample('malware.vhd'))
        gpt = self._file_offset(data, 512)
        self.assertEqual(data[gpt:gpt + 8], B'EFI PART')
        table = int.from_bytes(data[gpt + 0x48:gpt + 0x50], 'little') * 512
        size = int.from_bytes(data[gpt + 0x54:gpt + 0x58], 'little')
        first = self._file_offset(data, table)
        for slot, label in enumerate(labels, 1):
            entry = self._file_offset(data, table + slot * size)
            self.assertFalse(any(data[entry:entry + size]))
            data[entry:entry + size] = data[first:first + size]
            data[entry + 0x38:entry + 0x38 + 72] = label.encode('utf-16le').ljust(72, B'\0')
        return data

    def test_volumes_sharing_a_gpt_label_get_separate_folders(self):
        intact = self._sample('malware.vhd') | self.load(list=True) | {str}
        data = self._malware_with_its_partition_copied_under('Basic data partition')
        paths = data | self.load(list=True) | {str}
        self.assertEqual(paths, {
            F'Basic data partition.{index}/{path}' for index in (0, 1) for path in intact})

    def test_volume_named_like_a_disambiguated_label_gets_a_separate_folder(self):
        intact = self._sample('malware.vhd') | self.load(list=True) | {str}
        data = self._malware_with_its_partition_copied_under(
            'Basic data partition',
            'Basic data partition.1',
        )
        paths = data | self.load(list=True) | {str}
        self.assertEqual(len(paths), 3 * len(intact))
        self.assertEqual({path.split('/')[0] for path in paths}, {
            'Basic data partition.0',
            'Basic data partition.1.1',
            'Basic data partition.1.2',
        })

    def test_volume_failing_to_list_is_extracted_raw_and_does_not_stop_the_other_volumes(self):
        intact = [str(path) for path in self._sample('malware.vhd') | self.load(list=True) | []]
        data = self._malware_with_its_partition_copied_under('Basic data partition')
        files = FatVolume.files
        failures = [IndexError('damaged directory')]

        def fail_after_first_file(volume: FatVolume, recover: bool = False):
            listing = files(volume, recover)
            if failures:
                for file in listing:
                    yield file
                    if not file.is_dir:
                        raise failures.pop()
            yield from listing

        with patch.object(FatVolume, 'files', fail_after_first_file):
            paths = data | self.load(list=True) | {str}
        self.assertEqual(paths, {
            F'Basic data partition.0/{intact[0]}',
            'Basic data partition.0.img',
            *(F'Basic data partition.1/{path}' for path in intact),
        })

    def _fixed_vhd_with_nested_directories(self, depth: int, files: dict[int, list[bytes]]):
        data = bytearray(self._sample('fixed.vhd'))
        volume = int.from_bytes(data[0x1C6:0x1CA], 'little') * 512
        boot = data[volume:volume + 512]
        sector_size = int.from_bytes(boot[0x0B:0x0D], 'little')
        cluster_size = sector_size * boot[0x0D]
        fat = volume + int.from_bytes(boot[0x0E:0x10], 'little') * sector_size
        fat_size = int.from_bytes(boot[0x24:0x28], 'little') * sector_size
        fat_count = boot[0x10]
        clusters = fat + fat_count * fat_size
        root = clusters + (int.from_bytes(boot[0x2C:0x30], 'little') - 2) * cluster_size
        end = volume + int.from_bytes(boot[0x20:0x24], 'little') * sector_size
        cluster_count = (end - clusters) // cluster_size

        def entry(name: bytes, attributes: int, cluster: int = 0):
            return B''.join((
                name,
                bytes((attributes,)),
                bytes(8),
                (cluster >> 16).to_bytes(2, 'little'),
                bytes(4),
                (cluster & 0xFFFF).to_bytes(2, 'little'),
                bytes(4),
            ))

        free = (
            cluster for cluster in range(3, cluster_count + 2)
            if not int.from_bytes(data[fat + 4 * cluster:fat + 4 * cluster + 4], 'little')
        )
        chain = list(itertools.islice(free, depth))
        self.assertEqual(len(chain), depth)
        for cluster in chain:
            for copy in range(fat_count):
                link = fat + copy * fat_size + 4 * cluster
                data[link:link + 4] = (0x0FFFFFFF).to_bytes(4, 'little')
        slot = next(k for k in range(root, root + cluster_size, 32) if data[k] == 0)
        tables = [slot, *(clusters + (cluster - 2) * cluster_size for cluster in chain)]
        for level, table in enumerate(tables):
            listing = [entry(name, 0x20) for name in files.get(level, ())]
            if level < depth:
                listing.insert(0, entry(B'NESTED     ', 0x10, chain[level]))
            listing.append(bytes(32))
            size = 32 * len(listing)
            if level == 0:
                self.assertLessEqual(slot + size, root + cluster_size)
                self.assertFalse(any(data[slot:slot + size]))
            data[table:table + size] = B''.join(listing)
        return data

    def test_directories_nested_beyond_the_recursion_limit_are_listed(self):
        depth = 1200
        data = self._fixed_vhd_with_nested_directories(depth, {depth: [B'DEEP    TXT']})
        paths = data | self.load(list=True) | {str}
        self.assertIn('NESTED/' * depth + 'DEEP.TXT', paths)

    def test_entries_whose_path_exceeds_the_windows_maximum_are_skipped(self):
        depth = 4700
        data = self._fixed_vhd_with_nested_directories(depth, {
            0: [B'AFTER   TXT'],
            4680: [B'FIT     TXT', B'OVER    TXT'],
            depth: [B'DEEP    TXT'],
        })
        paths = data | self.load(list=True) | {str}
        longest = 'NESTED/' * 4680 + 'FIT.TXT'
        self.assertEqual(len(longest), 32767)
        self.assertIn(longest, paths)
        self.assertEqual(max(map(len, paths)), 32767)
        self.assertIn('AFTER.TXT', paths)
        self.assertTrue(set(_FILE_HASHES) <= paths)

    def _ntfs_mft_data_attribute(self, data: bytearray) -> tuple[int, int]:
        mbr = self._file_offset(data, 0)
        volume = int.from_bytes(data[mbr + 0x1C6:mbr + 0x1CA], 'little') * 512
        boot = self._file_offset(data, volume)
        cluster_size = int.from_bytes(data[boot + 0x0B:boot + 0x0D], 'little') * data[boot + 0x0D]
        mft_cluster = int.from_bytes(data[boot + 0x30:boot + 0x38], 'little')
        record = self._file_offset(data, volume + mft_cluster * cluster_size)
        self.assertEqual(data[record:record + 4], B'FILE')
        position = record + int.from_bytes(data[record + 0x14:record + 0x16], 'little')
        while int.from_bytes(data[position:position + 4], 'little') != 0x80:
            position += int.from_bytes(data[position + 4:position + 8], 'little')
        self.assertEqual(data[position + 8], 1)
        return record, position

    def test_ntfs_volume_whose_mft_claims_more_than_the_volume_is_extracted_raw(self):
        data = bytearray(self._sample('ntfs.vhd'))
        record, attribute = self._ntfs_mft_data_attribute(data)
        size = attribute + 0x30
        self.assertLess((size - record) % 512, 510 - 8)
        data[size:size + 8] = (1 << 62).to_bytes(8, 'little')
        paths = data | self.load(list=True) | {str}
        self.assertTrue(paths)
        self.assertTrue(all(path.startswith('partition0.img/') for path in paths))

    def test_ntfs_volume_whose_mft_claims_more_than_the_stored_data_is_extracted_raw(self):
        data = bytearray(self._sample('ntfs.vhd'))
        mbr = self._file_offset(data, 0)
        data[mbr + 0x1CA:mbr + 0x1CE] = B'\xFF' * 4
        record, attribute = self._ntfs_mft_data_attribute(data)
        size = attribute + 0x30
        self.assertLess((size - record) % 512, 510 - 8)
        data[size:size + 8] = (1 << 40).to_bytes(8, 'little')
        paths = data | self.load(list=True) | {str}
        self.assertTrue(paths)
        self.assertTrue(all(path.startswith('partition0.img/') for path in paths))

    def test_ntfs_volume_whose_mft_runs_claim_more_than_its_size_is_listed(self):
        intact = self._sample('ntfs.vhd') | self.load(list=True) | {str}
        for compression_unit in (0, 4):
            with self.subTest(compression_unit=compression_unit):
                data = bytearray(self._sample('ntfs.vhd'))
                record, attribute = self._ntfs_mft_data_attribute(data)
                length = int.from_bytes(data[attribute + 4:attribute + 8], 'little')
                runs = attribute + int.from_bytes(data[attribute + 0x20:attribute + 0x22], 'little')
                self.assertLessEqual(runs + 8, attribute + length)
                self.assertLess((runs - record) % 512, 510 - 8)
                self.assertEqual(data[runs], 0x21)
                self.assertFalse(any(data[runs + 4:runs + 8]))
                offset = bytes(data[runs + 2:runs + 4])
                data[runs:runs + 8] = B'\x24\xFF\xFF\xFF\x7F' + offset + B'\0'
                data[attribute + 0x22] = compression_unit
                paths = data | self.load(list=True) | {str}
                self.assertEqual(paths, intact)
