import datetime
import lzma
import functools

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


class TestVHDExtractor(TestUnitBase):

    @functools.lru_cache(maxsize=10)
    def _sample(self, name: str):
        return lzma.decompress(self.download_sample(_DISK_HASHES[name]))

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
