import json

from refinery.lib.structures import StructReader

from ... import TestUnitBase


class TestNuitkaExtractor(TestUnitBase):

    def test_modified_archive_deflate1(self):
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        data = data | self.ldu('xt7z', 'flake.exe') | self.load('flake.exe') | self.ldu('pemeta', '-cP') | json.loads
        self.assertEqual(data['TimeStamp']['Linker'], '2023-09-20 21:12:44')

    def test_xt_extracts_onefile_executable(self):
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        data = data | self.ldu('xt7z', 'flake.exe') | self.ldu('xt', 'flake.exe') | self.ldu('pemeta', '-cP') | json.loads
        self.assertEqual(data['TimeStamp']['Linker'], '2023-09-20 21:12:44')

    def test_format_check_closes_the_resource_reader(self):
        from refinery.units.formats.pe.perc import perc
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        data = data | self.ldu('xt7z', 'flake.exe') | bytearray
        with self.assertNoInstanceSurvives(perc):
            self.assertTrue(self.load().handles(data))

    def test_dos_executable_is_rejected(self):
        data = self.download_sample('f36d9551c1917a7990db2b4582191656d748179ea2bd15499294388e9c4fa458')
        self.assertFalse(self.load().handles(data))

    def test_two_files_with_the_same_name_are_both_extracted(self):
        from refinery.lib.shared.pyzstd import pyzstd
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        flake = data | self.ldu('xt7z', 'flake.exe') | bytearray
        [archive] = [bytes(r) for r in flake | self.ldu('perc') if r[:3] == B'KAY']
        body = bytearray(pyzstd.ZstdDecompressor().decompress(archive[3:]))
        # every entry is a name, a 64-bit size, and the data of the file
        reader = StructReader(memoryview(body))
        while (at := reader.tell()) < len(body):
            if reader.read_w_string('utf-16') == '_lzma.pyd':
                break
            reader.skip(reader.u64())
        body[at:at + 18] = 'flake.exe'.encode('utf-16le')
        modified = B'KAY' + pyzstd.compress(bytes(body))
        original = archive | self.load() | {'path': bytes}
        files = modified | self.load() | {'path': bytes}
        self.assertEqual(files['flake.exe/1'], original['flake.exe'])
        self.assertEqual(files['flake.exe/2'], original['_lzma.pyd'])
        self.assertNotIn('_lzma.pyd', files)
        self.assertEqual(len(files), len(original))
