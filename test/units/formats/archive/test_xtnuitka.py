import json

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

    def test_dos_executable_is_rejected(self):
        data = self.download_sample('f36d9551c1917a7990db2b4582191656d748179ea2bd15499294388e9c4fa458')
        self.assertFalse(self.load().handles(data))
