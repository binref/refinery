import json

from ... import TestUnitBase


class TestNuitkaExtractor(TestUnitBase):

    def test_modified_archive_deflate1(self):
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        data = data | self.ldu('xt7z', 'flake.exe') | self.load('flake.exe') | self.ldu('pemeta', '-cP') | json.loads
        self.assertEqual(data['TimeStamp']['Linker'], '2023-09-20 21:12:44')
