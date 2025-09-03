from ... import TestUnitBase


class TestISOFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('d4bd4131c785b46d7557be3a94015db09e8e183eaafc6af366e849b0175da681')
        unit = self.load()
        unpacked = unit(data)
        self.assertTrue(unpacked.startswith(b'{\\rtf1'), 'unpacked file is not an RTF document')
        self.assertIn(B'EU48RUK5N4YDFT73I3RIF3H3UH', data)

    def test_real_world_01(self):
        data = self.download_sample('1c4b99cb11181ab2cca65fca41f38b5e7efbc12bf2b46cb1f6e73a029f9d97f0')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('4963339bb261a8abc0dfdc95cd37dd3d5624f283402bfd72c6486e19bb5aedd5', chunks['start.cmd'])
        self.assertEqual('bdceb5afb4cb92f1bb938948cbe496bfa3de8c8d7b1f242cb133e2b18600256b', chunks['macosx.dat'])
        self.assertEqual('36484434a281c6ed81966682dede4cbb5cfb7eed775cdcf001a348939e3bb331', chunks['Attachments.lnk'])

    def test_real_world_02(self):
        data = self.download_sample('3b215a9d7af057b5bcdd2ad726333d66ef1701eae11cb1fb9d12c0338f5693a0')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('c826cda4ccfe815e0be4e9a007c0c32a6e7d9757140f0d1123a4e1e134e553c3', chunks['readme.txt'])
        self.assertEqual('81deb33e1cdd6bcca6e8464141ddd28de8cf3c586ddca2ce39c5448b43461c1b', chunks['readme.html'])
        self.assertEqual('b5bec5fab272c825a54b6eed129949db9d79b94fa8fce5a550a5901b2ec3937a', chunks['plpinstc.com'])
        self.assertEqual('90cdf6e126e574409d77b1fafa1945ec251e59a7c050d88d43e838a20d6cf590', chunks['liesmich.txt'])
        self.assertEqual('cf8f25af4cfe40ae8e1be28ad49220ed01c6ec7e23917cb4c181078532e352b3', chunks['liesmich.html'])
        self.assertEqual('e303921ad81f685d35ec38122320c8633255d05fa191b8d97e7a7d6555b26b8d', chunks['licence.txt'])
        self.assertEqual('eaf3aa81fe9fa245e4b9f9d0978e70b1a3822ef8cf4f4d7f2029aeadd3970b47', chunks['isolinux.cfg'])
        self.assertEqual('2ecb32325499df028e8cf980918a91964c0c15c4b0e65cc01c5f2a2899a77363', chunks['isolinux.bin'])
        self.assertEqual('637e2c44c586bb18b4d72791eda901fb5ff8c1e80a7977719df2f98768b1f75d', chunks['boot.catalog'])

    def test_stripping_revision_numbers(self):
        data = self.download_sample('52e488784d46b3b370836597b1565cf18a5fa4a520d0a71297205db845fc9d26')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('187c69325af91afb8df501ba842fe993496f1e4e7914c437f26cdb365f1105dd', chunks['TL2064100007xls.exe'])
