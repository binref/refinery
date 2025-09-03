from .... import TestUnitBase


class TestDotNetResourceExtractor(TestUnitBase):

    def test_real_world_01(self):
        unit = self.load('70218dfd-5f9f-d4*')
        data = self.download_sample('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        data = unit(data)
        self.assertTrue(data.startswith(b'\xCE\xCA\xEF\xBE'))
        self.assertIn(b'PublicKeyToken=b03f5f7f11d50a3a', data)
