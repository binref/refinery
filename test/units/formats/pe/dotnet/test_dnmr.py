from .... import TestUnitBase


class TestDotNetManagedResourceDeserializer(TestUnitBase):

    def test_real_world_01(self):
        rsrc = self.ldu('dnrc', '70218dfd-5f9f-d4.Resources.resources')
        data = rsrc(self.download_sample('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf'))
        unit = self.load('f0787dcf-8df6-f70')
        test = data | unit | bytes
        self.assertTrue(test.startswith(bytes.fromhex('89504E470D0A1A0A')))

    def test_real_world_02(self):
        rsrc = self.ldu('dnrc', '70218dfd-5f9f-d4.Resources.resources')
        data = rsrc(self.download_sample('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf'))
        unit = self.load('b091b52a-98c2-06')
        self.assertEqual(unit(data), bytes((29, 0, 0, 0)))
