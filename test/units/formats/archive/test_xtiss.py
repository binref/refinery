from ... import TestUnitBase


class TestZipFileExtractor(TestUnitBase):

    def test_example_v1_archive(self):
        data = self.download_sample('70f6f67ca03d4eb687e1980caf2e4b3e39b1f888624ffc93d2ac988b010e9d75')
        out = str(data | self.load('Setup.ini') | self.ldu('recode')).strip()
        self.assertTrue(out.endswith('http:''//www.installengine''.com/Msiengine20/instmsiw.exe'))

    def test_example_v2_archive(self):
        data = self.download_sample('d68f0ed81b6a19f566af1c00daae4a595533a743671dc9d23303b5b81cd90006')
        out = str(data | self.load('Setup.ini') | self.ldu('recode')).strip()
        self.assertTrue(out.endswith('PreReq0=Microsoft .NET Framework 4.8 Full.prq'))
