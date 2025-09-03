from ... import TestUnitBase
from .test_doctxt import PARAGRAPHS


class TestOfficeCrypt(TestUnitBase):

    def test_simple_samples(self):
        crypt = self.load('space-cowboy')
        doctxt = self.ldu('doctxt')
        data = self.download_sample('e12a6f21e62a300ee86a26d8a1f876113bebf1b52709421d4894f832dd54bcf1')
        output = str(data | crypt | doctxt)
        for p in PARAGRAPHS:
            self.assertIn(p, output)
