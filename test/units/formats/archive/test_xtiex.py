from ... import TestUnitBase


class TestIExpressExtractor(TestUnitBase):

    _SAMPLE = '574863ffff2691818b2fcd0d1543eddf07b71577d7535c8bd9b46f2fa7a22390'

    def test_packaged_file_is_extracted(self):
        data = self.download_sample(self._SAMPLE)
        self.assertEqual(data | self.load() | {'path': bytes}, {
            'readme.txt': B'Binary Refinery IExpress test file.\r\n'
        })

    def test_resource_reader_is_closed_after_use(self):
        from refinery.units.formats.pe.perc import perc
        data = self.download_sample(self._SAMPLE)
        with self.assertNoInstanceSurvives(perc):
            self.assertEqual(data | self.load() | [bytes], [B'Binary Refinery IExpress test file.\r\n'])
