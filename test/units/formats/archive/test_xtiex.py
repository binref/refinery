from ... import TestUnitBase


class TestIExpressExtractor(TestUnitBase):

    _SAMPLE = '574863ffff2691818b2fcd0d1543eddf07b71577d7535c8bd9b46f2fa7a22390'
    _README = B'Binary Refinery IExpress test file.\r\n'

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

    def _with_admqcmd_named_cabinet(self, point_at_cabinet: bool = False) -> bytearray:
        """
        The test sample with its resource ADMQCMD renamed to CABINET, so that it holds two resources
        named CABINET. The renamed resource keeps its own data unless it is pointed at the data of
        the real cabinet.
        """
        from refinery.lib.shared.pefile import pefile
        data = self.download_sample(self._SAMPLE)
        pe = pefile.PE(data=bytes(data))
        [rcdata] = [e for e in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE').entries if e.id == 10]
        offsets = {
            str(e.name): e.directory.entries[0].data.struct.get_file_offset()
            for e in rcdata.directory.entries if e.name
        }
        modified = bytearray(data)
        name = (7).to_bytes(2, 'little') + 'ADMQCMD'.encode('utf-16le')
        self.assertEqual(modified.count(name), 1)
        at = modified.find(name) + 2
        modified[at:at + 14] = 'CABINET'.encode('utf-16le')
        if point_at_cabinet:
            source = offsets['CABINET']
            target = offsets['ADMQCMD']
            modified[target:target + 8] = data[source:source + 8]
        return modified

    def test_a_resource_named_cabinet_that_is_no_cabinet_is_reported_and_skipped(self):
        data = self._with_admqcmd_named_cabinet()
        with self.load_logged() as (unit, log):
            files = data | unit | {'path': bytes}
        self.assertEqual(files, {'RCDATA/CABINET/2057/readme.txt': self._README})
        self.assertEqual(len(log), 1)
        self.assertIn('RCDATA/CABINET/1033', log[0])

    def test_the_files_of_two_cabinets_lie_below_their_resources(self):
        data = self._with_admqcmd_named_cabinet(point_at_cabinet=True)
        self.assertEqual(data | self.load() | {'path': bytes}, {
            'RCDATA/CABINET/1033/readme.txt': self._README,
            'RCDATA/CABINET/2057/readme.txt': self._README,
        })
