from unittest.mock import patch

from refinery.units.formats.archive.xtnuitka import xtnuitka
from refinery.units.formats.archive.xtsql import xtsql

from ... import TestUnitBase


class TestAutoExtractor(TestUnitBase):

    def _dos_self_extracting_archive(self):
        return self.download_sample('f36d9551c1917a7990db2b4582191656d748179ea2bd15499294388e9c4fa458')

    def _nuitka_onefile_executable(self):
        data = self.download_sample(
            '3a5a8ea5e4e45a90ac0964b92511983e663143702eb27706f714c71f447435d6', 'OKFR20ALOEN23UPS')
        return data | self.ldu('xt7z', 'flake.exe') | bytes

    def test_extraction_skips_unit_whose_format_check_fails(self):
        data = self._dos_self_extracting_archive()
        with patch.object(xtsql, 'handles', side_effect=ValueError):
            chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        self.assertEqual(chunks['DEDICATE.DOC'], 'edc82bf30189cccb2c5ab3a18d212149ba82e3c14c700ea58433389a3d1e8f7e')

    def test_format_check_skips_unit_whose_format_check_fails(self):
        data = self._dos_self_extracting_archive()
        with patch.object(xtsql, 'handles', side_effect=ValueError):
            self.assertTrue(self.load().handles(data))

    def test_uncertain_units_are_tried_after_one_that_extracts_nothing(self):
        data = self._nuitka_onefile_executable()
        with patch.object(xtnuitka, 'handles', return_value=None):
            paths = {chunk['path'] for chunk in data | self.load()}
        self.assertIn('flake.exe', paths)
