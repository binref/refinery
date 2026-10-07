from ... import TestUnitBase

import hashlib

import pytest

from refinery.lib.chm import CHM

FARMANAGER_HELP = 'b329740e3729487b4475985ec4348da58c880d812c76a39b445c39c9fc57c5c8'
HP_HELP = '7584ece3f33b66ef69d111d0c7104d8d033e0d8c3ee918261cfac57768d30f1d'


def contents(data):
    chm = CHM.Parse(memoryview(data))
    entries = {
        path: (entry, chm.extractor(entry)) for path, entry in chm.filesystem.items()
        if entry.length > 0 and not path.startswith('::DataSpace')
    }
    result = {}
    for path, (entry, extract) in entries.items():
        try:
            result[path] = hashlib.sha256(extract()).digest()
        except Exception as error:
            result[path] = error
    return chm, result


@pytest.mark.cythonized
class TestChmExtractor(TestUnitBase):

    def test_chm_normal_document(self):
        data = self.download_sample('b329740e3729487b4475985ec4348da58c880d812c76a39b445c39c9fc57c5c8')
        unit = self.load('9.html')
        self.assertTrue(unit.handles(data))
        test = data | unit | str
        self.assertIn('http://api.farmanager.com/ru/service_functions/panelcontrol.html', test)

    def test_offset_count_regression(self):
        data = self.download_sample('7584ece3f33b66ef69d111d0c7104d8d033e0d8c3ee918261cfac57768d30f1d')
        unit = self.load('html/NoHelp1.htm')
        self.assertTrue(unit.handles(data))
        test = data | unit | self.ldu('recode') | str
        self.assertIn('CONTENT="HP05206873"', test)

    def _assert_damage_fails_only_the_files_up_to_the_next_reset(self, sample: str, block: int):
        data = self.download_sample(sample)
        chm, intact = contents(data)
        section = chm.sections[1]
        start = block * section.block_size
        end = (block - block % section.reset_interval + section.reset_interval) * section.block_size
        damaged = bytearray(data)
        damaged[chm.sections[0].offset + section.offset + section.block_offsets[block] + 7] ^= 0xFF
        _, result = contents(damaged)
        for path, digest in result.items():
            entry = chm.filesystem[path]
            if entry.section_index == 1 and entry.offset < end and entry.offset + entry.length > start:
                self.assertIsInstance(digest, Exception, path)
            else:
                self.assertEqual(digest, intact[path], path)

    def test_damage_in_a_middle_block_fails_only_the_files_up_to_the_next_reset(self):
        self._assert_damage_fails_only_the_files_up_to_the_next_reset(FARMANAGER_HELP, 10)

    def test_damage_in_the_first_reset_interval_fails_only_the_files_up_to_the_next_reset(self):
        self._assert_damage_fails_only_the_files_up_to_the_next_reset(HP_HELP, 1)
