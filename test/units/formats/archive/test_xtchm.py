from ... import TestUnitBase

import hashlib

import pytest

from refinery.lib.chm import CHM
from refinery.units.formats.archive.xtchm import xtchm

FARMANAGER_HELP = 'b329740e3729487b4475985ec4348da58c880d812c76a39b445c39c9fc57c5c8'
HP_HELP = '7584ece3f33b66ef69d111d0c7104d8d033e0d8c3ee918261cfac57768d30f1d'


def files(chm: CHM):
    return {entry.name: entry for entry in chm.entries()}


def digests(data) -> dict[str, str]:
    return {str(chunk['path']): hashlib.sha256(chunk).hexdigest() for chunk in data | xtchm() | [...]}


def contents(data):
    chm = CHM.Parse(memoryview(data))
    entries = {
        path: (entry, chm.extractor(entry)) for path, entry in files(chm).items()
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
            entry = files(chm)[path]
            if entry.section_index == 1 and entry.offset < end and entry.offset + entry.length > start:
                self.assertIsInstance(digest, Exception, path)
            else:
                self.assertEqual(digest, intact[path], path)

    def test_damage_in_a_middle_block_fails_only_the_files_up_to_the_next_reset(self):
        self._assert_damage_fails_only_the_files_up_to_the_next_reset(FARMANAGER_HELP, 10)

    def test_damage_in_the_first_reset_interval_fails_only_the_files_up_to_the_next_reset(self):
        self._assert_damage_fails_only_the_files_up_to_the_next_reset(HP_HELP, 1)

    def test_an_entry_that_names_a_section_which_does_not_exist_fails_alone(self):
        data = bytearray(self.download_sample(FARMANAGER_HELP))
        chm, intact = contents(data)
        path = next(p for p, e in files(chm).items() if p.endswith('.html') and e.section_index == 1)
        name = path.encode('utf8')
        # a listing entry stores the length of its name, the name, and then its section index
        entry = bytes([len(name)]) + name + B'\x01'
        data[data.index(entry) + len(entry) - 1] = len(chm.sections)
        damaged, result = contents(data)
        self.assertEqual(files(damaged)[path].section_index, len(chm.sections))
        self.assertIsInstance(result.pop(path), IndexError)
        del intact[path]
        self.assertEqual(result, intact)

    def test_two_pages_with_the_same_name_are_both_extracted(self):
        data = self.download_sample(FARMANAGER_HELP)
        original = data | self.load() | {'path': bytes}
        modified = bytearray(data)
        # both names have the same length, so the directory entry is renamed in place
        self.assertEqual(modified.count(B'/11.html'), 1)
        at = modified.index(B'/11.html')
        modified[at:at + 8] = B'/10.html'
        pages = modified | self.load('10.html') | [bytes]
        self.assertEqual(pages, [original['10.html'], original['11.html']])

    _RESET_TABLE = (
        '::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/'
        'InstanceData/ResetTable'
    )

    def _listing_chunk(self, data: bytearray, k: int) -> int:
        position = -1
        for _ in range(k + 1):
            position = data.index(B'PMGL', position + 1)
        return position

    def _add_free_space(self, data: bytearray, chunk: int, delta: int):
        free = int.from_bytes(data[chunk + 4:chunk + 8], 'little') + delta
        data[chunk + 4:chunk + 8] = free.to_bytes(4, 'little')

    def test_internal_part_named_again_at_the_end_of_the_previous_chunk_is_found_through_the_index(self):
        data = self.download_sample(FARMANAGER_HELP)
        modified = bytearray(data)
        chunk = self._listing_chunk(modified, 1)
        folder = self._RESET_TABLE[:-len('ResetTable')].encode('utf8')
        # the last entry of the chunk is the folder of the reset table: name, then three zero values
        entry = bytes([len(folder)]) + folder + bytes(3)
        decoy = bytes([len(self._RESET_TABLE)]) + self._RESET_TABLE.encode('utf8') + bytes(3)
        at = modified.index(entry, chunk, chunk + 0x1000)
        growth = len(decoy) - len(entry)
        modified[at:at + len(entry) + growth] = decoy
        self._add_free_space(modified, chunk, -growth)
        self.assertEqual(len(modified), len(data))
        self.assertEqual(digests(modified), digests(data))

    def test_internal_part_listed_twice_in_one_chunk_is_found_as_its_first_entry(self):
        data = self.download_sample(FARMANAGER_HELP)
        modified = bytearray(data)
        chunk = self._listing_chunk(modified, 2)
        name = self._RESET_TABLE.encode('utf8')
        # name, section 0, offset 134 and length 200, each length and number as a 7-bit encoded integer
        real = bytes([len(name)]) + name + B'\x00\x81\x06\x81\x48'
        at = modified.index(real, chunk, chunk + 0x1000) + len(real)
        modified[at:at + len(real)] = real[:-4] + B'\x81\x00' + real[-2:]
        self._add_free_space(modified, chunk, -len(real))
        # the last two bytes of a listing chunk count its entries
        modified[chunk + 0x1000 - 2] += 1
        self.assertEqual(digests(modified), digests(data))
