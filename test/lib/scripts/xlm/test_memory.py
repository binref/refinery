from __future__ import annotations

from refinery.lib.scripts.xlm.memory import XlmFiles, XlmMemory
from test import TestBase


class TestXlmFiles(TestBase):

    def test_a_write_appends_to_the_file_the_program_opened(self):
        files = XlmFiles()
        self.assertEqual(files.write('payload.js', 'a'), False)
        files.open('payload.js')
        self.assertEqual(files.write('payload.js', 'a'), True)
        self.assertEqual(files.write('payload.js', 'b'), True)
        self.assertEqual(files.size('payload.js'), 2)

    def test_an_open_of_a_name_the_program_already_used_keeps_its_content(self):
        files = XlmFiles()
        files.open('payload.js')
        files.write('payload.js', 'a')
        files.open('payload.js')
        self.assertEqual(files.size('payload.js'), 1)
        self.assertEqual(files.first(), 'payload.js')

    def test_the_first_file_answers_a_write_that_names_none(self):
        files = XlmFiles()
        self.assertEqual(files.first(), 'default_filename')
        files.open('one.tmp')
        files.open('two.tmp')
        self.assertEqual(files.first(), 'one.tmp')


class TestXlmMemory(TestBase):

    def test_a_write_lands_in_the_region_the_address_names(self):
        memory = XlmMemory()
        base = memory.allocate(0x00400000, 16)
        self.assertEqual(base, 0x00400000)
        self.assertEqual(memory.write(base, b'ABCD', 4), True)
        self.assertEqual(memory.write(base + 4, b'EFGH', 4), True)
        self.assertEqual(bytes(memory._regions[0].data[:8]), b'ABCDEFGH')

    def test_an_allocation_at_a_reserved_address_moves_past_every_region(self):
        memory = XlmMemory()
        first = memory.allocate(0x00400000, 16)
        second = memory.allocate(0x00400008, 16)
        self.assertEqual(second, first + 16 + 4096)
        self.assertEqual(memory.write(second, b'ABCD', 4), True)
        self.assertEqual(memory.write(first, b'ABCD', 4), True)

    def test_a_write_outside_every_region_does_not_happen(self):
        memory = XlmMemory()
        memory.allocate(0x00400000, 8)
        self.assertEqual(memory.write(0x00500000, b'ABCD', 4), False)
        self.assertEqual(memory.write(0x00400000, b'ABCD', 16), False)
