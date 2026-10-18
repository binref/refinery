from __future__ import annotations

import io
import zipfile

from refinery.lib.ole.file import OleFile
from refinery.lib.ole.vba import VBADirectory, decompress_stream
from refinery.lib.structures import EOF

from ... import TestBase


class TestDirStream(TestBase):

    def _dir_stream(self) -> bytearray:
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            project = archive.read('word/vbaProject.bin')
        return decompress_stream(OleFile(project).openstream('VBA/dir').read())

    def test_the_dir_stream_of_a_word_project(self):
        directory = VBADirectory.Parse(memoryview(self._dir_stream()))
        self.assertEqual(directory.name, 'Project')
        self.assertEqual(directory.codepage, 1251)
        self.assertTrue(directory.is_64bit)
        self.assertEqual([module.name for module in directory.module_records()], ['ThisDocument', 'main'])
        self.assertEqual([module.stream_name_unicode for module in directory.module_records()], ['ThisDocument', 'main'])

    def test_a_project_name_that_runs_past_the_end_of_the_stream_makes_the_dir_stream_unreadable(self):
        data = self._dir_stream()
        position = data.index(B'\x04\x00\x07\x00\x00\x00Project')
        data[position + 2:position + 6] = len(data).to_bytes(4, 'little')
        with self.assertRaises(EOF):
            VBADirectory.Parse(memoryview(data))
