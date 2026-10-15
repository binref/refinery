import collections
import io
import zipfile

from ... import TestUnitBase
from .. import rename_ole_entry
from . import list_part_twice


class TestVBAExtractor(TestUnitBase):

    def test_maldoc_01(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertIn(B'http://109.94.209'B'.91/12340.txt', code[0])

    def test_maldoc_02(self):
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        unit = self.load()
        code = list(data | unit)
        self.assertIn(B'ActiveDocument.Content.Find.Execute FindText:="$1", ReplaceWith:=dowKarolYou, Replace:=wdReplaceAll', code[0])

    def test_do_not_extract_plaintext(self):
        data = b"some plaintext data"
        unit = self.load()
        self.assertEqual(bytes(data | unit), b'')

    def _project(self, sample: str) -> bytes:
        with zipfile.ZipFile(io.BytesIO(self.download_sample(sample))) as archive:
            return archive.read('word/vbaProject.bin')

    def test_a_stream_named_like_a_module_does_not_replace_the_module(self):
        project = self._project('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        modules = project | self.load() | {'path': bytes}
        renamed = rename_ole_entry(project, 'VBA/__SRP_1', 'main')
        self.assertEqual((renamed | self.load() | {'path': bytes})['VBA/main'], modules['VBA/main'])

    def test_every_project_of_a_document_that_lists_its_project_twice_is_extracted(self):
        first = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        second = self._project('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        doubled = list_part_twice(first, 'word/vbaProject.bin', lambda _: second)
        expected = collections.Counter(bytes(chunk) for chunk in first | self.load())
        expected.update(bytes(chunk) for chunk in second | self.load())
        self.assertEqual(collections.Counter(bytes(chunk) for chunk in doubled | self.load()), expected)
