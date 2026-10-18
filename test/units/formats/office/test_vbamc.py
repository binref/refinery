import collections

from .. import rename_ole_entry, resize_ole_entry
from . import (
    DOC,
    DOCM,
    DOCX,
    STOMPED_DOCM,
    XLS,
    VBAUnitTestBase,
    invert_checksum,
    list_part_twice,
    rename_vba_project,
)


class TestVBAExtractor(VBAUnitTestBase):

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

    def test_a_stream_named_like_a_module_does_not_replace_the_module(self):
        project = self._project('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        modules = project | self.load() | {'path': bytes}
        renamed = rename_ole_entry(project, 'VBA/__SRP_1', 'main')
        self.assertEqual((renamed | self.load() | {'path': bytes})['Project/main'], modules['Project/main'])

    def test_every_project_of_a_document_that_lists_its_project_twice_is_extracted(self):
        first = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        second = self._project('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        doubled = list_part_twice(first, 'word/vbaProject.bin', lambda _: second)
        expected = collections.Counter(bytes(chunk) for chunk in first | self.load())
        expected.update(bytes(chunk) for chunk in second | self.load())
        self.assertEqual(collections.Counter(bytes(chunk) for chunk in doubled | self.load()), expected)

    def test_the_modules_of_a_project_come_out_below_the_name_of_the_project(self):
        for sample, paths in [
            (DOC, ['Project/ThisDocument', 'Project/UserForm1', 'Project/Module1']),
            (XLS, ['VBAProject/ThisWorkbook', 'VBAProject/Sheet1']),
            (DOCM, ['Project/ThisDocument', 'Project/main']),
        ]:
            with self.subTest(sample=sample[:8]):
                self.assertEqual(list(self._modules(self.download_sample(sample))), paths)

    def test_two_projects_with_one_name_get_a_numbered_folder_each(self):
        other = self._project(STOMPED_DOCM)
        data = self._with_embedded(other)
        own = self._modules(self.download_sample(DOCM))
        embedded = self._modules(other)
        self.assertEqual(list(own), ['Project/ThisDocument', 'Project/main'])
        self.assertEqual(list(embedded), ['Project/ThisDocument', 'Project/msform_ct'])
        expected = {F'1/{path}': code for path, code in own.items()} | {F'2/{path}': code for path, code in embedded.items()}
        self.assertEqual(self._modules(data), expected)

    def test_a_module_path_without_the_number_selects_the_module_of_every_project(self):
        data = self._with_embedded(self._project(STOMPED_DOCM))
        self.assertEqual(list(self._modules(data, 'Project/ThisDocument')), ['1/Project/ThisDocument', '2/Project/ThisDocument'])
        self.assertEqual(list(self._modules(data, '1/Project/ThisDocument')), ['1/Project/ThisDocument'])

    def test_two_projects_with_different_names_are_both_numbered(self):
        data = self._with_embedded(self.download_sample(XLS))
        self.assertEqual(list(self._modules(data)), [
            '1/Project/ThisDocument',
            '1/Project/main',
            '2/VBAProject/ThisWorkbook',
            '2/VBAProject/Sheet1',
        ])

    def test_a_project_name_with_a_slash_is_used_as_stored(self):
        project = rename_vba_project(self._project(DOCM), 'VBA/dir', B'Project', B'Pro/ect')
        self.assertEqual(list(self._modules(project)), ['Pro/ect/ThisDocument', 'Pro/ect/main'])

    def test_a_project_name_of_dots_is_resolved_like_every_extracted_path(self):
        project = rename_vba_project(self._project(DOCM), 'VBA/dir', B'Project', B'.......')
        # a path part of n dots removes n - 1 parents, as for every path extractor
        self.assertEqual(list(self._modules(project)), ['ThisDocument', 'main'])

    def test_the_stream_variable_names_the_part_and_the_stream_of_every_module(self):
        data = self._with_embedded(self.download_sample(XLS))
        self.assertEqual(self._streams(data), [
            'word/vbaProject.bin/VBA/ThisDocument',
            'word/vbaProject.bin/VBA/main',
            'word/embeddings/oleObject1.bin/_VBA_PROJECT_CUR/VBA/ThisWorkbook',
            'word/embeddings/oleObject1.bin/_VBA_PROJECT_CUR/VBA/Sheet1',
        ])
        self.assertEqual(self._streams(self.download_sample(DOC)), [
            'Macros/VBA/ThisDocument',
            'Macros/VBA/UserForm1',
            'Macros/VBA/Module1',
        ])

    def test_a_project_whose_dir_stream_is_cut_short_is_skipped_with_a_warning(self):
        data = self._with_embedded(resize_ole_entry(self._project(STOMPED_DOCM), 'VBA/dir', 100))
        modules, log = self._logged_modules(data)
        self.assertEqual(modules, self._modules(self.download_sample(DOCM)))
        self.assertTrue(any('word/embeddings/oleObject1.bin/VBA/dir' in message for message in log), log)

    def test_a_dir_stream_cut_inside_its_last_module_record_keeps_the_modules_in_front_of_it(self):
        project = self._project(DOCM)
        intact = self._modules(project)
        modules, log = self._logged_modules(resize_ole_entry(project, 'VBA/dir', 707))
        self.assertEqual(modules, {'Project/ThisDocument': intact['Project/ThisDocument']})
        self.assertTrue(any('VBA/dir' in message for message in log), log)

    def test_an_unreadable_part_is_skipped_with_a_warning(self):
        data = invert_checksum(self._with_embedded(self.download_sample(XLS)), 'word/vbaProject.bin')
        modules, log = self._logged_modules(data)
        self.assertEqual(modules, self._modules(self.download_sample(XLS)))
        self.assertTrue(any('word/vbaProject.bin' in message for message in log), log)

    def test_a_module_stream_cut_short_is_skipped_with_a_warning(self):
        project = self._project(DOCM)
        intact = self._modules(project)
        modules, log = self._logged_modules(resize_ole_entry(project, 'VBA/ThisDocument', 2))
        self.assertEqual(modules, {'Project/main': intact['Project/main']})
        self.assertTrue(any('VBA/ThisDocument' in message for message in log), log)

    def test_a_compound_file_that_cannot_be_opened_is_an_error(self):
        data = self.download_sample(DOC)[:0x1000]
        with self.assertRaises(EOFError):
            list(data | self.load())

    def test_a_document_without_macros_gives_nothing(self):
        self.assertEqual(list(self.download_sample(DOCX) | self.load()), [])

    def test_the_format_check_accepts_a_macro_document(self):
        self.assertTrue(self.unit().handles(self.download_sample(DOCM)))
