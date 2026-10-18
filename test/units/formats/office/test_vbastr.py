from refinery.lib.frame import Chunk
from refinery.units import Unit

from .. import replace_in_ole_stream, resize_ole_entry
from . import DOCM, DOCX, STOMPED_DOCM, VBAUnitTestBase, invert_checksum, list_part_twice

FORMS_DOC = '303bc0f4742c61166d05f7a14a25b3c118fa3ba04298b8370071b4ed19f1a987'


class TestVBAStr(VBAUnitTestBase):

    def test_blogpost_example(self):
        # https://nvdp01.github.io/analysis/2022/06/29/extracting-vba-userform-field-values.html
        data = self.download_sample(FORMS_DOC)
        test = data | self.load('tabyAeEx3574.tip') | str
        self.assertEqual(test, 'nnacShtlaeHW\\putratS\\sm')

    def test_stomped_document_01(self):
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        unit = self.load()
        strings = list(data | unit)
        self.assertEqual(len(strings), 5)
        self.assertIn(bytes.fromhex('48 80 2C 5C 59'), strings)
        self.assertIn(bytes.fromhex('48 80 2C 56 37'), strings)
        self.assertIn(b'Tahomae', strings)
        strings = [
            bytes(s | self.ldu('hex') | self.ldu('xor', 'An2Lcw6Gseh'))
            for s in strings if len(s) > 100]
        self.assertEqual(len(strings), 2)
        self.assertTrue(any(B'function a0_0x4511()' in string for string in strings))

    def test_the_variables_of_a_form_come_out_below_its_project_and_form(self):
        variables = self._modules(self.download_sample(FORMS_DOC))
        self.assertEqual({path.rsplit('/', 2)[0] for path in variables}, {
            'Project/vbFrmeFtIzEB1911',
            'Project/vbFrmEKCqjDo3300',
            'Project/vbFrmmyqVySwU1696',
            'Project/vbFrmrbYH1375',
        })
        self.assertEqual(variables['Project/vbFrmmyqVySwU1696/tabyAeEx3574/tabyAeEx3574.tip'], B'nnacShtlaeHW\\putratS\\sm')

    def test_the_strings_of_a_form_whose_controls_cannot_be_parsed_come_out_below_its_project_and_form(self):
        self.assertEqual(list(self._modules(self.download_sample(STOMPED_DOCM))), [
            'Project/msform_ct/o.v1.val',
            'Project/msform_ct/o.v2.val',
            'Project/msform_ct/o.v3.val',
            'Project/msform_ct/o.v4.val',
            'Project/msform_ct/o.v5.val',
        ])

    def test_a_form_whose_controls_cannot_be_parsed_does_not_cost_the_variables_of_the_other_forms(self):
        stomped = self.download_sample(STOMPED_DOCM)
        forms = self.download_sample(FORMS_DOC)
        data = list_part_twice(stomped, 'word/vbaProject.bin', lambda _: bytes(forms), 'word/embeddings/oleObject1.bin')
        expected = {F'1/{path}': value for path, value in self._modules(stomped).items()}
        expected.update({F'2/{path}': value for path, value in self._modules(forms).items()})
        self.assertEqual(self._modules(data), expected)

    def test_a_form_whose_object_stream_ends_early_falls_back_to_its_strings(self):
        document = self.download_sample(FORMS_DOC)
        intact = self._modules(document)
        variables = self._modules(resize_ole_entry(document, 'Macros/vbFrmmyqVySwU1696/o', 640))
        form = 'Project/vbFrmmyqVySwU1696/'
        others = {path: value for path, value in variables.items() if not path.startswith(form)}
        strings = {path[len(form):]: value for path, value in variables.items() if path.startswith(form)}
        self.assertEqual(others, {path: value for path, value in intact.items() if not path.startswith(form)})
        self.assertTrue(strings)
        self.assertTrue(all(path.startswith('o.') and path.endswith('.val') for path in strings), strings)
        self.assertTrue(any(B'Start Menu' in value for value in strings.values()), strings)

    def test_a_frame_comes_out_below_its_storage_inside_its_form(self):
        document = self.download_sample(FORMS_DOC)
        intact = self._modules(document)
        # the cut object stream makes the frame fall back to its strings: the names of its pages and tabs
        variables = self._modules(resize_ole_entry(document, 'Macros/vbFrmeFtIzEB1911/i13/o', 100))
        self.assertEqual({path: value for path, value in variables.items() if path not in intact}, {
            'Project/vbFrmeFtIzEB1911/i13/o.v1.val': bytes.fromhex('80') + B'Page1',
            'Project/vbFrmeFtIzEB1911/i13/o.v2.val': bytes.fromhex('80') + B'Page2',
            'Project/vbFrmeFtIzEB1911/i13/o.v3.val': bytes.fromhex('80') + B'Tab3',
            'Project/vbFrmeFtIzEB1911/i13/o.v4.val': bytes.fromhex('80') + B'Tab4',
        })
        self.assertEqual({path: value for path, value in variables.items() if path in intact}, intact)

    def test_the_forms_of_a_project_whose_dir_stream_cannot_be_read_keep_the_path_of_their_storage(self):
        document = self.download_sample(FORMS_DOC)
        intact = self._modules(document)
        variables, log = self._logged_modules(resize_ole_entry(document, 'Macros/VBA/dir', 100))
        self.assertEqual(variables, {F'Macros/{path.removeprefix("Project/")}': value for path, value in intact.items()})
        self.assertTrue(any('Macros/VBA/dir' in message for message in log), log)

    def test_a_control_name_outside_ascii_names_the_folder_of_the_control(self):
        # the form stores this name compressed, as one Latin-1 byte per character
        document = replace_in_ole_stream(
            self.download_sample(FORMS_DOC), 'Macros/vbFrmmyqVySwU1696/f', B'tabyAeEx3574', B'taby\xC4eEx3574'
        )
        variables = self._modules(document)
        self.assertEqual(variables['Project/vbFrmmyqVySwU1696/taby\xC4eEx3574/taby\xC4eEx3574.tip'], B'nnacShtlaeHW\\putratS\\sm')

    def test_the_project_number_is_the_one_that_the_macro_units_give(self):
        alone = self._modules(self.download_sample(FORMS_DOC))
        data = self._with_embedded(self.download_sample(FORMS_DOC))
        self.assertEqual(self._modules(data), {F'2/{path}': value for path, value in alone.items()})
        vbamc: Unit = self.ldu('vbamc')
        chunks = [chunk for chunk in data | vbamc if isinstance(chunk, Chunk)]
        macros = {str(chunk.meta['path']): str(chunk.meta['stream']) for chunk in chunks}
        self.assertEqual({path.split('/')[0] for path in macros}, {'1', '2'})
        self.assertTrue(all(
            stream.startswith('word/embeddings/oleObject1.bin/') == path.startswith('2/')
            for path, stream in macros.items()
        ), macros)

    def test_the_stream_variable_names_the_part_and_the_object_stream_of_the_form(self):
        streams = set(self._streams(self._with_embedded(self.download_sample(FORMS_DOC))))
        self.assertEqual(streams, {
            'word/embeddings/oleObject1.bin/Macros/vbFrmeFtIzEB1911/o',
            'word/embeddings/oleObject1.bin/Macros/vbFrmEKCqjDo3300/o',
            'word/embeddings/oleObject1.bin/Macros/vbFrmmyqVySwU1696/o',
            'word/embeddings/oleObject1.bin/Macros/vbFrmrbYH1375/o',
        })

    def test_an_unreadable_part_is_skipped_with_a_warning(self):
        data = invert_checksum(self._with_embedded(self.download_sample(FORMS_DOC)), 'word/vbaProject.bin')
        variables, log = self._logged_modules(data)
        self.assertEqual(variables, self._modules(self.download_sample(FORMS_DOC)))
        self.assertTrue(any('word/vbaProject.bin' in message for message in log), log)

    def test_a_document_without_macros_gives_nothing(self):
        self.assertEqual(list(self.download_sample(DOCX) | self.load()), [])
        self.assertEqual(list(B'some plaintext data' | self.load()), [])

    def test_the_format_check_accepts_a_macro_document(self):
        self.assertTrue(self.unit().handles(self.download_sample(DOCM)))
