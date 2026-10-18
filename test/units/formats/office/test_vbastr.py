from .. import resize_ole_entry
from . import DOCM, DOCX, STOMPED_DOCM, VBAUnitTestBase, invert_checksum, list_part_twice

FORMS_DOC = '303bc0f4742c61166d05f7a14a25b3c118fa3ba04298b8370071b4ed19f1a987'


class TestVBAStr(VBAUnitTestBase):

    def test_blogpost_example(self):
        # https://nvdp01.github.io/analysis/2022/06/29/extracting-vba-userform-field-values.html
        data = self.download_sample('303bc0f4742c61166d05f7a14a25b3c118fa3ba04298b8370071b4ed19f1a987')
        test = data | self.load('tabyAeEx3574.tip') | str
        self.assertEqual(test, 'nnacShtlaeHW\\putratS\\sm')

    def test_stomped_document_01(self):
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        unit = self.load()
        strings = list(data | unit)
        self.assertEqual(len(strings), 5)
        self.assertIn(bytes.fromhex('48 EF BF BD 2C 5C 59'), strings)
        self.assertIn(bytes.fromhex('48 EF BF BD 2C 56 37'), strings)
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

    def test_a_form_that_cannot_be_read_is_skipped_with_a_warning(self):
        document = self.download_sample(FORMS_DOC)
        intact = self._modules(document)
        variables, log = self._logged_modules(resize_ole_entry(document, 'Macros/vbFrmmyqVySwU1696/o', 2))
        expected = {path: value for path, value in intact.items() if not path.startswith('Project/vbFrmmyqVySwU1696/')}
        self.assertEqual(variables, expected)
        self.assertTrue(any('Macros/vbFrmmyqVySwU1696' in message for message in log), log)

    def test_the_project_number_is_the_one_that_the_macro_units_give(self):
        alone = self._modules(self.download_sample(FORMS_DOC))
        data = self._with_embedded(self.download_sample(FORMS_DOC))
        self.assertEqual(self._modules(data), {F'2/{path}': value for path, value in alone.items()})
        self.assertEqual({str(path).split('/')[0] for path in data | self.ldu('vbamc') | {'path': bytes}}, {'1', '2'})

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
