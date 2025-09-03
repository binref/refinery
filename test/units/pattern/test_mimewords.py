from .. import TestUnitBase


class TestMimeWords(TestUnitBase):

    def test_real_world_example(self):
        unit = self.load()

        subjects = B'\n'.join([
            B'Doc. 1: =?UTF-8?B?0JLQvtC/0YDQvtGBINCd0KLQlCDQutC+0LzQsNC90LTQuNGA0L7QstC60Lgg0L/QviDQrdGB0YLQvtC90LjQuC5kb2N4?=',
            B'Doc. 2: =?UTF-8?B?0LvQuNGB0YLQuC3Qt9Cw0L/RgNC+0YjQtdC90L3Rjy5kb2M=?=',
            B'Doc. 3: =?UTF-8?Q?mingi_=C3=A4ge_fail=2Eddoc?=',
            B'Doc. 4: =?UTF-8?Q?OU=CC=88_tax_residency_certificate=2E=2Epdf?=',
            B'Doc. 5: =?UTF-8?Q?OU=CC=88_tax_residency_certificate=2Epdf?=',
            B'Doc. 6: =?UTF-8?Q?Valitsemise_mahu_v=C3=A4hendamine=5Fhaldusalade_kaupa_2019=2Exlsm?=',
        ])

        decoded = U'\n'.join([
            U'Doc. 1: Вопрос НТД командировки по Эстонии.docx',
            U'Doc. 2: листи-запрошення.doc',
            U'Doc. 3: mingi äge fail.ddoc',
            U'Doc. 4: OÜ tax residency certificate..pdf',
            U'Doc. 5: OÜ tax residency certificate.pdf',
            U'Doc. 6: Valitsemise mahu vähendamine_haldusalade kaupa 2019.xlsm'
        ]).encode('UTF8')

        self.assertEqual(decoded, unit(subjects))
