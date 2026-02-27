from .. import TestUnitBase


class TestPYC(TestUnitBase):

    def test_against_pyc_from_archive(self):
        from refinery.lib.id import get_structured_data_type, Fmt
        main = self.download_sample('1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7')
        data = main | self.ldu('xtpyi', 'pyimod00_crypto_key.pyc') | bytes
        self.assertEqual(get_structured_data_type(data), Fmt.PYC)
        goal = main | self.ldu('xtpyi', 'pyimod00_crypto_key.py', decompile=True) | bytes
        self.assertLessEqual(Fmt.TEXT, get_structured_data_type(goal))
        test = data | self.load() | bytes
        self.assertEqual(test, goal)
