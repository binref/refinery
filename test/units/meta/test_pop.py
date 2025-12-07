from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


class TestPop(TestUnitBase):

    def test_error_when_variables_cannot_be_assigned(self):
        pl = self.ldu('push') [ self.ldu('rex', 'XX(.)', '{1}') | self.load('oops') ] # noqa
        with self.assertRaises(Exception):
            b'TEST' | pl | None

    def test_regression_pop_does_not_key_error(self):
        pl = L('emit FOO | rex . [| push [| put k XO | pop ]| pf {k} ]')
        self.assertEqual(pl(), B'XOXOXO')

    def test_push_push_pop_pop(self):
        pl = L('emit FOO [| push | push | snip 0 | pop a | cca v:a | pop b | pf {}/{a}/{b} ]')
        self.assertEqual(pl(), B'FOO/{a}/FOOF')
