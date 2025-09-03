from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestMetaVarGlobal(TestMetaBase):

    def test_mvg_01(self):
        pl = L('emit FOO [| nop [| put x BAR | mvg ]| cca var:x ]')
        self.assertEqual(pl(), B'FOOBAR')

    def test_mvg_02(self):
        pl = L('emit FOO [| nop [[| put x BAR | mvg ]| nop ]| pf {}{x} ]')
        self.assertEqual(pl(), B'FOO{x}')

    def test_mvg_03(self):
        pl = L('emit FOO [| nop [[| put x BAR | mvg -t ]| nop ]| pf {}{x} ]')
        self.assertEqual(pl(), B'FOOBAR')

    def test_cannot_propagate_variables_with_ambiguous_values(self):
        pl = L('emit FOO [| rex . [| put x | mvg ]| pf {}{x} ]')
        self.assertEqual(pl(), B'FOO{x}')

    def test_can_propagate_variables_with_unambiguous_values(self):
        pl = L('emit FOO [| rex . [| put x BAR | mvg ]| pf {}{x} ]')
        self.assertEqual(pl(), B'FOOBAR')

    def test_scope_cannot_be_increased(self):
        pl = L('emit s: [| put x alpha [| nop [| put x beta | mvg ]| nop ]| pf {x} ]')
        self.assertEqual(pl(), B'alpha')
