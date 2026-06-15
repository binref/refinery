from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba

from refinery.lib.scripts.vba.deobfuscation.constants import VbaConstantInlining


class TestVbaConstantInlining(TestVba):

    def test_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const K = "val"
              F K
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaConstantInlining), cleandoc("""
            Sub T()
              F "val"
            End Sub
        """))

    def test_constant_multi_assign(self):
        code = cleandoc("""
            Sub T()
              y = 1
              y = 2
              x = y
              F x
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaConstantInlining), code)

    def test_regression_matchgroup(self):
        code = cleandoc(r"""
            const a = "\3"
            b = a
        """)
        self.assertEqual(self._apply(code, VbaConstantInlining), r'b = "\3"')

    def test_constant_not_inlined_across_procedures(self):
        code = cleandoc("""
            Sub A()
              Const n = 7
              G n
            End Sub
            Sub B(n)
              H n
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaConstantInlining), cleandoc("""
            Sub A()
              G 7
            End Sub

            Sub B(n)
              H n
            End Sub
        """))
