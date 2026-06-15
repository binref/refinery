from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba

from refinery.lib.scripts.vba.deobfuscation.deadcode import (
    VbaDeadVariableRemoval,
    VbaEmptyProcedureRemoval,
)


class TestVbaDeadVariableRemoval(TestVba):

    def test_dead_variable_removal(self):
        code = cleandoc("""
            Sub T()
              x = 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), '')
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), cleandoc("""
            Sub T()
            End Sub
        """))

    def test_dead_variable_keep_calls(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), code)

    def test_dead_variable_keep_used(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
              y = x
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), cleandoc("""
            Sub T()
              x = Foo()
            End Sub
        """))

    def test_regression_overeager_removal(self):
        code = cleandoc("""
            a.Close
            b = z.function(x)
        """)
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), code)

    def test_function_return_value_not_treated_as_dead(self):
        code = cleandoc("""
            Function GetKey() As String
              GetKey = "secret"
            End Function

            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), code)

    def test_dead_variable_removed_despite_same_named_function(self):
        code = cleandoc("""
            Function Total() As Long
              Total = 1
            End Function
            Sub T()
              Total = 5
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaDeadVariableRemoval), cleandoc("""
            Function Total() As Long
              Total = 1
            End Function

            Sub T()
              G 1
            End Sub
        """))


class TestVbaEmptyProcedureRemoval(TestVba):

    def test_empty_sub_removed(self):
        code = cleandoc("""
            Sub Junk()
            End Sub
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_function_removed(self):
        code = cleandoc("""
            Function Junk()
            End Function
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_property_removed(self):
        code = cleandoc("""
            Property Get Junk()
            End Property
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_sub_called_preserved(self):
        code = cleandoc("""
            Sub Junk()
            End Sub

            Sub T()
              Junk
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), code)

    def test_nonempty_sub_uncalled_preserved(self):
        code = cleandoc("""
            Sub Junk()
              MsgBox "hi"
            End Sub

            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), code)

    def test_mixed_empty_procedures(self):
        code = cleandoc("""
            Sub A()
            End Sub
            Sub B()
            End Sub
            Sub T()
              A
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), cleandoc("""
            Sub A()
            End Sub

            Sub T()
              A
            End Sub
        """))

    def test_empty_sub_called_from_other_preserved(self):
        code = cleandoc("""
            Sub Junk()
            End Sub

            Sub Helper()
              Junk
            End Sub

            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._apply(code, VbaEmptyProcedureRemoval), code)
