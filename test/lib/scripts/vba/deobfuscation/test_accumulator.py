from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba


class TestVbaStringAccumulator(TestVba):

    def test_accumulator_basic_concat(self):
        code = cleandoc("""
            Sub T()
              x = "hello"
              x = x & " world"
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "hello world"
            End Sub
        """))

    def test_accumulator_long_chain(self):
        lines = ['Sub T()']
        lines.append('  x = "a"')
        for _ in range(50):
            lines.append('  x = x & "b"')
        lines.append('  F x')
        lines.append('End Sub')
        code = '\n'.join(lines)
        result = self._deobfuscate(code)
        self.assertEqual(result, F'Sub T()\n  F "a{"b" * 50}"\nEnd Sub')

    def test_accumulator_with_replace(self):
        code = cleandoc("""
            Sub T()
              x = "aXbXc"
              x = x & "dXe"
              x = Replace(x, "X", "")
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "abcde"
            End Sub
        """))

    def test_accumulator_prepend(self):
        code = cleandoc("""
            Sub T()
              x = "world"
              x = "hello " & x
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "hello world"
            End Sub
        """))

    def test_accumulator_chain_breaks_on_non_assignment(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              F x
              x = x & "b"
              G x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), code)

    def test_accumulator_chain_breaks_on_different_variable(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              y = "z"
              x = x & "b"
              F x, y
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "ab", "z"
            End Sub
        """))

    def test_accumulator_multi_concat_single_stmt(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              x = x & "b" & "c"
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "abc"
            End Sub
        """))

    def test_accumulator_replace_then_concat(self):
        code = cleandoc("""
            Sub T()
              x = "aXb"
              x = Replace(x, "X", "")
              x = x & "c"
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "abc"
            End Sub
        """))

    def test_accumulator_inlined_after_folding(self):
        code = cleandoc("""
            Sub T()
              x = "hel"
              x = x & "lo"
              F x
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              F "hello"
            End Sub
        """))

    def test_accumulator_surrogate_recombination(self):
        hi = '\uD83D'
        lo = '\uDCC6'
        combined = '\U0001F4C6'
        code = cleandoc(F"""
            Sub T()
              x = "a{hi}"
              x = x & "{lo}b"
              x = Replace(x, "{combined}", "")
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "ab"
            End Sub
        """))
