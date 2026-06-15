from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba


class TestVbaDeobfuscation(TestVba):

    def test_remove_comments(self):
        code = cleandoc("""
            ' Test
            b = a
            ' Test
        """)
        self.assertEqual(self._deobfuscate(code), 'b = a')

    def test_xor_operator(self):
        self.assertEqual(self._deobfuscate('CLng((0 Xor 0))'), 'CLng((0 Xor 0))')

    def test_constant_inline_let(self):
        code = cleandoc("""
            Sub T()
              y = 42
              x = y + 1
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F 43
            End Sub
        """))

    def test_negative_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const X = -1
              y = X + 5
              F y
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F 4
            End Sub
        """))

    def test_builtin_constant_vbobjecterror(self):
        code = cleandoc("""
            Sub T()
              x = vbObjectError
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F -2147221504
            End Sub
        """))

    def test_chr_inlining_in_concat(self):
        code = cleandoc("""
            Sub T()
              On Error Resume Next
              x = Chr(13)
              y = "a" + x + "b"
              F y
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              On Error Resume Next
              F "a" + Chr(13) + "b"
            End Sub
        """))
