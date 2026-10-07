from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


class TestAu3DeobfuscationSkeleton(TestBase):
    """
    The AutoIt3 deobfuscation framework currently registers no passes. These tests formalize that
    it is wired up but inert: it applies zero transformations and leaves the tree untouched.
    """

    SOURCES = [
        '$x = 1 + 2 * 3\nMsgBox(0, "", $x)\n',
        'Func f($a)\nReturn $a * 2\nEndFunc\n',
        'For $i = 0 To 10 Step 2\n$s &= Hex($i, 2)\nNext\n',
        '#include <String.au3>\n$s = StringReverse("abc")\n',
    ]

    def test_returns_zero_steps(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            steps = deobfuscate(ast)
            self.assertEqual(steps, 0)

    def test_output_unchanged(self):
        synth = Au3Synthesizer()
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            before = synth.convert(ast)
            deobfuscate(ast)
            after = synth.convert(ast)
            self.assertEqual(before, after)

    def test_no_parse_errors_on_wellformed_input(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            self.assertEqual(ast.errors, [])

    def test_parse_errors_on_malformed_input(self):
        ast = Au3Parser('$x = = 1\n').parse()
        self.assertNotEqual(ast.errors, [])
