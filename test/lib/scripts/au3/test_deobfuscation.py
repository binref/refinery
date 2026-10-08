from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


class TestAu3Deobfuscation(TestBase):
    """
    The pipeline over whole scripts: each group's changes re-run the groups that depend on
    them, which is what resolves the chains no single pass can — an alias rewrite unmasking the
    builtin a fold then evaluates, a fold unmasking the literal an `Execute` splice then reads.
    """

    SOURCES = [
        '$x = 1 + 2 * 3\nMsgBox(0, "", $x)\n',
        'Func f($a)\nReturn $a * 2\nEndFunc\n',
        'For $i = 0 To 10 Step 2\n    $s &= Hex($i, 2)\nNext\n',
        '#include <String.au3>\n$s = StringReverse("abc")\n',
    ]

    def test_constant_soup_folds_and_propagates(self):
        ast = Au3Parser(self.SOURCES[0]).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), '$x = 7\nMsgBox(0, "", 7)\n')

    def test_an_execute_call_splices_and_the_result_folds(self):
        ast = Au3Parser('$x = Execute("1 + 2 * 3")\n').parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), '$x = 7\n')

    def test_an_alias_chain_resolves_through_the_groups(self):
        """
        The distilled decoder shape: a variable naming `Execute` through one more variable
        naming the decoder builtin, so no single pass sees the whole chain — the alias rewrite
        unmasks the second alias, the fold produces the literal the `Execute` splice reads, and
        the splice result is the string the decoder returned.
        """
        ast = Au3Parser(
            'Local $e = Execute\n'
            'Local $b = $e("BinaryToString")\n'
            '$v = $e($b("0x22414243" & "4422"))\n'
        ).parse()
        self.assertGreater(deobfuscate(ast), 0)
        self.assertEqual(Au3Synthesizer().convert(ast), (
            'Local $e = Execute\n'
            'Local $b = Execute("BinaryToString")\n'
            '$v = "ABCD"\n'
        ))

    def test_declarations_the_passes_do_not_own_stay_standing(self):
        """
        The alias declarations stay behind as dead code — removing them is a later phase's
        question — and the multiply-defined variables the passes cannot prove a value for are
        left alone.
        """
        ast = Au3Parser(self.SOURCES[2]).parse()
        deobfuscate(ast)
        self.assertEqual(Au3Synthesizer().convert(ast), self.SOURCES[2])

    def test_running_the_pipeline_again_changes_nothing(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            deobfuscate(ast)
            once = Au3Synthesizer().convert(ast)
            self.assertEqual(deobfuscate(ast), 0)
            self.assertEqual(Au3Synthesizer().convert(ast), once)

    def test_no_parse_errors_on_wellformed_input(self):
        for source in self.SOURCES:
            ast = Au3Parser(source).parse()
            self.assertEqual(ast.errors, [])

    def test_parse_errors_on_malformed_input(self):
        ast = Au3Parser('$x = = 1\n').parse()
        self.assertNotEqual(ast.errors, [])
