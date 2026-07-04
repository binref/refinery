from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.php.deobfuscation import deobfuscate
from refinery.lib.scripts.php.parser import PhpParser
from refinery.lib.scripts.php.synth import PhpSynthesizer


class TestPhpDeobfuscationSkeleton(TestBase):
    """
    The PHP deobfuscation framework currently registers no passes. These tests formalize that it is
    wired up but inert: it applies zero transformations and leaves the tree untouched.
    """

    SOURCES = [
        '<?php $x = 1 + 2 * 3; echo $x;',
        '<?php function f($a) { return $a * 2; }',
        '<?php class C { public int $n = 0; function m() { return $this->n; } }',
        '<html><?php echo "hi"; ?></html>',
    ]

    def test_returns_zero_steps(self):
        for source in self.SOURCES:
            ast = PhpParser(source).parse()
            steps = deobfuscate(ast)
            self.assertEqual(steps, 0)

    def test_output_unchanged(self):
        synth = PhpSynthesizer()
        for source in self.SOURCES:
            ast = PhpParser(source).parse()
            before = synth.convert(ast)
            deobfuscate(ast)
            after = synth.convert(ast)
            self.assertEqual(before, after)

    def test_no_parse_errors_on_wellformed_input(self):
        for source in self.SOURCES:
            ast = PhpParser(source).parse()
            self.assertEqual(ast.errors, [])

    def test_parse_errors_on_malformed_input(self):
        ast = PhpParser('<?php { $a;').parse()
        self.assertNotEqual(ast.errors, [])
