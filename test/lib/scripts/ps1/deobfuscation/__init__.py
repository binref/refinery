from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts import set_value
from refinery.lib.scripts.ps1.data import KNOWN_PS_OPERATORS
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import Ps1BinaryExpression, Ps1Script, Ps1UnaryExpression
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1(TestBase):

    def _deobfuscate(
        self,
        source: str,
        remove_junk: bool = True,
        preserve_bare_output: bool = False,
        trust_eval: bool = False,
    ) -> str:
        ast = Ps1Parser(source).parse()
        deobfuscate(
            ast,
            remove_junk=remove_junk,
            preserve_bare_output=preserve_bare_output,
            trust_eval=trust_eval,
        )
        return Ps1Synthesizer().convert(ast)

    def _deobfuscate_iterative(
        self,
        source: str,
        iterations: int = 100,
        remove_junk: bool = True,
        preserve_bare_output: bool = False,
        trust_eval: bool = False,
    ) -> str:
        ast = Ps1Parser(source).parse()
        for _ in range(iterations):
            if not deobfuscate(
                ast,
                remove_junk=remove_junk,
                preserve_bare_output=preserve_bare_output,
                trust_eval=trust_eval,
            ):
                break
        return Ps1Synthesizer().convert(ast)

    def _untouched(self, source: str) -> str:
        ast = Ps1Parser(source).parse()
        for node in ast.walk():
            if isinstance(node, (Ps1BinaryExpression, Ps1UnaryExpression)):
                spelled = KNOWN_PS_OPERATORS.get(node.operator.lower(), node.operator)
                set_value(node, 'operator', spelled)
        return Ps1Synthesizer().convert(ast)

    def _assertDeobfuscatesTo(
        self,
        source: str,
        expected: str,
        remove_junk: bool = True,
        preserve_bare_output: bool = False,
        trust_eval: bool = False,
    ) -> None:
        deobfuscated = self._deobfuscate(
            inspect.cleandoc(source),
            remove_junk=remove_junk,
            preserve_bare_output=preserve_bare_output,
            trust_eval=trust_eval,
        )
        self.assertEqual(deobfuscated, self._untouched(inspect.cleandoc(expected)))

    def _assertDeobfuscatesToOneOf(
        self,
        source: str,
        *expected: str,
        remove_junk: bool = True,
        preserve_bare_output: bool = False,
        trust_eval: bool = False,
    ) -> None:
        deobfuscated = self._deobfuscate(
            inspect.cleandoc(source),
            remove_junk=remove_junk,
            preserve_bare_output=preserve_bare_output,
            trust_eval=trust_eval,
        )
        acceptable = tuple(self._untouched(inspect.cleandoc(program)) for program in expected)
        self.assertIn(deobfuscated, acceptable)

    def _assertKept(
        self,
        source: str,
        remove_junk: bool = True,
        preserve_bare_output: bool = False,
        trust_eval: bool = False,
    ) -> None:
        self._assertDeobfuscatesTo(
            source,
            source,
            remove_junk=remove_junk,
            preserve_bare_output=preserve_bare_output,
            trust_eval=trust_eval,
        )

    def _assertRemoved(self, source: str, statement: str, trust_eval: bool = False) -> None:
        self.assertIn(statement, source)
        self._assertDeobfuscatesTo(source, source.replace(statement, ''), trust_eval=trust_eval)

    def _transform(self, source: str, *transforms) -> Ps1Script:
        ast = Ps1Parser(source).parse()
        for transform in transforms:
            transform().visit(ast)
        return ast

    def _apply(self, source: str, *transforms) -> str:
        return Ps1Synthesizer().convert(self._transform(source, *transforms))

    def _assertUnchanged(self, source: str, *transforms) -> None:
        self.assertEqual(self._apply(source, *transforms), source)

    def _assertTreeIsIntact(self, source: str, expected: str, *transforms) -> None:
        ast = self._transform(source, *transforms)
        self.assertEqual(Ps1Synthesizer().convert(ast), expected)
        for node in ast.walk():
            for child in node.children():
                self.assertIs(child.parent, node, F'{child!r} in {node!r} names {child.parent!r}')
