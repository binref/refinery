from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.au3.deobfuscation import deobfuscate
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer


class TestAu3(TestBase):

    def _deobfuscate(self, source: str) -> str:
        ast = Au3Parser(source).parse()
        deobfuscate(ast)
        return Au3Synthesizer().convert(ast)

    def _transform(self, source: str, *transforms):
        ast = Au3Parser(inspect.cleandoc(source)).parse()
        for transform in transforms:
            transform().visit(ast)
        return ast

    def _apply(self, source: str, *transforms) -> str:
        return Au3Synthesizer().convert(self._transform(source, *transforms))

    def _laid_out(self, source: str) -> str:
        """
        The spelling of *source* the synthesizer writes, so an assertion over a script whose
        lines a statement alone cannot hold compares what the statements say and not where the
        synthesizer broke them.
        """
        return self._apply(source)

    def _assertDeobfuscatesTo(self, source: str, expected: str) -> None:
        """
        Both arguments are written as ordinary indented AutoIt3, and `expected` is rendered
        through the synthesizer before the comparison, so that layout cannot be mistaken for a
        statement having been removed.
        """
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(source)),
            Au3Synthesizer().convert(Au3Parser(inspect.cleandoc(expected)).parse()),
        )

    def _assertKept(self, source: str) -> None:
        self._assertDeobfuscatesTo(source, source)
