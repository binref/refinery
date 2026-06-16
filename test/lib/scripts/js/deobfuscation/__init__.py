from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestJsDeobfuscator(TestBase):

    def _deobfuscate(self, source: str) -> str:
        ast = JsParser(source).parse()
        deobfuscate(ast)
        return JsSynthesizer().convert(ast)

    def _deobfuscate_iterative(self, source: str, iterations: int = 100) -> str:
        ast = JsParser(source).parse()
        for _ in range(iterations):
            if not deobfuscate(ast):
                break
        return JsSynthesizer().convert(ast)

    def _run_transformer(self, source: str, t: type[Transformer]):
        ast = JsParser(source).parse()
        t().visit(ast)
        return JsSynthesizer().convert(ast)

    def _inline(self, source: str) -> str:
        return self._run_transformer(source, JsConstantInlining)

    def _simplify(self, source: str) -> str:
        return self._run_transformer(source, JsSimplifications)

    def _deadcode(self, source: str) -> str:
        return self._run_transformer(source, JsDeadCodeElimination)

    def _objectfold(self, source: str) -> str:
        return self._run_transformer(source, JsObjectFold)

    def _unwrap(self, source: str) -> str:
        return self._run_transformer(source, JsAssignmentsAsFunctionArgs)
