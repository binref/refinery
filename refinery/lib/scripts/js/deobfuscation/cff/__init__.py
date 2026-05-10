"""
Control-flow flattening recovery transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.js.deobfuscation.cff.sequential import JsControlFlowUnflattening
from refinery.lib.scripts.js.deobfuscation.cff.statemachine import JsGeneratorCFFUnflattening

__all__ = [
    'JsControlFlowUnflattening',
    'JsGeneratorCFFUnflattening',
]
