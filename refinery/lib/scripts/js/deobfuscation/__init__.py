"""
JavaScript AST deobfuscation transforms.
"""
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.model import JsScript


def deobfuscate(ast: JsScript) -> bool:
    """
    Apply all available deobfuscators to the input.
    """
    t = JsSimplifications()
    t.visit(ast)
    return t.changed
