"""
VBA AST deobfuscation transforms.
"""
from refinery.lib.scripts.vba.deobfuscation.emulator import VbaFunctionEvaluator
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.model import VbaModule


def deobfuscate(ast: VbaModule) -> bool:
    """
    Apply all available deobfuscators to the input.
    """
    simplifier = VbaSimplifications()
    evaluator = VbaFunctionEvaluator()
    simplified = simplifier.deobfuscate(ast)
    evaluator.visit(ast)
    return simplified or evaluator.changed
