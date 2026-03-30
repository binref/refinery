"""
VBA AST deobfuscation transforms.
"""
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.model import VbaModule


def deobfuscate(ast: VbaModule):
    """
    Apply all available deobfuscators to the input.
    """
    VbaSimplifications().visit(ast)
    return ast
