"""
VBA AST deobfuscation transforms.
"""
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.model import VbaModule


def deobfuscate(ast: VbaModule) -> bool:
    """
    Apply all available deobfuscators to the input.
    """
    return VbaSimplifications().deobfuscate(ast)
