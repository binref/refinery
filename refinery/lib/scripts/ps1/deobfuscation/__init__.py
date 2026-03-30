"""
PowerShell AST deobfuscation transforms.
"""
from refinery.lib.scripts.ps1.deobfuscation.securestring import Ps1SecureStringDecryptor
from refinery.lib.scripts.ps1.deobfuscation.simplify import Ps1Simplifications
from refinery.lib.scripts.ps1.deobfuscation.strings import Ps1StringOperations
from refinery.lib.scripts.ps1.deobfuscation.typecast import Ps1TypeCasts
from refinery.lib.scripts.ps1.model import Ps1Script


def deobfuscate(ast: Ps1Script):
    """
    Apply all available deobfuscators to the input.
    """
    Ps1Simplifications().visit(ast)
    Ps1StringOperations().visit(ast)
    Ps1TypeCasts().visit(ast)
    Ps1SecureStringDecryptor().visit(ast)
    return ast
