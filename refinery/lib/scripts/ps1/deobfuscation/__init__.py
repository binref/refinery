"""
PowerShell AST deobfuscation transforms.
"""
from refinery.lib.scripts.ps1.deobfuscation.aliases import Ps1AliasInlining
from refinery.lib.scripts.ps1.deobfuscation.constants import Ps1ConstantInlining
from refinery.lib.scripts.ps1.deobfuscation.emulator import Ps1ForEachPipeline, Ps1FunctionEvaluator
from refinery.lib.scripts.ps1.deobfuscation.expandable import Ps1ExpandableStringHoist
from refinery.lib.scripts.ps1.deobfuscation.folding import Ps1ConstantFolding
from refinery.lib.scripts.ps1.deobfuscation.iexinline import Ps1IexInlining
from refinery.lib.scripts.ps1.deobfuscation.securestring import Ps1SecureStringDecryptor
from refinery.lib.scripts.ps1.deobfuscation.simplify import Ps1Simplifications
from refinery.lib.scripts.ps1.deobfuscation.typecast import Ps1TypeCasts
from refinery.lib.scripts.ps1.deobfuscation.wildcards import Ps1WildcardResolution
from refinery.lib.scripts.ps1.model import Ps1Script


def deobfuscate(ast: Ps1Script) -> bool:
    """
    Apply all available deobfuscators to the input.
    """
    transformers = [
        Ps1Simplifications(),
        Ps1AliasInlining(),
        Ps1WildcardResolution(),
        Ps1ConstantInlining(),
        Ps1ExpandableStringHoist(),
        Ps1ConstantFolding(),
        Ps1ForEachPipeline(),
        Ps1FunctionEvaluator(),
        Ps1TypeCasts(),
        Ps1SecureStringDecryptor(),
        Ps1IexInlining(),
    ]
    for t in transformers:
        t.visit(ast)
    return any(t.changed for t in transformers)
