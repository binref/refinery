"""
PowerShell AST deobfuscation transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup
from refinery.lib.scripts.ps1.deobfuscation.aliases import Ps1AliasInlining
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    Ps1ConstantInlining,
    Ps1NullVariableInlining,
)
from refinery.lib.scripts.ps1.deobfuscation.deadcode import Ps1DeadCodeElimination
from refinery.lib.scripts.ps1.deobfuscation.emulator import Ps1ForEachPipeline, Ps1FunctionEvaluator
from refinery.lib.scripts.ps1.deobfuscation.expandable import Ps1ExpandableStringHoist
from refinery.lib.scripts.ps1.deobfuscation.folding import Ps1ConstantFolding
from refinery.lib.scripts.ps1.deobfuscation.iexinline import Ps1IexInlining
from refinery.lib.scripts.ps1.deobfuscation.securestring import Ps1SecureStringDecryptor
from refinery.lib.scripts.ps1.deobfuscation.simplify import Ps1Simplifications
from refinery.lib.scripts.ps1.deobfuscation.typecast import Ps1TypeCasts
from refinery.lib.scripts.ps1.deobfuscation.typenames import Ps1TypeSystemSimplifications
from refinery.lib.scripts.ps1.deobfuscation.wildcards import Ps1WildcardResolution
from refinery.lib.scripts.ps1.model import Ps1Script

_pipeline = DeobfuscationPipeline(
    groups=[
        TransformerGroup(
            'normalize',
            Ps1Simplifications,
            Ps1AliasInlining,
            Ps1WildcardResolution,
            Ps1TypeSystemSimplifications,
        ),
        TransformerGroup(
            'fold',
            Ps1ConstantFolding,
            Ps1DeadCodeElimination,
            Ps1ConstantInlining,
            Ps1ExpandableStringHoist,
            Ps1TypeCasts,
            Ps1NullVariableInlining,
        ),
        TransformerGroup(
            'evaluate',
            Ps1ForEachPipeline,
            Ps1FunctionEvaluator,
        ),
        TransformerGroup(
            'finalize',
            Ps1SecureStringDecryptor,
            Ps1IexInlining,
        ),
    ],
    dependencies={
        'fold': {'normalize'},
        'evaluate': {'fold'},
        'finalize': {'evaluate'},
    },
    invalidates={
        'normalize': set(),
        'fold': {'normalize', 'evaluate', 'finalize'},
    },
)


def deobfuscate(ast: Ps1Script, max_steps: int = 0) -> int:
    """
    Apply all available deobfuscators to the input.
    """
    Ps1NullVariableInlining.enabled = False
    steps = _pipeline.run(ast, max_steps=max_steps)
    Ps1NullVariableInlining.enabled = True
    steps += _pipeline.run(ast, max_steps=max_steps)
    return steps
