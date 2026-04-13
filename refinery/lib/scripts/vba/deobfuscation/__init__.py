"""
VBA AST deobfuscation transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup
from refinery.lib.scripts.vba.deobfuscation.constants import VbaConstantInlining
from refinery.lib.scripts.vba.deobfuscation.deadcode import VbaDeadVariableRemoval, VbaEmptyProcedureRemoval
from refinery.lib.scripts.vba.deobfuscation.emulator import VbaFunctionEvaluator
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.model import VbaModule

_pipeline = DeobfuscationPipeline(
    groups=[
        TransformerGroup(
            'fold',
            VbaSimplifications,
            VbaConstantInlining,
            VbaDeadVariableRemoval,
            VbaEmptyProcedureRemoval,
        ),
        TransformerGroup(
            'evaluate',
            VbaFunctionEvaluator,
        ),
    ],
    dependencies={
        'evaluate': {'fold'},
    },
)


def deobfuscate(ast: VbaModule, max_steps: int = 0) -> int:
    """
    Apply all available deobfuscators to the input.
    """
    return _pipeline.run(ast, max_steps=max_steps)
