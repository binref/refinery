"""
AutoIt3 AST deobfuscation transforms.

Three groups, in the order the obfuscated shapes need them. `normalize` rewrites what a call
structurally is — an `Execute` call over a string literal becomes the expression that literal
names, and a call through an alias variable becomes the function that variable provably names —
`fold` replaces what is known — an expression whose operands pin its value becomes the literal
of that value, and a variable read the propagation walk proves a value for becomes that literal —
and `emulate` replaces what a script-defined function returns: the interpreter runs the call
over the value domain and the call becomes the literal of its result.

`fold` depends on `normalize` and re-triggers it: folding an `Execute` call's argument into the
string literal it always was is what makes the next `normalize` pass see a flattenable call, and
rewriting a callee through an alias is what makes the next `fold` pass see the builtin the alias
named. `emulate` depends on `fold` — only literal arguments reach a decoded call — and every
change it makes re-triggers the whole pipeline: a decoded `"BinaryToString"` is what the next
`normalize` pass turns into an alias rewrite, and a decoded argument is what the next `fold`
pass folds. The remaining alias declarations stay behind as dead code; removing them is a later
phase's question.
"""
from __future__ import annotations

from refinery.lib.scripts.au3.analysis import Au3ModelCache
from refinery.lib.scripts.au3.deobfuscation.evaluate import Au3FunctionEvaluation
from refinery.lib.scripts.au3.deobfuscation.execute import Au3ExecuteFlattening
from refinery.lib.scripts.au3.deobfuscation.fold import Au3ConstantFolding
from refinery.lib.scripts.au3.deobfuscation.indirect import Au3IndirectCallRewrite
from refinery.lib.scripts.au3.deobfuscation.propagate import Au3ConstantPropagation
from refinery.lib.scripts.au3.model import Au3Script
from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup

_normalize = TransformerGroup(
    'normalize',
    Au3ExecuteFlattening,
    Au3IndirectCallRewrite,
)

_fold = TransformerGroup(
    'fold',
    Au3ConstantFolding,
    Au3ConstantPropagation,
)

_emulate = TransformerGroup(
    'emulate',
    Au3FunctionEvaluation,
)

_GROUP_DEPENDENCIES = {
    'fold': {'normalize'},
    'emulate': {'fold'},
}

_GROUP_INVALIDATORS = {
    'fold': {'normalize', 'emulate'},
}

_pipeline = DeobfuscationPipeline(
    [_normalize, _fold, _emulate],
    dependencies=_GROUP_DEPENDENCIES,
    invalidators=_GROUP_INVALIDATORS,
)


def deobfuscate(ast: Au3Script, max_steps: int = 5000) -> int:
    """
    Apply all available deobfuscators to the input. A non-zero `max_steps` bounds the total number
    of change-producing transformer passes and raises
    `refinery.lib.scripts.pipeline.DeobfuscationTimeout` once it is exceeded, so a set of
    transforms that fails to converge fails loudly instead of hanging. Pass `0` to disable the
    bound entirely.
    """
    return _pipeline.run(ast, max_steps=max_steps, models=Au3ModelCache(ast))
