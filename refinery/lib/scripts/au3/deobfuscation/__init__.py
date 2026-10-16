"""
AutoIt3 AST deobfuscation transforms.

Five groups, in the order the obfuscated shapes need them. `normalize` rewrites what a call
structurally is — an `Execute` call over a string literal becomes the expression that literal
names, a call through an alias variable becomes the function that variable provably names, and
a `Call`, `Assign`, or `Eval` over a string-literal name becomes the direct call, plain write,
or plain read that name spells — `fold` replaces what is known — an expression whose operands
pin its value becomes the literal of that value, a variable read the propagation walk proves a
value for becomes that literal, and a dispatcher loop whose state a provable constant pins becomes
the one case body it ever runs — `emulate` replaces what a script-defined function returns:
the interpreter runs the call over the value domain and the call becomes the literal of its
result — `cleanup` removes what no live code reaches: a function no call names, a declarator
no occurrence binds, an effect-free statement, and a plain assignment whose target nothing reads
— each only when no dynamic-name channel could observe the removal — and `canonicalize` reprints
what survived: a call whose callee names a builtin, or whose `Call` argument does, takes the
official spelling of that name, a change no resolution reads.

`fold` depends on `normalize` and re-triggers it: folding an `Execute` call's argument into the
string literal it always was is what makes the next `normalize` pass see a flattenable call, and
rewriting a callee through an alias is what makes the next `fold` pass see the builtin the alias
named. `emulate` depends on `fold` — only literal arguments reach a decoded call — and every
change it makes re-triggers the whole pipeline: a decoded `"BinaryToString"` is what the next
`normalize` pass turns into an alias rewrite, and a decoded argument is what the next `fold`
pass folds. `cleanup` depends on `emulate` and takes no selective invalidation set: a removal
changes everything the other models know, the `emulate` stance. `canonicalize` depends on
`cleanup` and takes the empty one: it rewrites only spellings, every model keys lowercased
names, and no group depends on it, so its changes re-run nothing. The group's internal loop is
what iterates a sweep to its fixpoint — a function whose only callers an earlier sweep removed
keeps its call sites until the next sweep re-census.
"""
from __future__ import annotations

from refinery.lib.scripts.au3.analysis import Au3ModelCache
from refinery.lib.scripts.au3.deobfuscation.casing import Au3BuiltinCaseNormalization
from refinery.lib.scripts.au3.deobfuscation.eliminate import Au3DeadCodeElimination
from refinery.lib.scripts.au3.deobfuscation.evaluate import Au3FunctionEvaluation
from refinery.lib.scripts.au3.deobfuscation.execute import Au3ExecuteFlattening
from refinery.lib.scripts.au3.deobfuscation.fold import Au3ConstantFolding
from refinery.lib.scripts.au3.deobfuscation.indirect import Au3IndirectCallRewrite
from refinery.lib.scripts.au3.deobfuscation.names import Au3DynamicNameFlattening
from refinery.lib.scripts.au3.deobfuscation.propagate import Au3ConstantPropagation
from refinery.lib.scripts.au3.deobfuscation.unflatten import Au3ControlFlowDeflattening
from refinery.lib.scripts.au3.deobfuscation.unused import Au3UnusedVariableRemoval
from refinery.lib.scripts.au3.model import Au3Script
from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup

_normalize = TransformerGroup(
    'normalize',
    Au3ExecuteFlattening,
    Au3IndirectCallRewrite,
    Au3DynamicNameFlattening,
)

_fold = TransformerGroup(
    'fold',
    Au3ConstantFolding,
    Au3ConstantPropagation,
    Au3ControlFlowDeflattening,
)

_emulate = TransformerGroup(
    'emulate',
    Au3FunctionEvaluation,
)

_cleanup = TransformerGroup(
    'cleanup',
    Au3DeadCodeElimination,
    Au3UnusedVariableRemoval,
)

_canonicalize = TransformerGroup(
    'canonicalize',
    Au3BuiltinCaseNormalization,
)

_GROUP_DEPENDENCIES = {
    'fold': {'normalize'},
    'emulate': {'fold'},
    'cleanup': {'emulate'},
    'canonicalize': {'cleanup'},
}

_GROUP_INVALIDATORS = {
    'fold': {'normalize', 'emulate', 'cleanup', 'canonicalize'},
    'canonicalize': set(),
}

_pipeline = DeobfuscationPipeline(
    [_normalize, _fold, _emulate, _cleanup, _canonicalize],
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
