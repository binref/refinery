"""
PowerShell AST deobfuscation transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup
from refinery.lib.scripts.ps1.analysis import Ps1ModelCache
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
from refinery.lib.scripts.ps1.deobfuscation.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.deobfuscation.rename import Ps1VariableRenaming
from refinery.lib.scripts.ps1.deobfuscation.securestring import Ps1SecureStringDecryptor
from refinery.lib.scripts.ps1.deobfuscation.simplify import Ps1Simplifications
from refinery.lib.scripts.ps1.deobfuscation.typecast import Ps1TypeCasts
from refinery.lib.scripts.ps1.deobfuscation.typenames import Ps1TypeSystemSimplifications
from refinery.lib.scripts.ps1.deobfuscation.unflatten import Ps1ControlFlowDeflattening
from refinery.lib.scripts.ps1.deobfuscation.unused import (
    Ps1DeadStoreElimination,
    Ps1JunkStatementRemoval,
    Ps1UnusedVariableRemoval,
)
from refinery.lib.scripts.ps1.deobfuscation.wildcards import Ps1WildcardResolution
from refinery.lib.scripts.ps1.model import Ps1Script

_folds = (
    Ps1ConstantFolding,
    Ps1DeadCodeElimination,
    Ps1ControlFlowDeflattening,
    Ps1ConstantInlining,
    Ps1ExpandableStringHoist,
    Ps1TypeCasts,
)

_cleanup = (
    Ps1NullVariableInlining,
    Ps1UnusedVariableRemoval,
    Ps1DeadStoreElimination,
    Ps1JunkStatementRemoval,
)

_fold_base = TransformerGroup('fold', *_folds)
_fold_full = TransformerGroup('fold', *_folds, *_cleanup)

_emulate = TransformerGroup(
    'emulate',
    Ps1ForEachPipeline,
    Ps1FunctionEvaluator,
)

_normalize = TransformerGroup(
    'normalize',
    Ps1Simplifications,
    Ps1AliasInlining,
    Ps1WildcardResolution,
    Ps1TypeSystemSimplifications,
)

_finalize = TransformerGroup(
    'finalize',
    Ps1SecureStringDecryptor,
    Ps1IexInlining,
)

_cosmetic = TransformerGroup(
    'cosmetic',
    Ps1VariableRenaming,
)

_DEPENDENCIES = {
    'fold'     : {'normalize'},
    'emulate'  : {'fold'},
    'finalize' : {'emulate'},
}

_INVALIDATORS = {
    'fold': {'normalize', 'emulate', 'finalize'},
}

_phase1 = DeobfuscationPipeline(
    [_normalize, _fold_base, _emulate, _finalize],
    dependencies=_DEPENDENCIES,
    invalidators=_INVALIDATORS,
)

_phase2 = DeobfuscationPipeline(
    [_normalize, _fold_full, _emulate, _finalize, _cosmetic],
    dependencies={**_DEPENDENCIES, 'cosmetic': {'finalize'}},
    invalidators=_INVALIDATORS,
)


def deobfuscate(
    ast: Ps1Script,
    max_steps: int = 5000,
    remove_junk: bool = True,
    preserve_bare_output: bool = False,
) -> int:
    """
    Apply all available deobfuscators to the input. When `remove_junk` is `True`, a second pass
    removes unused variable assignments, uncalled function definitions, and side-effect-free
    expression statements.

    A non-zero `max_steps` bounds the total number of change-producing transformer passes across
    both phases and raises `refinery.lib.scripts.pipeline.DeobfuscationTimeout` once it is
    exceeded, so a set of transforms that fails to converge fails loudly instead of hanging. The
    default is generous — real inputs settle in the low tens of passes — so it never bounds a
    legitimate deobfuscation, only a runaway loop. Pass `0` to disable the bound entirely.

    The two switches are not the same knob at different strengths. `remove_junk` decides whether
    that second pass runs at all, so turning it off also keeps every dead store and uncalled
    function, `preserve_bare_output` decides one question inside it — whether a statement whose only
    effect is to write a value to the success output stream may be deleted — and leaves the rest of
    the pass working. See `refinery.lib.scripts.ps1.deobfuscation.options.Ps1DeobfuscationOptions`
    for what that costs and the assumption it rests on.
    """
    # One analysis cache is built over the script and shared across both phases; the now-honored
    # `tree_version` counter keeps it consistent even across the two pipeline runs, so a transform in
    # either phase queries models built on the current tree instead of rebuilding them per pass.
    cache = Ps1ModelCache(ast)
    # Both phases are handed the same options, because a configuration two pipelines disagree about
    # is a configuration neither of them states. Only phase 2 holds the pass that reads this one
    # today, and building the phase-1 call that way would encode which pass that is.
    options = Ps1DeobfuscationOptions(preserve_bare_output=preserve_bare_output)
    steps = _phase1.run(ast, max_steps=max_steps, models=cache, options=options)
    if not remove_junk:
        return steps
    # Carry the phase-1 step count into phase 2 so a single `max_steps` budget is enforced across
    # both phases. Splitting the budget instead lets a phase-1 result of exactly `max_steps` leave a
    # remaining budget of 0, which the pipeline would read as "unlimited" and run phase 2 unbounded.
    return _phase2.run(
        ast,
        max_steps=max_steps,
        initial_steps=steps,
        models=cache,
        options=options,
    )
