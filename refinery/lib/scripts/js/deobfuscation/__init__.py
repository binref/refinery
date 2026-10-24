"""
JavaScript AST deobfuscation transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import tree_version
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.conversions import ConversionSettlement
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.antidbg import JsRemoveSelfDefending
from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs
from refinery.lib.scripts.js.deobfuscation.b91strings import (
    JsBase91AccessorDecoys,
    JsBase91StringDecoder,
)
from refinery.lib.scripts.js.deobfuscation.cff import (
    JsControlFlowUnflattening,
    JsStateMachineUnflattening,
)
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.dispatcher import JsDispatcherUnwrapper
from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator
from refinery.lib.scripts.js.deobfuscation.flatfunctions import JsFunctionUnflattening
from refinery.lib.scripts.js.deobfuscation.globalfinder import JsGlobalFinderInlining
from refinery.lib.scripts.js.deobfuscation.iifeaccessor import JsIIFEAccessorPromoter
from refinery.lib.scripts.js.deobfuscation.lzstrings import JsLZStringDecoder
from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.paramcopy import JsParameterCopyCoalescing
from refinery.lib.scripts.js.deobfuscation.parameters import JsRestPatternParameters
from refinery.lib.scripts.js.deobfuscation.protospelling import JsPrototypeSpellingNormalization
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking
from refinery.lib.scripts.js.deobfuscation.scramble import JsScrambleStringDecoder
from refinery.lib.scripts.js.deobfuscation.selfchecks import JsSelfCheckFolding
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.singleuse import JsSingleUseFunctionInliner
from refinery.lib.scripts.js.deobfuscation.stringarray import JsStringArrayResolver
from refinery.lib.scripts.js.deobfuscation.unshuffle import JsArrayUnshuffle
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.pipeline import (
    DeobfuscationPipeline,
    PipelineObserver,
    TransformerGroup,
)

_pipeline = DeobfuscationPipeline(
    groups=[
        TransformerGroup(
            'unpack',
            JsReflectionInlining,
        ),
        TransformerGroup(
            'normalize',
            JsPrototypeSpellingNormalization,
            JsAssignmentsAsFunctionArgs,
            JsSimplifications,
            JsDeadCodeElimination,
        ),
        TransformerGroup(
            'fold',
            JsSelfCheckFolding,
            JsNamespaceFlattening,
            JsCallWrapperInliner,
            JsDispatcherUnwrapper,
            JsFunctionUnflattening,
            JsIIFEAccessorPromoter,
            JsFunctionEvaluator,
            JsObjectFold,
            JsControlFlowUnflattening,
            JsStateMachineUnflattening,
            JsRestArrayUnpacking,
            JsParameterCopyCoalescing,
            JsRestPatternParameters,
            JsArrayUnshuffle,
            JsConstantInlining,
            JsGlobalFinderInlining,
        ),
        TransformerGroup(
            'resolve',
            JsStringArrayResolver,
            JsBase91AccessorDecoys,
            JsBase91StringDecoder,
            JsScrambleStringDecoder,
            JsLZStringDecoder,
        ),
        TransformerGroup(
            'cleanup',
            JsRemoveSelfDefending,
            JsUnusedCodeRemoval,
            JsSingleUseFunctionInliner,
        ),
    ],
    dependencies={
        'normalize': {'unpack'},
        'fold': {'normalize'},
        'resolve': {'fold'},
        'cleanup': {'fold'},
    },
)


def deobfuscate(
    ast: JsScript,
    max_steps: int = 5000,
    *,
    execution: ExecutionModel = ExecutionModel.script,
    entrypoints: tuple[str, ...] = (),
    environment: HostEnvironment = HostEnvironment.universal,
    trust_eval: bool = False,
    preserve_script_return: bool = False,
    loaded_by_other_files: bool = False,
    observer: PipelineObserver | None = None,
) -> int:
    """
    Apply all available deobfuscators to the input. A non-zero *max_steps* bounds the total number
    of change-producing transformer passes and raises
    `refinery.lib.scripts.pipeline.DeobfuscationTimeout` once it is exceeded, so a transform that
    fails to converge fails loudly instead of hanging. The default is generous — real inputs settle
    in a few to a few dozen passes (the differential corpus peaks in the low tens) — so it never
    bounds a legitimate deobfuscation, only a runaway loop. Pass `0` to disable the bound entirely.
    *execution* selects the execution model the input is assumed to run under, *entrypoints* names
    top-level functions a host calls by name, and *environment* pins the host whose global names are
    assumed present; see `refinery.lib.scripts.js.options.DeobfuscationOptions`. *trust_eval*
    selects the trusting model, which assumes code supplied as data is inert and is deliberately
    unsound; the default is the suspecting model, so a caller that reads this function's output as
    equivalent to its input keeps that claim. *loaded_by_other_files* says that code may load the
    input and read what it exports. *observer* is called around every transformer, which is how a
    property of the tree is attributed to the pass that moved it; see
    `refinery.lib.scripts.js.deobfuscation.audit.StrictModeAudit`.

    A conversion of a function that is handed on, with no evidence that the program installs a
    conversion on it, is folded only on a tree the run has settled: a key a later pass decodes may
    yet spell such an install. The run keeps a record of the tree it last refused such a
    conversion on (`refinery.lib.scripts.js.analysis.conversions.ConversionSettlement`). When the
    pipeline reaches its fixpoint on that tree, every pass that decodes has run to its end, so the
    record settles the tree and the pipeline runs again over the same models, with the step budget
    carried over. A change in that run leaves the settled tree behind, since a fold may let a pass
    decode more, so the pipeline runs again as long as a run that changed the tree ends on one it
    refused a conversion on.
    """
    options = DeobfuscationOptions(
        execution=execution,
        entrypoints=tuple(entrypoints),
        environment=environment,
        trust_eval=trust_eval,
        preserve_script_return=preserve_script_return,
        loaded_by_other_files=loaded_by_other_files,
    )
    settlement = ConversionSettlement()
    models = ModelCache(ast, options, settlement)
    JsLZStringDecoder.read_input(models)
    steps = _pipeline.run(
        ast,
        max_steps=max_steps,
        models=models,
        options=options,
        observer=observer,
    )
    while settlement.waits_on(tree_version(ast)):
        settlement.settle(tree_version(ast))
        settled_steps = _pipeline.run(
            ast,
            max_steps=max_steps,
            initial_steps=steps,
            models=models,
            options=options,
            observer=observer,
        )
        if settled_steps == steps:
            break
        steps = settled_steps
    return steps
