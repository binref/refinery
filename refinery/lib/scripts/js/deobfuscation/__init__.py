"""
JavaScript AST deobfuscation transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.js.deobfuscation.antidbg import JsRemoveReDoS
from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs
from refinery.lib.scripts.js.deobfuscation.b91strings import JsBase91StringDecoder
from refinery.lib.scripts.js.deobfuscation.cff import (
    JsControlFlowUnflattening,
    JsGeneratorCFFUnflattening,
)
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.dispatcher import JsDispatcherUnwrapper
from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator
from refinery.lib.scripts.js.deobfuscation.globalfinder import JsGlobalFinderInlining
from refinery.lib.scripts.js.deobfuscation.iifeaccessor import JsIIFEAccessorPromoter
from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking
from refinery.lib.scripts.js.deobfuscation.scramble import JsScrambleStringDecoder
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.stringarray import JsStringArrayResolver
from refinery.lib.scripts.js.deobfuscation.unshuffle import JsArrayUnshuffle
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup

_pipeline = DeobfuscationPipeline(
    groups=[
        TransformerGroup(
            'unpack',
            JsReflectionInlining,
        ),
        TransformerGroup(
            'normalize',
            JsAssignmentsAsFunctionArgs,
            JsSimplifications,
            JsDeadCodeElimination,
        ),
        TransformerGroup(
            'fold',
            JsNamespaceFlattening,
            JsCallWrapperInliner,
            JsDispatcherUnwrapper,
            JsIIFEAccessorPromoter,
            JsFunctionEvaluator,
            JsObjectFold,
            JsControlFlowUnflattening,
            JsGeneratorCFFUnflattening,
            JsRestArrayUnpacking,
            JsArrayUnshuffle,
            JsConstantInlining,
            JsGlobalFinderInlining,
        ),
        TransformerGroup(
            'resolve',
            JsStringArrayResolver,
            JsBase91StringDecoder,
            JsScrambleStringDecoder,
        ),
        TransformerGroup(
            'cleanup',
            JsRemoveReDoS,
            JsUnusedCodeRemoval,
        ),
    ],
    dependencies={
        'normalize': {'unpack'},
        'fold': {'normalize'},
        'resolve': {'fold'},
        'cleanup': {'fold'},
    },
    invalidators={
        'unpack': {'normalize', 'fold', 'resolve', 'cleanup'},
        'normalize': {'fold', 'resolve'},
        'fold': {'normalize', 'resolve'},
        'resolve': {'normalize', 'fold'},
        'cleanup': {'fold'},
    },
)


def deobfuscate(ast: JsScript, max_steps: int = 5000) -> int:
    """
    Apply all available deobfuscators to the input. A non-zero *max_steps* bounds the total number of
    change-producing transformer passes and raises
    `refinery.lib.scripts.pipeline.DeobfuscationTimeout` once it is exceeded, so a transform that fails
    to converge fails loudly instead of hanging. The default is generous — real inputs settle in a few
    to a few dozen passes (the differential corpus peaks in the low tens) — so it never bounds a
    legitimate deobfuscation, only a runaway loop. Pass `0` to disable the bound entirely.
    """
    return _pipeline.run(ast, max_steps=max_steps, models=ModelCache(ast))
