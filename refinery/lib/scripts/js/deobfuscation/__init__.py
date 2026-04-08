"""
JavaScript AST deobfuscation transforms.
"""
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.pipeline import DeobfuscationPipeline, TransformerGroup

_pipeline = DeobfuscationPipeline(
    groups=[TransformerGroup('simplify', JsSimplifications)],
)


def deobfuscate(ast: JsScript, max_steps: int = 0) -> int:
    """
    Apply all available deobfuscators to the input.
    """
    return _pipeline.run(ast, max_steps=max_steps)
