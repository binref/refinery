"""
PHP AST deobfuscation transforms.

This module is currently an empty skeleton: the deobfuscation framework is wired up but carries no
passes yet. Passes will be added here as `TransformerGroup` entries once the PHP front-end is
exercised against real samples.
"""
from __future__ import annotations

from refinery.lib.scripts.php.model import PhpScript
from refinery.lib.scripts.pipeline import DeobfuscationPipeline

_pipeline = DeobfuscationPipeline(groups=[])


def deobfuscate(ast: PhpScript, max_steps: int = 0) -> int:
    """
    Apply all available deobfuscators to the input. No passes are registered yet, so this is a
    no-op that always reports zero applied transformations.
    """
    return _pipeline.run(ast, max_steps=max_steps)
