"""
The XLM macro-language layer over the formula substrate of `refinery.lib.excel`: the
macrosheet model, the name table, the workbook view the interpreter reads, the command
registry with its severity classes, and the environment of answers the macro commands read.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm.commands import XLM_COMMANDS, XlmSeverity, severity
from refinery.lib.scripts.xlm.deobfuscation import deobfuscate
from refinery.lib.scripts.xlm.engine import XlmEngine
from refinery.lib.scripts.xlm.environment import XlmEnvironment
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.model import XlmCell, XlmMacrosheet, build_xlm_model
from refinery.lib.scripts.xlm.names import XlmNameEntry, XlmNameTable
from refinery.lib.scripts.xlm.references import (
    XlmArrival,
    XlmCursor,
    expand_range,
    resolve_reference,
)
from refinery.lib.scripts.xlm.trace import XlmStatus, XlmStep, visible_steps
from refinery.lib.scripts.xlm.values import (
    XlmOutcome,
    XlmReference,
    XlmValue,
    apply_binary,
    concat,
    condition,
    unwrap_literal,
    wrap_literal,
)
from refinery.lib.scripts.xlm.view import XlmView

__all__ = [
    'XLM_COMMANDS',
    'XlmArrival',
    'XlmCell',
    'XlmCursor',
    'XlmEngine',
    'XlmEnvironment',
    'XlmMacrosheet',
    'XlmNameEntry',
    'XlmNameTable',
    'XlmOutcome',
    'XlmReference',
    'XlmSeverity',
    'XlmStatus',
    'XlmStep',
    'XlmValue',
    'XlmView',
    'apply_binary',
    'build_xlm_model',
    'concat',
    'condition',
    'deobfuscate',
    'evaluate_expression',
    'expand_range',
    'resolve_reference',
    'severity',
    'unwrap_literal',
    'visible_steps',
    'wrap_literal',
]
