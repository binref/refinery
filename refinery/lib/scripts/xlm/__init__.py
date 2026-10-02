"""
The XLM macro-language layer over the formula substrate of `refinery.lib.excel`: the
macrosheet model, the name table, the workbook view the interpreter reads, the command
registry with its severity classes, and the environment of answers the macro commands read.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm.commands import XLM_COMMANDS, XlmSeverity, severity
from refinery.lib.scripts.xlm.environment import XlmEnvironment
from refinery.lib.scripts.xlm.model import XlmCell, XlmMacrosheet, build_xlm_model
from refinery.lib.scripts.xlm.names import XlmNameEntry, XlmNameTable
from refinery.lib.scripts.xlm.view import XlmView

__all__ = [
    'XLM_COMMANDS',
    'XlmCell',
    'XlmEnvironment',
    'XlmMacrosheet',
    'XlmNameEntry',
    'XlmNameTable',
    'XlmSeverity',
    'XlmView',
    'build_xlm_model',
    'severity',
]
