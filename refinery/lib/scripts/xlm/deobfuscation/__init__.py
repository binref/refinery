"""
The static deobfuscation of an XLM program: the passes that clean the macrosheet model a
listing starts from. The constant folding replaces what the workbook stores with what it
computes, the removal of the cells no formula leads to then drops the padding that folding
emptied, and nothing else rewrites the model — the emulator evaluates everything else, and a
trace that folded or swept its input would hide the program it exists to show.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.scripts.xlm.deobfuscation.deadcode import sweep
from refinery.lib.scripts.xlm.deobfuscation.fold import fold

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.view import XlmView


def deobfuscate(view: XlmView, start_point: str = '') -> None:
    """
    Clean the macrosheets of the view in place for a listing: fold every statically computable
    subtree into the value it computes, then remove the cells no formula leads to, keeping the
    entry points the run starts from.
    """
    fold(view)
    sweep(view, start_point)
