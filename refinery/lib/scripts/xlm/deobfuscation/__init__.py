"""
The static deobfuscation of an XLM program: the passes that clean the macrosheet model a run
starts from. The removal of the cells no run can reach is the one pass the macro language
leaves to static analysis — everything else the emulator evaluates anyway, and folding a
listing would hide the obfuscation the extraction exists to show.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.scripts.xlm.deobfuscation.deadcode import sweep

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.view import XlmView


def deobfuscate(view: XlmView, start_point: str = '') -> None:
    """
    Clean the macrosheets of the view in place for a listing or a run: remove the dead cells
    no execution reaches, keeping the entry points the run starts from.
    """
    sweep(view, start_point)
