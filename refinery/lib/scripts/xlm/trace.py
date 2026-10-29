"""
The trace the emulator produces: one step per executed cell, with the status of the cell and
the output level that decides which steps a trace shows.
"""
from __future__ import annotations

from enum import auto, Enum
from typing import Iterable, NamedTuple

from refinery.lib.scripts.xlm.commands import XlmSeverity


class XlmStatus(str, Enum):
    """
    The state one executed cell left the program in.
    """
    FullEvaluation = auto()
    PartialEvaluation = auto()
    Error = auto()
    NotImplemented = auto()
    End = auto()
    Branching = auto()
    FullBranching = auto()
    Ignored = auto()


class XlmStep(NamedTuple):
    """
    One executed cell of a run: the sheet it sits on with its one-based row and column, the
    status the run left it in, the text the trace prints for it, its indentation inside a
    branch, and the output level it prints at — the level of its command, or the lowest level
    when the cell is no command call at all.
    """
    sheet: str
    row: int
    col: int
    status: XlmStatus
    text: str
    indent: int
    severity: XlmSeverity


def visible_steps(steps: Iterable[XlmStep], level: int):
    """
    The steps a trace at the given output level shows: a step the interpreter ignored never
    shows, and otherwise a step shows when its own level reaches the requested one; a level
    above the highest shows the steps of the highest.
    """
    level = min(level, max(s.value for s in XlmSeverity))
    for step in steps:
        if step.status is XlmStatus.Ignored:
            continue
        elif step.severity.value >= level:
            yield step
