"""
The trace the emulator produces: one step per executed cell, with the status the retiring
interpreter reported and the output level that decides which steps a trace shows.
"""
from __future__ import annotations

import enum
import re

from typing import NamedTuple

from refinery.lib.scripts.xlm.commands import XlmSeverity


class XlmStatus(enum.Enum):
    """
    The state one executed cell left the program in, spelled as the retiring interpreter
    reported it.
    """

    FullEvaluation = enum.auto()
    PartialEvaluation = enum.auto()
    Error = enum.auto()
    NotImplemented = enum.auto()
    End = enum.auto()
    Branching = enum.auto()
    FullBranching = enum.auto()
    IGNORED = enum.auto()


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


_QUOTED_TEXT = re.compile(R'"([^"]|"")*"')


def visible_steps(steps, level: int):
    """
    The steps a trace at the given output level shows: a step the interpreter ignored never
    shows, at the string-extraction level only the triage commands show and only the quoted
    string literals their text carries, and otherwise a step shows when its own level
    reaches the requested one.
    """
    for step in steps:
        if step.status is XlmStatus.IGNORED:
            continue
        if level >= 3 and step.severity is XlmSeverity.IMPORTANT:
            strings = [match.group(0) for match in _QUOTED_TEXT.finditer(step.text)]
            if strings:
                yield step._replace(text='\n'.join(strings))
        elif step.severity.value >= level:
            yield step
