"""
The guess of the day of the month a program runs under: the one answer a DAY command cannot
read from its workbook, searched by running the whole program under every day of a month and
keeping the day whose trace spells the least unprintable text.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.engine import XlmEngine


def guess_day(engine: XlmEngine) -> int:
    """
    The day of the month that makes the program's own trace most readable: every candidate day
    runs the program from its entry points through a fresh engine over the shared view — the
    writes and names of one trial are the state the next trial starts from, the way the trial
    runs of the retiring interpreter shared their cells — and the day whose trace carries the
    smallest share of unprintable characters and failed CHAR calls wins. Zero names no day at
    all, because every trial of the program died.
    """
    best_day = 0
    best_ratio = 1.0
    for day in range(1, 32):
        trial = engine.trial(day)
        unprintable = 0
        total = 0
        try:
            for index, step in enumerate(trial.run()):
                unprintable += sum(
                    1
                    for char in step.text
                    if not 32 <= ord(char) <= 128
                )
                total += len(step.text)
                if (
                    index > 10
                    and (unprintable + trial.char_errors) / (total or 1) > best_ratio
                ):
                    break
            ratio = (unprintable + trial.char_errors) / total if total else 1.0
        except Exception:
            continue
        if ratio < best_ratio:
            best_ratio = ratio
            best_day = day
            if ratio == 0:
                break
    return best_day
