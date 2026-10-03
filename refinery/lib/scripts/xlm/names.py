"""
The name table of an XLM workbook: the defined names the format stores, keyed for the
case-insensitive lookup the macro language performs and resolved by scope when the caller
knows the sheet it reads from, with the fuzzy discovery that finds the `auto_open` entry of
a workbook whatever name it was hidden behind.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.excel.formula.model import Expression
from refinery.lib.excel.workbook import ExcelWorkbook


class XlmNameEntry(NamedTuple):
    """
    A defined name as the macro language sees it: the name as written, the zero-based index
    of the sheet the name is scoped to in the full sheet table of the format — chartsheets
    included — or `None` when the name is global, and the decoded formula.
    """

    name: str
    sheet: int | None
    formula: Expression | None


def _is_subsequence(pattern: str, name: str) -> bool:
    """
    Whether `name` contains the characters of `pattern` in order, each consumed once.
    """
    position = 0
    for char in pattern:
        position = name.find(char, position)
        if position < 0:
            return False
        position += 1
    return True


class XlmNameTable:
    """
    The defined names of a workbook as a list in document order, keeping an entry for every
    sheet a name is scoped to. The table is mutable because `SET.NAME` and `DEFINE.NAME`
    define names at run time.
    """

    def __init__(self, workbook: ExcelWorkbook):
        self._entries: list[XlmNameEntry] = [
            XlmNameEntry(
                name=record.name,
                sheet=record.sheet,
                formula=workbook.formula(record.formula),
            )
            for record in workbook.defined_names()
        ]

    def entries(self) -> list[XlmNameEntry]:
        """
        Every entry, in document order.
        """
        return list(self._entries)

    def resolve(self, name: str, sheet: int | None = None) -> XlmNameEntry | None:
        """
        The entry a name spells, matched case-insensitively. An entry scoped to the given
        sheet wins over a global entry, and a name scoped only to another sheet answers
        nothing — the way Excel answers `#NAME?`. `None` when the workbook defines no such
        name for the scope.
        """
        key = name.lower()
        scoped: XlmNameEntry | None = None
        global_entry: XlmNameEntry | None = None
        for entry in self._entries:
            if entry.name.lower() != key:
                continue
            if entry.sheet == sheet and scoped is None:
                scoped = entry
            elif entry.sheet is None and global_entry is None:
                global_entry = entry
        return scoped or global_entry

    def fuzzy(self, pattern: str) -> list[XlmNameEntry]:
        """
        The entries a pattern might mean, in document order: every entry whose name starts
        with the pattern, and when none does, every entry whose name contains the pattern's
        characters in order, each character of the name matching at most one of the pattern.
        """
        pattern = pattern.lower()
        matches = [entry for entry in self._entries if entry.name.lower().startswith(pattern)]
        if matches:
            return matches
        return [entry for entry in self._entries if _is_subsequence(pattern, entry.name.lower())]

    def define(self, entry: XlmNameEntry) -> None:
        """
        Define the name an entry carries, replacing the entry that spells it in the same
        scope and appending a new one when no such entry exists.
        """
        key = entry.name.lower()
        for position, existing in enumerate(self._entries):
            if existing.name.lower() == key and existing.sheet == entry.sheet:
                self._entries[position] = entry
                return
        self._entries.append(entry)

    def restore(self, entries: list[XlmNameEntry]) -> None:
        """
        Hold the entries an earlier state of the table held, as the undo of a definition
        performs.
        """
        self._entries = list(entries)

    def undefine(self, name: str) -> None:
        """
        Remove every entry a name spells, case-insensitively, whatever sheet it is scoped to.
        """
        key = name.lower()
        self._entries = [entry for entry in self._entries if entry.name.lower() != key]
