"""
The name table of an XLM workbook: the defined names the format stores, keyed for the
case-insensitive lookup the macro language performs, with the fuzzy discovery that finds the
`auto_open` entry of a workbook whatever name it was hidden behind.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.excel.formula.model import Expression
from refinery.lib.excel.workbook import ExcelWorkbook


class XlmNameEntry(NamedTuple):
    """
    A defined name as the macro language sees it: the name as written, the zero-based index
    of the sheet the name is scoped to, and the decoded formula. The scope index counts the
    full sheet table of the format — chartsheets included — and is stored rather than resolved,
    because what a scoped name means is a question of interpretation, not of reading.
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
    The defined names of a workbook, keyed by lowercased name. A duplicate lowercased name
    keeps its first entry and drops the later ones, a fixed rule where the wrappers of the
    retiring port disagreed. The table is mutable because `SET.NAME` and `DEFINE.NAME` define
    names at run time.
    """

    def __init__(self, workbook: ExcelWorkbook):
        self._entries: dict[str, XlmNameEntry] = {}
        for record in workbook.defined_names():
            key = record.name.lower()
            if key in self._entries:
                continue
            self._entries[key] = XlmNameEntry(
                name=record.name,
                sheet=record.sheet,
                formula=workbook.formula(record.formula),
            )

    def entries(self) -> list[tuple[str, XlmNameEntry]]:
        """
        Every entry as a pair of the name as written and its record, in name-table order.
        """
        return [(entry.name, entry) for entry in self._entries.values()]

    def resolve(self, name: str) -> XlmNameEntry | None:
        """
        The entry a name spells, matched case-insensitively, or `None` when the workbook
        defines no such name.
        """
        return self._entries.get(name.lower())

    def fuzzy(self, pattern: str) -> list[tuple[str, XlmNameEntry]]:
        """
        The entries a pattern might mean, as pairs of the name as written and its record, in
        name-table order: every entry whose name starts with the pattern, and when none does,
        every entry whose name contains the pattern's characters in order.
        """
        pattern = pattern.lower()
        matches = [
            (entry.name, entry)
            for key, entry in self._entries.items()
            if key.startswith(pattern)
        ]
        if matches:
            return matches
        return [
            (entry.name, entry)
            for key, entry in self._entries.items()
            if _is_subsequence(pattern, key)
        ]

    def define(self, name: str, entry: XlmNameEntry) -> None:
        """
        Define a name, replacing any entry that already spells it.
        """
        self._entries[name.lower()] = entry

    def undefine(self, name: str) -> None:
        """
        Remove the entry a name spells, case-insensitively, if there is one.
        """
        self._entries.pop(name.lower(), None)
