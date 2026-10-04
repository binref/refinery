"""
The text of an XLM program as the static passes read it: the formula of every macrosheet cell and
of every defined name, and the formulas their string literals spell, because the program can
write such a text into a cell, where it runs, or hand it to a command that reads it as an
address.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.excel import parse_formula
from refinery.lib.excel.formula.model import Expression, XlString


def program_nodes(formula, parsed: dict[str, Expression]) -> Iterator[tuple[Expression, bool]]:
    """
    Every node of a formula and of the formulas its string literals spell, each with whether a
    string literal spelled it. The parses of string literals are kept in the given dictionary,
    and a text that reads as no formula contributes the node of its own unparsed text.
    """
    if formula is None:
        return
    for node in formula.walk():
        yield node, False
        if isinstance(node, XlString) and node.value:
            tree = parsed.get(node.value)
            if tree is None:
                tree = parsed[node.value] = parse_formula(node.value)
            for spelled, _ in program_nodes(tree, parsed):
                yield spelled, True
