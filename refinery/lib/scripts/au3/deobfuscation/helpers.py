"""
Shared utilities for AutoIt3 deobfuscation transforms.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

from refinery.lib.scripts import Node, Statement, set_child_list
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.model import Au3FunctionDeclaration

#: What a statement-list rebuild asks per statement, given the scope it stands in: `None` keeps
#: the statement, and a sequence is what stands in its place.
Replacement = Callable[[Statement, Au3FunctionDeclaration | None], Sequence[Statement] | None]


def rebuild_statements(
    parent: Node,
    attr: str,
    scope: Au3FunctionDeclaration | None,
    replace: Replacement,
) -> bool:
    """
    The statement list *attr* of *parent*, which stands in *scope*, rebuilt through *replace*:
    a statement it keeps has its nested lists and any function body it holds rebuilt the same
    way, and a sequence it answers takes the statement's place unvisited — the statement itself
    among them when *replace* edited it where it stands. A list is written back only when one of
    its statements changed, and the answer is whether any list was.
    """
    surviving: list[Statement] = []
    changed = False
    for statement in getattr(parent, attr):
        replacement = replace(statement, scope)
        if replacement is not None:
            surviving.extend(replacement)
            changed = True
            continue
        surviving.append(statement)
        if rebuild_nested(statement, scope, replace):
            changed = True
    if changed:
        set_child_list(parent, attr, surviving)
    return changed


def rebuild_nested(
    statement: Statement,
    scope: Au3FunctionDeclaration | None,
    replace: Replacement,
) -> bool:
    """
    Every statement list *statement* holds, rebuilt through *replace* by `rebuild_statements`:
    its nested lists in *scope*, and the body of a function declaration in the function's own.
    """
    changed = False
    for owner, nested in ast.statement_lists(statement):
        if rebuild_statements(owner, nested, scope, replace):
            changed = True
    if isinstance(statement, Au3FunctionDeclaration):
        if rebuild_statements(statement, 'body', statement, replace):
            changed = True
    return changed
