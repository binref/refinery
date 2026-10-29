"""
The model of `test.lib.scripts.ps1.dispatch` held to what Windows PowerShell 5.1 wrote, and the
analysis held to the model over generated programs.
"""
from __future__ import annotations

import functools
import re

from dataclasses import dataclass

from test import TestBase
from test.lib.scripts.ps1 import corpus, dispatch
from test.lib.scripts.ps1.dispatch import (
    Break,
    Catch,
    Continue,
    Event,
    Fail,
    Generator,
    If,
    Loop,
    Mark,
    Preference,
    Statement,
    Sub,
    Throw,
    Trap,
    Try,
)

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.effects import deletion_is_observable
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BreakStatement,
    Ps1ContinueStatement,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1IfStatement,
    Ps1SubExpression,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def shown(trace: dispatch.Trace) -> str:
    """
    A trace as the transcripts below record it: each mark, `ERROR` for an error 5.1 reported and
    stepped over, and `THROW` where the run ended on one.
    """
    return ' '.join(
        event.value if isinstance(event, Event) else event for event in trace if event is not Event.ENDED)


#: What Windows PowerShell 5.1 wrote for each anchor of `test.lib.scripts.ps1.dispatch.ANCHORS`,
#: measured on 2026-10-29 by running each one as `test.lib.scripts.ps1.corpus.DISPATCH` renders it,
#: in the form `shown` gives. An anchor added or changed has no entry until it is measured with
#: `test.lib.scripts.ps1.oracle.behaviours`.
DISPATCH_TRANSCRIPTS: dict[str, str] = {
    'top / cast / Continue'                                                             : 'ERROR rest',
    'if / cast / Continue'                                                              : 'ERROR rest after',
    'loop / cast / Continue'                                                            : 'ERROR rest ERROR rest after',
    'try body, finally / cast / Continue'                                               : 'fin ERROR after',
    'catch body / cast / Continue'                                                      : 'ERROR after',
    'finally body / cast / Continue'                                                    : 't ERROR rest after',
    'finally body, error / cast / Continue'                                             : 'c after',
    'trap body / cast / Continue'                                                       : 'THROW',
    'subexpression / cast / Continue'                                                   : 'ERROR rest after',
    'if in a catch body / cast / Continue'                                              : 'ERROR after',
    'try in a try body / cast / Continue'                                               : 'ERROR after',
    'loop in a try body / cast / Continue'                                              : 'c after',
    'try body, catch [untyped] / cast / Continue'                                       : 'c after',
    'trapped block, continue [untyped] / cast / Continue'                               : 't rest after',
    'under a trapped block, continue [untyped] / cast / Continue'                       : 't after',
    'trapped block, break [untyped] / cast / Continue'                                  : 't THROW',
    'under a trapped block, break [untyped] / cast / Continue'                          : 't THROW',
    'trapped block, runs off [untyped] / cast / Continue'                               : 't ERROR rest after',
    'under a trapped block, runs off [untyped] / cast / Continue'                       : 't ERROR after',
    'try body, catch [RuntimeException] / cast / Continue'                              : 'c after',
    'trapped block, continue [RuntimeException] / cast / Continue'                      : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / Continue'              : 't after',
    'trapped block, break [RuntimeException] / cast / Continue'                         : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / Continue'                 : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / Continue'                      : 't ERROR rest after',
    'under a trapped block, runs off [RuntimeException] / cast / Continue'              : 't ERROR after',
    'try body, catch [InvalidCastException] / cast / Continue'                          : 'c after',
    'trapped block, continue [InvalidCastException] / cast / Continue'                  : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / Continue'          : 't after',
    'trapped block, break [InvalidCastException] / cast / Continue'                     : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / Continue'             : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / Continue'                  : 't ERROR rest after',
    'under a trapped block, runs off [InvalidCastException] / cast / Continue'          : 't ERROR after',
    'try body, catch [IOException] / cast / Continue'                                   : 'ERROR after',
    'trapped block, continue [IOException] / cast / Continue'                           : 'THROW',
    'under a trapped block, continue [IOException] / cast / Continue'                   : 'THROW',
    'trapped block, break [IOException] / cast / Continue'                              : 'THROW',
    'under a trapped block, break [IOException] / cast / Continue'                      : 'THROW',
    'trapped block, runs off [IOException] / cast / Continue'                           : 'THROW',
    'under a trapped block, runs off [IOException] / cast / Continue'                   : 'THROW',
    'top / cast / SilentlyContinue'                                                     : 'rest',
    'if / cast / SilentlyContinue'                                                      : 'rest after',
    'loop / cast / SilentlyContinue'                                                    : 'rest rest after',
    'try body, finally / cast / SilentlyContinue'                                       : 'fin after',
    'catch body / cast / SilentlyContinue'                                              : 'after',
    'finally body / cast / SilentlyContinue'                                            : 't rest after',
    'finally body, error / cast / SilentlyContinue'                                     : 'c after',
    'subexpression / cast / SilentlyContinue'                                           : 'rest after',
    'if in a catch body / cast / SilentlyContinue'                                      : 'after',
    'try in a try body / cast / SilentlyContinue'                                       : 'after',
    'loop in a try body / cast / SilentlyContinue'                                      : 'c after',
    'try body, catch [untyped] / cast / SilentlyContinue'                               : 'c after',
    'trapped block, continue [untyped] / cast / SilentlyContinue'                       : 't rest after',
    'under a trapped block, continue [untyped] / cast / SilentlyContinue'               : 't after',
    'trapped block, break [untyped] / cast / SilentlyContinue'                          : 't THROW',
    'under a trapped block, break [untyped] / cast / SilentlyContinue'                  : 't THROW',
    'trapped block, runs off [untyped] / cast / SilentlyContinue'                       : 't rest after',
    'under a trapped block, runs off [untyped] / cast / SilentlyContinue'               : 't after',
    'try body, catch [RuntimeException] / cast / SilentlyContinue'                      : 'c after',
    'trapped block, continue [RuntimeException] / cast / SilentlyContinue'              : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / SilentlyContinue'      : 't after',
    'trapped block, break [RuntimeException] / cast / SilentlyContinue'                 : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / SilentlyContinue'         : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / SilentlyContinue'              : 't rest after',
    'under a trapped block, runs off [RuntimeException] / cast / SilentlyContinue'      : 't after',
    'try body, catch [InvalidCastException] / cast / SilentlyContinue'                  : 'c after',
    'trapped block, continue [InvalidCastException] / cast / SilentlyContinue'          : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / SilentlyContinue'  : 't after',
    'trapped block, break [InvalidCastException] / cast / SilentlyContinue'             : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / SilentlyContinue'     : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / SilentlyContinue'          : 't rest after',
    'under a trapped block, runs off [InvalidCastException] / cast / SilentlyContinue'  : 't after',
    'try body, catch [IOException] / cast / SilentlyContinue'                           : 'after',
    'trapped block, continue [IOException] / cast / SilentlyContinue'                   : 'THROW',
    'under a trapped block, continue [IOException] / cast / SilentlyContinue'           : 'THROW',
    'trapped block, break [IOException] / cast / SilentlyContinue'                      : 'THROW',
    'under a trapped block, break [IOException] / cast / SilentlyContinue'              : 'THROW',
    'trapped block, runs off [IOException] / cast / SilentlyContinue'                   : 'THROW',
    'under a trapped block, runs off [IOException] / cast / SilentlyContinue'           : 'THROW',
    'top / cast / Stop'                                                                 : 'THROW',
    'if / cast / Stop'                                                                  : 'THROW',
    'loop / cast / Stop'                                                                : 'THROW',
    'try body, finally / cast / Stop'                                                   : 'fin THROW',
    'catch body / cast / Stop'                                                          : 'THROW',
    'finally body / cast / Stop'                                                        : 't THROW',
    'finally body, error / cast / Stop'                                                 : 'c after',
    'trap body / cast / Stop'                                                           : 'THROW',
    'subexpression / cast / Stop'                                                       : 'THROW',
    'if in a catch body / cast / Stop'                                                  : 'THROW',
    'try in a try body / cast / Stop'                                                   : 'THROW',
    'loop in a try body / cast / Stop'                                                  : 'c after',
    'try body, catch [untyped] / cast / Stop'                                           : 'c after',
    'trapped block, continue [untyped] / cast / Stop'                                   : 't rest after',
    'under a trapped block, continue [untyped] / cast / Stop'                           : 't after',
    'trapped block, break [untyped] / cast / Stop'                                      : 't THROW',
    'under a trapped block, break [untyped] / cast / Stop'                              : 't THROW',
    'trapped block, runs off [untyped] / cast / Stop'                                   : 't THROW',
    'under a trapped block, runs off [untyped] / cast / Stop'                           : 't THROW',
    'try body, catch [RuntimeException] / cast / Stop'                                  : 'c after',
    'trapped block, continue [RuntimeException] / cast / Stop'                          : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / Stop'                  : 't after',
    'trapped block, break [RuntimeException] / cast / Stop'                             : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / Stop'                     : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / Stop'                          : 't THROW',
    'under a trapped block, runs off [RuntimeException] / cast / Stop'                  : 't THROW',
    'try body, catch [InvalidCastException] / cast / Stop'                              : 'c after',
    'trapped block, continue [InvalidCastException] / cast / Stop'                      : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / Stop'              : 't after',
    'trapped block, break [InvalidCastException] / cast / Stop'                         : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / Stop'                 : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / Stop'                      : 't THROW',
    'under a trapped block, runs off [InvalidCastException] / cast / Stop'              : 't THROW',
    'try body, catch [IOException] / cast / Stop'                                       : 'THROW',
    'trapped block, continue [IOException] / cast / Stop'                               : 'THROW',
    'under a trapped block, continue [IOException] / cast / Stop'                       : 'THROW',
    'trapped block, break [IOException] / cast / Stop'                                  : 'THROW',
    'under a trapped block, break [IOException] / cast / Stop'                          : 'THROW',
    'trapped block, runs off [IOException] / cast / Stop'                               : 'THROW',
    'under a trapped block, runs off [IOException] / cast / Stop'                       : 'THROW',
    'top / throw / Continue'                                                            : 'THROW',
    'if / throw / Continue'                                                             : 'THROW',
    'loop / throw / Continue'                                                           : 'THROW',
    'try body, finally / throw / Continue'                                              : 'fin THROW',
    'catch body / throw / Continue'                                                     : 'THROW',
    'finally body / throw / Continue'                                                   : 't THROW',
    'finally body, error / throw / Continue'                                            : 'c after',
    'trap body / throw / Continue'                                                      : 'THROW',
    'subexpression / throw / Continue'                                                  : 'THROW',
    'if in a catch body / throw / Continue'                                             : 'THROW',
    'try in a try body / throw / Continue'                                              : 'THROW',
    'loop in a try body / throw / Continue'                                             : 'c after',
    'try body, catch [untyped] / throw / Continue'                                      : 'c after',
    'trapped block, continue [untyped] / throw / Continue'                              : 't rest after',
    'under a trapped block, continue [untyped] / throw / Continue'                      : 't after',
    'trapped block, break [untyped] / throw / Continue'                                 : 't THROW',
    'under a trapped block, break [untyped] / throw / Continue'                         : 't THROW',
    'trapped block, runs off [untyped] / throw / Continue'                              : 't ERROR rest after',
    'under a trapped block, runs off [untyped] / throw / Continue'                      : 't ERROR after',
    'try body, catch [RuntimeException] / throw / Continue'                             : 'c after',
    'trapped block, continue [RuntimeException] / throw / Continue'                     : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / Continue'             : 't after',
    'trapped block, break [RuntimeException] / throw / Continue'                        : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / Continue'                : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / Continue'                     : 't ERROR rest after',
    'under a trapped block, runs off [RuntimeException] / throw / Continue'             : 't ERROR after',
    'try body, catch [InvalidCastException] / throw / Continue'                         : 'THROW',
    'trapped block, continue [InvalidCastException] / throw / Continue'                 : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / Continue'         : 'THROW',
    'trapped block, break [InvalidCastException] / throw / Continue'                    : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / Continue'            : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / Continue'                 : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / Continue'         : 'THROW',
    'try body, catch [IOException] / throw / Continue'                                  : 'THROW',
    'trapped block, continue [IOException] / throw / Continue'                          : 'THROW',
    'under a trapped block, continue [IOException] / throw / Continue'                  : 'THROW',
    'trapped block, break [IOException] / throw / Continue'                             : 'THROW',
    'under a trapped block, break [IOException] / throw / Continue'                     : 'THROW',
    'trapped block, runs off [IOException] / throw / Continue'                          : 'THROW',
    'under a trapped block, runs off [IOException] / throw / Continue'                  : 'THROW',
    'top / throw / SilentlyContinue'                                                    : 'rest',
    'if / throw / SilentlyContinue'                                                     : 'rest after',
    'loop / throw / SilentlyContinue'                                                   : 'rest rest after',
    'try body, finally / throw / SilentlyContinue'                                      : 'fin after',
    'catch body / throw / SilentlyContinue'                                             : 'after',
    'finally body / throw / SilentlyContinue'                                           : 't rest after',
    'finally body, error / throw / SilentlyContinue'                                    : 'c after',
    'subexpression / throw / SilentlyContinue'                                          : 'rest after',
    'if in a catch body / throw / SilentlyContinue'                                     : 'after',
    'try in a try body / throw / SilentlyContinue'                                      : 'after',
    'loop in a try body / throw / SilentlyContinue'                                     : 'c after',
    'try body, catch [untyped] / throw / SilentlyContinue'                              : 'c after',
    'trapped block, continue [untyped] / throw / SilentlyContinue'                      : 't rest after',
    'under a trapped block, continue [untyped] / throw / SilentlyContinue'              : 't after',
    'trapped block, break [untyped] / throw / SilentlyContinue'                         : 't THROW',
    'under a trapped block, break [untyped] / throw / SilentlyContinue'                 : 't THROW',
    'trapped block, runs off [untyped] / throw / SilentlyContinue'                      : 't rest after',
    'under a trapped block, runs off [untyped] / throw / SilentlyContinue'              : 't after',
    'try body, catch [RuntimeException] / throw / SilentlyContinue'                     : 'c after',
    'trapped block, continue [RuntimeException] / throw / SilentlyContinue'             : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / SilentlyContinue'     : 't after',
    'trapped block, break [RuntimeException] / throw / SilentlyContinue'                : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / SilentlyContinue'        : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / SilentlyContinue'             : 't rest after',
    'under a trapped block, runs off [RuntimeException] / throw / SilentlyContinue'     : 't after',
    'try body, catch [InvalidCastException] / throw / SilentlyContinue'                 : 'after',
    'trapped block, continue [InvalidCastException] / throw / SilentlyContinue'         : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / SilentlyContinue' : 'THROW',
    'trapped block, break [InvalidCastException] / throw / SilentlyContinue'            : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / SilentlyContinue'    : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / SilentlyContinue'         : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / SilentlyContinue' : 'THROW',
    'try body, catch [IOException] / throw / SilentlyContinue'                          : 'after',
    'trapped block, continue [IOException] / throw / SilentlyContinue'                  : 'THROW',
    'under a trapped block, continue [IOException] / throw / SilentlyContinue'          : 'THROW',
    'trapped block, break [IOException] / throw / SilentlyContinue'                     : 'THROW',
    'under a trapped block, break [IOException] / throw / SilentlyContinue'             : 'THROW',
    'trapped block, runs off [IOException] / throw / SilentlyContinue'                  : 'THROW',
    'under a trapped block, runs off [IOException] / throw / SilentlyContinue'          : 'THROW',
    'top / throw / Stop'                                                                : 'THROW',
    'if / throw / Stop'                                                                 : 'THROW',
    'loop / throw / Stop'                                                               : 'THROW',
    'try body, finally / throw / Stop'                                                  : 'fin THROW',
    'catch body / throw / Stop'                                                         : 'THROW',
    'finally body / throw / Stop'                                                       : 't THROW',
    'finally body, error / throw / Stop'                                                : 'c after',
    'trap body / throw / Stop'                                                          : 'THROW',
    'subexpression / throw / Stop'                                                      : 'THROW',
    'if in a catch body / throw / Stop'                                                 : 'THROW',
    'try in a try body / throw / Stop'                                                  : 'THROW',
    'loop in a try body / throw / Stop'                                                 : 'c after',
    'try body, catch [untyped] / throw / Stop'                                          : 'c after',
    'trapped block, continue [untyped] / throw / Stop'                                  : 't rest after',
    'under a trapped block, continue [untyped] / throw / Stop'                          : 't after',
    'trapped block, break [untyped] / throw / Stop'                                     : 't THROW',
    'under a trapped block, break [untyped] / throw / Stop'                             : 't THROW',
    'trapped block, runs off [untyped] / throw / Stop'                                  : 't THROW',
    'under a trapped block, runs off [untyped] / throw / Stop'                          : 't THROW',
    'try body, catch [RuntimeException] / throw / Stop'                                 : 'c after',
    'trapped block, continue [RuntimeException] / throw / Stop'                         : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / Stop'                 : 't after',
    'trapped block, break [RuntimeException] / throw / Stop'                            : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / Stop'                    : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / Stop'                         : 't THROW',
    'under a trapped block, runs off [RuntimeException] / throw / Stop'                 : 't THROW',
    'try body, catch [InvalidCastException] / throw / Stop'                             : 'THROW',
    'trapped block, continue [InvalidCastException] / throw / Stop'                     : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / Stop'             : 'THROW',
    'trapped block, break [InvalidCastException] / throw / Stop'                        : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / Stop'                : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / Stop'                     : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / Stop'             : 'THROW',
    'try body, catch [IOException] / throw / Stop'                                      : 'THROW',
    'trapped block, continue [IOException] / throw / Stop'                              : 'THROW',
    'under a trapped block, continue [IOException] / throw / Stop'                      : 'THROW',
    'trapped block, break [IOException] / throw / Stop'                                 : 'THROW',
    'under a trapped block, break [IOException] / throw / Stop'                         : 'THROW',
    'trapped block, runs off [IOException] / throw / Stop'                              : 'THROW',
    'under a trapped block, runs off [IOException] / throw / Stop'                      : 'THROW',
}


class Unreadable(Exception):
    pass


_SYNTH = Ps1Synthesizer()
_FAIL = re.compile(r'^\$null = \[int\]\$args\[(\d+)\]$', re.IGNORECASE)
_MARK = re.compile(r"^Write-Host '(\w+)'$", re.IGNORECASE)
_TEST = re.compile(r'^\$args\[(\d+)\]$', re.IGNORECASE)
_PREFERENCE = re.compile(r"^\$ErrorActionPreference = '(\w+)'$", re.IGNORECASE)


class _Reader:
    """
    Reads a script `test.lib.scripts.ps1.dispatch.render` wrote, or the deobfuscator made of one,
    back into the grammar, and keeps which node each failing point and `trap` was read from.
    """

    def __init__(self):
        self.nodes: dict[int, Node] = {}

    def program(self, body) -> tuple[Statement, ...]:
        read: list[Statement] = []
        for node in body:
            statement = self._statement(node)
            if statement is not None:
                self.nodes[id(statement)] = node
                read.append(statement)
        return tuple(read)

    def _block(self, block) -> tuple[Statement, ...]:
        return () if block is None else self.program(block.body)

    def _statement(self, node) -> Statement | None:
        if isinstance(node, Ps1ExpressionStatement):
            text = _SYNTH.convert(node).strip()
            if _PREFERENCE.match(text):
                return None
            if (match := _FAIL.match(text)):
                return Fail(int(match.group(1)))
            if (match := _MARK.match(text)):
                return Mark(match.group(1))
            expression = node.expression
            if (
                isinstance(expression, Ps1AssignmentExpression)
                and isinstance(expression.value, Ps1SubExpression)
                and expression.target is not None
                and _SYNTH.convert(expression.target).strip().lower() == '$null'
            ):
                return Sub(self.program(expression.value.body))
            raise Unreadable(text)
        if isinstance(node, Ps1ThrowStatement):
            return Throw()
        if isinstance(node, Ps1IfStatement):
            if len(node.clauses) != 1:
                raise Unreadable(_SYNTH.convert(node))
            condition, block = node.clauses[0]
            if not (match := _TEST.match(_SYNTH.convert(condition).strip())):
                raise Unreadable(_SYNTH.convert(node))
            return If(int(match.group(1)), self._block(block), self._block(node.else_block))
        if isinstance(node, Ps1ForEachLoop):
            return Loop(self._block(node.body))
        if isinstance(node, Ps1TryCatchFinally):
            catches = []
            for clause in node.catch_clauses:
                if len(clause.types) > 1:
                    raise Unreadable(_SYNTH.convert(node))
                catches.append(Catch(clause.types[0] if clause.types else None, self._block(clause.body)))
            final = None if node.finally_block is None else self._block(node.finally_block)
            return Try(self._block(node.try_block), tuple(catches), final)
        if isinstance(node, Ps1TrapStatement):
            return Trap(node.type_name.strip() or None, self._block(node.body))
        if isinstance(node, Ps1ContinueStatement) and node.label is None:
            return Continue()
        if isinstance(node, Ps1BreakStatement) and node.label is None:
            return Break()
        raise Unreadable(_SYNTH.convert(node))


def _observable(program: tuple[Statement, ...], removed: Statement, preference: Preference) -> bool:
    smaller = dispatch.without(program, removed)
    return any(
        dispatch.visible(dispatch.run(program, preference, on))
        != dispatch.visible(dispatch.run(smaller, preference, on))
        for on in dispatch.vectors(program)
    )


@dataclass(frozen=True)
class Disagreement:
    """
    One answer of the analysis the model contradicts, for the generated program `number`: deleting
    a failing point or a `trap` the model says changes what the program shows was called
    unobservable, or the output shows something else for some inputs.
    """
    law: str
    number: int


def disagreements(program: tuple[Statement, ...], preference: Preference, number: int) -> list[Disagreement]:
    """
    Every answer of the analysis about generated program `number` the model contradicts.
    """
    source = dispatch.render(program, preference)
    tree = Ps1Parser(source).parse()
    reader = _Reader()
    read = reader.program(tree.body)
    cache = Ps1ModelCache(tree)
    faults = cache.faults
    handlers = cache.handlers
    found: set[Disagreement] = set()
    for statement in dispatch.statements(read):
        node = reader.nodes.get(id(statement))
        if node is None or not _observable(read, statement, preference):
            continue
        if isinstance(statement, Fail):
            if not deletion_is_observable(node, faults, cache.world_reach, cache.error_state):
                found.add(Disagreement('deletion veto', number))
        elif isinstance(node, Ps1TrapStatement):
            if faults.removable_traps([node], handlers.raises(True), handlers.skips):
                found.add(Disagreement('trap removal', number))
    output = Ps1Parser(source).parse()
    deobfuscate(output, trust_eval=False)
    try:
        rewritten = _Reader().program(output.body)
    except Unreadable:
        found.add(Disagreement('output unreadable', number))
        return sorted(found, key=str)
    if any(
        dispatch.visible(dispatch.run(read, preference, on))
        != dispatch.visible(dispatch.run(rewritten, preference, on))
        for on in dispatch.vectors(read)
    ):
        found.add(Disagreement('output', number))
    return sorted(found, key=str)


#: How many generated programs the analysis is held to, and the seed that names them. Over these
#: 400 the analysis the error roadmap started from disagrees with the model 37 times, and a reader
#: that forgets either landing of plan (1) 8 and 23 times.
PROGRAMS = 400
SEED = 7


@functools.cache
def _all_disagreements() -> tuple[Disagreement, ...]:
    found: list[Disagreement] = []
    for number, (program, preference) in enumerate(Generator(SEED).programs(PROGRAMS)):
        found.extend(disagreements(program, preference, number))
    return tuple(found)


#: The disagreements the analysis has today over the generated programs, each with the defect it
#: is an instance of. A program is rendered with `test.lib.scripts.ps1.dispatch.render` from its
#: place in `Generator(SEED).programs(PROGRAMS)`.
DISPATCH_DEFECTS: dict[Disagreement, str] = {
    Disagreement('output', 235):
        'A failing cast that is the last line of a `try` body with a `finally` is removed; see '
        '`TestPs1WhereAnErrorLandsIsAskedOfEveryWayIntoIt` in '
        '`test.lib.scripts.ps1.deobfuscation.test_removal_observability`.',
}


class TestPs1TheDispatchModelWritesWhat51Writes(TestBase):
    """
    The model is held to what 5.1 wrote for every anchor, reported errors included.
    """

    def test_every_anchor_runs_as_51_ran_it(self):
        for name, (program, preference, on) in dispatch.ANCHORS.items():
            if name not in DISPATCH_TRANSCRIPTS:
                continue
            with self.subTest(name):
                self.assertEqual(shown(dispatch.run(program, preference, on)), DISPATCH_TRANSCRIPTS[name])

    def test_every_anchor_was_measured(self):
        self.assertEqual(sorted(set(dispatch.ANCHORS) - set(DISPATCH_TRANSCRIPTS)), [])

    def test_every_measurement_is_an_anchor(self):
        self.assertEqual(sorted(set(DISPATCH_TRANSCRIPTS) - set(dispatch.ANCHORS)), [])

    def test_the_corpus_runs_the_anchors_as_the_model_renders_them(self):
        self.assertEqual(corpus.DISPATCH, tuple(
            dispatch.render(program, preference, on) for program, preference, on in dispatch.ANCHORS.values()))

    def test_every_generated_program_reads_back_as_it_was_generated(self):
        for number, (program, preference) in enumerate(Generator(SEED).programs(PROGRAMS)):
            source = dispatch.render(program, preference)
            with self.subTest(number=number):
                self.assertEqual(
                    dispatch.render(_Reader().program(Ps1Parser(source).parse().body), preference), source)


class TestPs1TheAnalysisAgreesWithTheDispatchModel(TestBase):
    """
    Over generated programs, the deletion veto and the `trap` removal answer never call a deletion
    unobservable that the model says changes what the program shows, and the deobfuscated output
    shows what the program shows for every input.
    """

    def test_every_disagreement_is_a_recorded_defect(self):
        self.assertEqual(sorted(_all_disagreements(), key=str), sorted(DISPATCH_DEFECTS, key=str))
