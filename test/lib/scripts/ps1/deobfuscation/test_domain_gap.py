from __future__ import annotations

import collections
import unittest

from refinery.lib.scripts.ps1.analysis.values import NOTHING, UNKNOWN, apply, read, render
from refinery.lib.scripts.ps1.data import binary_operators, operand_witnesses
from refinery.lib.scripts.ps1.deobfuscation.emulator import _Ps1Interpreter
from refinery.lib.scripts.ps1.model import Ps1BinaryExpression, Ps1ExpressionStatement
from refinery.lib.scripts.ps1.parser import Ps1Parser

#: How many applications the interpreter answers and the value domain declines to, by the type of
#: the left operand. The interpreter cannot be pointed at the domain while this is not empty: every
#: one of these is a fold the deobfuscator takes today and would stop taking.
#:
#: The four largest rows are the four types the domain refuses to read a grid cell over, and they
#: are the migration's work in the order it is worth doing. This is a ratchet — the numbers come
#: down as the domain learns to answer, and a commit that raises one has removed a fold.
GAP: dict[str, int] = {
    'System.String': 2133,
    'System.Object[]': 1317,
    'System.Char': 1125,
    'System.Int64': 1132,
    'System.Int32': 750,
    'System.Double': 640,
    'System.Byte': 450,
    'System.Boolean': 260,
    'System.Void': 170,
}

#: The witness spellings the reader cannot make a fact of, so the census is quantified over the
#: rest. Three are a `Single`, which no fact carries because `render` cannot spell one, and two read
#: a static member rather than writing a value. Pinned because a census whose population shrinks
#: silently reports an improvement it did not make.
UNREADABLE_WITNESSES: tuple[str, ...] = (
    '[decimal]::MaxValue',
    '[double]::MaxValue',
    '[single]-1.5',
    '[single]0',
    '[single]1.5',
)


def _witnesses() -> dict[str, tuple]:
    """
    The shipped operand witnesses as facts, keyed by the row they were captured for. Read out of
    the resource through the ordinary reader rather than written out again here, so that the census
    cannot come to be quantified over values the capture never used.
    """
    found = {}
    for name, spellings in operand_witnesses().items():
        facts = []
        for spelling in spellings:
            statement = next(
                node for node in Ps1Parser(spelling).parse().walk()
                if isinstance(node, Ps1ExpressionStatement)
            )
            fact = read(statement.expression)
            if fact is not UNKNOWN:
                facts.append(fact)
        if facts:
            found[name] = tuple(facts)
    return found


def _unreadable() -> list[str]:
    refused = []
    for spellings in operand_witnesses().values():
        for spelling in spellings:
            statement = next(
                node for node in Ps1Parser(spelling).parse().walk()
                if isinstance(node, Ps1ExpressionStatement)
            )
            if read(statement.expression) is UNKNOWN:
                refused.append(spelling)
    return sorted(refused)


def _gap() -> collections.Counter:
    interpreter = _Ps1Interpreter()
    counted: collections.Counter = collections.Counter()
    for operator in sorted(binary_operators()):
        for name, lefts in _witnesses().items():
            for rights in _witnesses().values():
                for left in lefts:
                    for right in rights:
                        spelled_left, spelled_right = render(left), render(right)
                        if spelled_left is None or spelled_right is None:
                            continue
                        node = Ps1BinaryExpression(
                            operator=operator, left=spelled_left, right=spelled_right)
                        try:
                            interpreter._eval_binary(node)
                        except Exception:
                            continue
                        if apply(operator, left, right) is NOTHING:
                            counted[name] += 1
    return counted


class TestPs1DomainAnswersWhereTheInterpreterDoes(unittest.TestCase):
    """
    What stands between the interpreter and the value domain, counted rather than described.

    The interpreter computes in Python values that carry no .NET type; the domain computes in facts
    that do. Pointing the first at the second is only sound once the domain answers wherever the
    interpreter answers, and this is the measurement of how far that is from true.
    """

    def test_the_applications_only_the_interpreter_answers_are_the_ones_recorded(self):
        self.assertEqual(dict(_gap()), GAP)

    def test_the_witnesses_the_census_cannot_read_are_the_ones_recorded(self):
        self.assertEqual(_unreadable(), sorted(UNREADABLE_WITNESSES))
