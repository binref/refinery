"""
`refinery.lib.scripts.ps1.analysis.values.evaluate` remembers the answers it has already given. What
it remembers is only sound while the expression still denotes what it denoted and while the caller
asking is the one that asked, so what is held here is that its answers are the ones it would give
with no memory at all: the same expression asked twice, an expression a mutation has changed
underneath it, and two callers that type a variable occurrence differently.
"""
from __future__ import annotations

import itertools
import unittest

from refinery.lib.scripts import Node, set_child, set_child_list, set_value
from refinery.lib.scripts.ps1.analysis.values import (
    MAYBE,
    NEVER,
    NOTHING,
    Ps1Constant,
    Ps1Outcome,
    Ps1Typed,
    Ps1VariableTyping,
    evaluate,
    type_of,
)
from refinery.lib.scripts.ps1.data import resolve_type
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1BinaryExpression,
    Ps1ExpressionStatement,
    Ps1ParenExpression,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _type(name: str) -> Ps1TypeName:
    resolved = resolve_type(name)
    assert resolved is not None, name
    return resolved


INT32 = _type('System.Int32')
INT64 = _type('System.Int64')
STRING = _type('System.String')
OBJECT_ARRAY = _type('System.Object[]')
FILE_INFO = _type('System.IO.FileInfo')


def _expressions(source: str) -> list[Expression]:
    found = []
    for statement in Ps1Parser(source).parse().body:
        assert isinstance(statement, Ps1ExpressionStatement)
        assert statement.expression is not None
        found.append(statement.expression)
    return found


def _expression(source: str) -> Expression:
    return _expressions(source)[0]


def _binary(source: str) -> Ps1BinaryExpression:
    node = _expression(source)
    assert isinstance(node, Ps1BinaryExpression)
    return node


def _parenthesized_binary(node: Node | None) -> Ps1BinaryExpression:
    assert isinstance(node, Ps1ParenExpression)
    assert isinstance(node.expression, Ps1BinaryExpression)
    return node.expression


def _typed_as(name: Ps1TypeName | None) -> Ps1VariableTyping:
    return lambda variable: name


def _int32_array(*values: int) -> Ps1Outcome:
    elements = tuple(Ps1Constant(INT32, value) for value in values)
    return Ps1Outcome(NEVER, Ps1Constant(OBJECT_ARRAY, elements))


class TestPs1EvaluateAnswersTheSameWhetherOrNotItRemembers(unittest.TestCase):
    """
    A remembered answer is an optimisation and nothing else: an expression asked about a second time
    is worth exactly what it was worth the first time, and a caller that asks in a different order
    or asks the same thing twice reads the same answers.
    """

    SOURCES = (
        '1 + 1',
        "'a' + 'b'",
        '[int]1.5',
        '(2 * (3 + 4))',
        '1, 2, 3',
        '$x',
        '$x + 1',
        '[int]"0x10" -band 255',
    )

    def _asked_once(self, source: str) -> Ps1Outcome:
        return evaluate(_expression(source))

    def _asked_twice(self, source: str) -> Ps1Outcome:
        node = _expression(source)
        evaluate(node)
        return evaluate(node)

    def test_asking_twice_answers_what_asking_once_answered(self):
        self.assertEqual(
            {source: self._asked_twice(source) for source in self.SOURCES},
            {source: self._asked_once(source) for source in self.SOURCES},
        )

    def test_asking_in_any_order_answers_what_asking_alone_answered(self):
        alone = {source: self._asked_once(source) for source in self.SOURCES}
        nodes = dict(zip(self.SOURCES, _expressions('\n'.join(self.SOURCES))))
        for order in (self.SOURCES, tuple(reversed(self.SOURCES))):
            self.assertEqual({source: evaluate(nodes[source]) for source in order}, alone)

    def test_a_subexpression_answers_the_same_asked_before_and_after_its_parent(self):
        node = _binary('(1 + 2) * 3')
        inner = node.left
        self.assertIsInstance(inner, Ps1ParenExpression)
        before = evaluate(inner)
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 9)))
        self.assertEqual(evaluate(inner), before)
        self.assertEqual(before, Ps1Outcome(NEVER, Ps1Constant(INT32, 3)))


class TestPs1EvaluateAnswersForTheTreeAsItStandsNow(unittest.TestCase):
    """
    Every mutation below changes what the expression denotes, so the answer given before it is the
    wrong answer after it. A cache that survives the edit reports the value of a script that is no
    longer there, and a fold reading it writes that value into the script.
    """

    def test_a_replaced_operand_is_the_operand_the_answer_is_built_from(self):
        node = _expression('2 + 3')
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 5)))
        set_child(node, 'right', _expression('40'))
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 42)))

    def test_a_replaced_operator_is_the_operator_the_answer_is_built_from(self):
        node = _expression('2 + 3')
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 5)))
        set_value(node, 'operator', '*')
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 6)))

    def test_a_replacement_deep_in_the_expression_reaches_the_answer_for_the_whole(self):
        node = _binary('(1 + 1) * 10')
        inner = _parenthesized_binary(node.left)
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 20)))
        set_child(inner, 'right', _expression('4'))
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 50)))

    def test_a_replaced_array_element_is_the_element_the_array_is_built_from(self):
        node = _expression('1, 2')
        self.assertEqual(evaluate(node), _int32_array(1, 2))
        set_child_list(node, 'elements', [_expression('7'), _expression('8')])
        self.assertEqual(evaluate(node), _int32_array(7, 8))

    def test_a_constant_operand_replaced_by_a_variable_stops_naming_a_value(self):
        node = _expression("'a' + 'b'")
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(STRING, 'ab')))
        set_child(node, 'right', _expression('$x'))
        self.assertEqual(evaluate(node), NOTHING)

    def test_a_variable_operand_replaced_by_a_constant_starts_naming_a_value(self):
        node = _expression('$x + 1')
        self.assertEqual(evaluate(node), NOTHING)
        set_child(node, 'left', _expression('41'))
        self.assertEqual(evaluate(node), Ps1Outcome(NEVER, Ps1Constant(INT32, 42)))

    def test_an_edit_to_another_tree_does_not_change_the_answer_here(self):
        node = _expression('2 + 3')
        answer = evaluate(node)
        set_value(_expression('2 + 3'), 'operator', '*')
        self.assertEqual(evaluate(node), answer)
        self.assertEqual(answer, Ps1Outcome(NEVER, Ps1Constant(INT32, 5)))


class TestPs1EvaluateKeepsTheTypingsOfDifferentCallersApart(unittest.TestCase):
    """
    The typing a caller passes decides what a variable occurrence carries, so it decides the answer:
    `String.Length` is an Int32 and `FileInfo.Length` an Int64, and a caller that types nothing is
    owed neither. Two callers asking about the same node therefore ask two different questions.
    """

    SOURCE = '$f.Length'

    TYPINGS = {
        'untyped'   : None,
        'string'    : _typed_as(STRING),
        'file_info' : _typed_as(FILE_INFO),
    }

    def _asked_alone(self) -> dict[str, Ps1Outcome]:
        return {
            name: evaluate(_expression(self.SOURCE), typing)
            for name, typing in self.TYPINGS.items()
        }

    def test_the_typing_of_the_receiver_decides_the_type_of_the_member(self):
        self.assertEqual(
            {name: type_of(answer.value) for name, answer in self._asked_alone().items()},
            {'untyped': None, 'string': INT32, 'file_info': INT64},
        )

    def test_every_order_of_asking_gives_each_typing_the_answer_it_asked_for(self):
        alone = self._asked_alone()
        self.assertEqual(len(set(alone.values())), len(self.TYPINGS))
        for order in itertools.permutations(self.TYPINGS):
            node = _expression(self.SOURCE)
            self.assertEqual(
                {name: evaluate(node, self.TYPINGS[name]) for name in order}, alone)

    def test_a_typing_asked_again_after_another_one_still_answers_its_own(self):
        alone = self._asked_alone()
        for first, second in itertools.permutations(self.TYPINGS, 2):
            node = _expression(self.SOURCE)
            self.assertEqual(evaluate(node, self.TYPINGS[first]), alone[first])
            self.assertEqual(evaluate(node, self.TYPINGS[second]), alone[second])
            self.assertEqual(evaluate(node, self.TYPINGS[first]), alone[first])

    def test_two_typings_that_disagree_only_about_one_variable_answer_differently(self):
        node = _expression('$f.Length -band $g.Length')
        both = evaluate(node, _typed_as(STRING))
        self.assertEqual(both, Ps1Outcome(MAYBE, Ps1Typed(INT32)))
        only_f = evaluate(node, lambda variable: STRING if variable.name == 'f' else None)
        self.assertEqual(only_f, NOTHING)
        self.assertEqual(evaluate(node, _typed_as(STRING)), both)


if __name__ == '__main__':
    unittest.main()
