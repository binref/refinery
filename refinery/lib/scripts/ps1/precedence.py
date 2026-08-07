"""
How tightly each PowerShell construct binds, as one scale read by both the parser and the
synthesizer.

The parser needs it to decide what an operator takes as its operands; the synthesizer needs it to
decide where a bracket has to go, because a tree a pass builds carries no parentheses of its own and
`Ps1BinaryExpression(Ps1BinaryExpression(1, '+', 2), '*', 3)` prints as `1 + 2 * 3` without one.
Keeping the two on separate tables is how a printer drifts from the grammar it is supposed to
invert, so the tiers are named here once and both sides name them.

The order is the one `Ps1Parser` implements, which is also the order the reference tokenizer gives:
range binds tighter than format, format tighter than multiplication, and the comma that builds an
array tighter than any binary operator.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandInvocation,
    Ps1Pipeline,
    Ps1RangeExpression,
    Ps1UnaryExpression,
)

#: A primary expression: a literal, a variable, a member access, anything already delimited. It
#: takes no neighbours, so it never needs a bracket and every slot accepts it.
ATOM = 100

#: A prefix operator and a cast. Both bind to a single operand.
UNARY = 90

#: The comma that builds an array. It is an operand of the binary operators rather than the other
#: way round, so it binds tighter than all of them.
COMMA = 80

RANGE = 70
FORMAT = 60
MULTIPLICATIVE = 50
ADDITIVE = 40
COMPARISON = 30
BITWISE = 20
LOGICAL = 10
ASSIGNMENT = 5

#: A command invocation and a pipeline. Both run to the end of the statement, taking whatever
#: follows as arguments or stages, so anything printed after one is swallowed by it. Nothing may
#: stand beside one unbracketed.
COMMAND = 0

BINARY: dict[str, int] = {
    '..'  : RANGE,          # noqa
    '-f'  : FORMAT,         # noqa
    '*'   : MULTIPLICATIVE, # noqa
    '/'   : MULTIPLICATIVE, # noqa
    '%'   : MULTIPLICATIVE, # noqa
    '+'   : ADDITIVE,       # noqa
    '-'   : ADDITIVE,       # noqa
}
BINARY.update(dict.fromkeys(('-and', '-or', '-xor'), LOGICAL))
BINARY.update(dict.fromkeys(('-band', '-bor', '-bxor'), BITWISE))


def register_comparisons(operators) -> None:
    """
    Record the comparison operators, which the parser derives from its dash-operator table. They
    are added here rather than spelled out twice, so that an operator the lexer learns to read is
    one the synthesizer knows how to bracket.
    """
    BINARY.update(dict.fromkeys(operators, COMPARISON))


def of_operator(operator: str) -> int:
    """
    How tightly `operator` binds. An operator the table does not know is treated as the loosest
    binary tier, which brackets more than necessary rather than less.
    """
    return BINARY.get(operator.lower(), LOGICAL)


def of(node: Node) -> int:
    """
    How tightly the *spelling* of `node` binds — that is, how loosely its outermost operator holds
    on to what is printed beside it. A slot that requires more than this has to bracket the node.
    """
    if isinstance(node, Ps1BinaryExpression):
        return of_operator(node.operator)
    if isinstance(node, Ps1RangeExpression):
        return RANGE
    if isinstance(node, Ps1ArrayLiteral):
        return COMMA
    if isinstance(node, (Ps1UnaryExpression, Ps1CastExpression)):
        return UNARY
    if isinstance(node, Ps1AssignmentExpression):
        return ASSIGNMENT
    if isinstance(node, (Ps1CommandInvocation, Ps1Pipeline)):
        return COMMAND
    return ATOM


def needs_brackets(node: Expression, minimum: int) -> bool:
    return of(node) < minimum


def needs_brackets_between_delimiters(node: Node) -> bool:
    """
    Whether `node` has to be bracketed inside a list the language already delimits, as a method
    call and an attribute delimit their arguments with `(` and `)`.

    This is not a question about binding power, because the delimiters bound the slot on both
    sides and every operator binds tighter than they do: `M($a * 2)` reads back whole. Two things
    still reach past them. A comma is the delimiter, so an argument built with the comma operator
    would be read as several arguments; the parser makes the same distinction from the other side
    by disabling the comma while it reads one. And a command takes what follows as its own
    arguments.
    """
    return isinstance(node, Ps1ArrayLiteral) or of(node) <= COMMAND
