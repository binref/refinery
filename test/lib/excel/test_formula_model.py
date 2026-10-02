from __future__ import annotations

from refinery.lib.excel.formula import parse_formula, synthesize_formula
from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlDefinedName,
    XlFunctionCall,
    XlNumber,
    XlParenExpression,
)
from refinery.lib.scripts import canonical

from ... import TestBase


class TestFormulaModelCanonicalForms(TestBase):
    """
    The canonical form of two programs is what survives when only spelling differences remain:
    a parenthesis the source wrote and a defined name in the callee position of a call both
    spell nothing the plain form does not, while the raw spelling of a number is a display
    concern of the synthesizer alone.
    """

    def test_parenthesis_wraps_to_its_operand(self):
        self.assertEqual(
            canonical(XlParenExpression(operand=XlNumber(value=1))),
            canonical(XlNumber(value=1)),
        )

    def test_defined_name_callee_wraps_to_a_name_call(self):
        self.assertEqual(
            canonical(XlFunctionCall(callee=XlDefinedName(name='X'), arguments=[])),
            canonical(XlFunctionCall(callee='X', arguments=[])),
        )

    def test_number_spelling_is_not_the_program(self):
        self.assertEqual(
            canonical(parse_formula('=1e3')),
            canonical(parse_formula('=1000')),
        )

    def test_number_spelling_survives_synthesis(self):
        self.assertEqual(synthesize_formula(parse_formula('=1e3')), '1e3')
        self.assertEqual(synthesize_formula(parse_formula('=1000')), '1000')


class TestFormulaModelNodeFramework(TestBase):

    def test_array_constant_rows_are_children(self):
        tree = parse_formula('={1,"a";2,"b"}')
        self.assertEqual(
            [type(node).__name__ for node in tree.children()],
            ['XlNumber', 'XlString', 'XlNumber', 'XlString'],
        )
        self.assertEqual(
            {type(node).__name__ for node in tree.walk()},
            {'XlArrayConstant', 'XlNumber', 'XlString'},
        )

    def test_call_arguments_are_children(self):
        tree = parse_formula('=SUM(A1,"a")')
        self.assertEqual(
            [type(node).__name__ for node in tree.children()],
            ['XlA1Reference', 'XlString'],
        )

    def test_an_array_constant_rebuilds_from_its_children(self):
        tree = parse_formula('={1,"a";2,"b"}')
        rows = tree.rows
        rebuilt = XlArrayConstant(rows=rows)
        self.assertEqual(synthesize_formula(rebuilt), '{1,"a";2,"b"}')

    def test_an_empty_call_is_a_valid_program(self):
        tree = parse_formula('=RETURN()')
        self.assertEqual(synthesize_formula(tree), 'RETURN()')
        self.assertEqual(
            canonical(tree),
            canonical(XlFunctionCall(callee='RETURN', arguments=[])),
        )


class TestFormulaModelSynthesis(TestBase):
    """
    Synthesis of trees whose output has to stay readable as the same tree: a union inside an
    argument list, and a nesting deeper than the recursion limit the synthesizer runs under.
    """

    def test_a_union_call_argument_is_wrapped_in_parentheses(self):
        # a union bare in the argument list would read back as two arguments of the call
        union = XlBinaryExpression(
            left=XlA1Reference(row=1, col=1),
            operator=XlBinaryOperator.UNION,
            right=XlA1Reference(row=1, col=2),
        )
        call = XlFunctionCall(callee='SUM', arguments=[union])
        self.assertEqual(synthesize_formula(call), 'SUM((A1,B1))')
        self.assertEqual(canonical(call), canonical(parse_formula('=SUM((A1,B1))')))
        self.assertNotEqual(canonical(call), canonical(parse_formula('=SUM(A1,B1)')))

    def test_a_tree_past_the_recursion_limit_synthesizes(self):
        tree: Expression = XlNumber(value=1)
        for _ in range(2000):
            tree = XlParenExpression(operand=tree)
        self.assertEqual(synthesize_formula(tree), 2000 * '(' + '1' + 2000 * ')')
