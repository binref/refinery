from __future__ import annotations

import sys

from refinery.lib.excel import open_workbook
from refinery.lib.excel.formula import (
    International,
    parse_formula,
    synthesize_formula,
)
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlFunctionCall,
    XlNumber,
    XlR1C1Reference,
    XlUnaryExpression,
    XlUnaryOperator,
    XlUnparsedFormula,
)
from refinery.lib.scripts import canonical

from ... import TestBase
from .samples import REVENG1


class TestFormulaPrecedence(TestBase):

    def test_leading_negation_binds_tighter_than_power(self):
        self.assertEqual(
            canonical(parse_formula('=-2^2')),
            canonical(XlBinaryExpression(
                left=XlUnaryExpression(operator=XlUnaryOperator.NEG, operand=XlNumber(value=2)),
                operator=XlBinaryOperator.POW,
                right=XlNumber(value=2),
            )),
        )

    def test_power_right_operand_carries_unary_sign(self):
        self.assertEqual(
            canonical(parse_formula('=2^-2')),
            canonical(XlBinaryExpression(
                left=XlNumber(value=2),
                operator=XlBinaryOperator.POW,
                right=XlUnaryExpression(operator=XlUnaryOperator.NEG, operand=XlNumber(value=2)),
            )),
        )

    def test_parenthesized_power_binds_negation_outside(self):
        self.assertEqual(
            canonical(parse_formula('=-(2^2)')),
            canonical(XlUnaryExpression(
                operator=XlUnaryOperator.NEG,
                operand=XlBinaryExpression(
                    left=XlNumber(value=2),
                    operator=XlBinaryOperator.POW,
                    right=XlNumber(value=2),
                ),
            )),
        )

    def test_percent_is_postfix_and_tighter_than_power(self):
        self.assertEqual(
            canonical(parse_formula('=2^4%')),
            canonical(XlBinaryExpression(
                left=XlNumber(value=2),
                operator=XlBinaryOperator.POW,
                right=XlUnaryExpression(
                    operator=XlUnaryOperator.PERCENT,
                    operand=XlNumber(value=4),
                ),
            )),
        )

    def test_percent_wraps_tightened_negation(self):
        self.assertEqual(
            canonical(parse_formula('=-2%')),
            canonical(XlUnaryExpression(
                operator=XlUnaryOperator.PERCENT,
                operand=XlUnaryExpression(operator=XlUnaryOperator.NEG, operand=XlNumber(value=2)),
            )),
        )

    def test_multiplication_binds_tighter_than_addition(self):
        self.assertEqual(
            canonical(parse_formula('=1+2*3')),
            canonical(XlBinaryExpression(
                left=XlNumber(value=1),
                operator=XlBinaryOperator.ADD,
                right=XlBinaryExpression(
                    left=XlNumber(value=2),
                    operator=XlBinaryOperator.MUL,
                    right=XlNumber(value=3),
                ),
            )),
        )

    def test_range_binds_tighter_than_intersection(self):
        self.assertEqual(
            canonical(parse_formula('=A1:B2 C1:D2')),
            canonical(XlBinaryExpression(
                left=XlBinaryExpression(
                    left=XlA1Reference(row=1, col=1),
                    operator=XlBinaryOperator.RANGE,
                    right=XlA1Reference(row=2, col=2),
                ),
                operator=XlBinaryOperator.ISECT,
                right=XlBinaryExpression(
                    left=XlA1Reference(row=1, col=3),
                    operator=XlBinaryOperator.RANGE,
                    right=XlA1Reference(row=2, col=4),
                ),
            )),
        )

    def test_space_before_sign_is_subtraction_not_intersection(self):
        for text in ('=A1 -B1', '=A1 - B1'):
            self.assertEqual(
                canonical(parse_formula(text)),
                canonical(XlBinaryExpression(
                    left=XlA1Reference(row=1, col=1),
                    operator=XlBinaryOperator.SUB,
                    right=XlA1Reference(row=1, col=2),
                )),
            )

    def test_space_between_operands_is_intersection(self):
        self.assertEqual(
            canonical(parse_formula('=A1 B1')),
            canonical(XlBinaryExpression(
                left=XlA1Reference(row=1, col=1),
                operator=XlBinaryOperator.ISECT,
                right=XlA1Reference(row=1, col=2),
            )),
        )

    def test_separator_inside_call_is_not_union(self):
        self.assertEqual(
            canonical(parse_formula('=SUM(A1,B1)')),
            canonical(XlFunctionCall(
                callee='SUM',
                arguments=[XlA1Reference(row=1, col=1), XlA1Reference(row=1, col=2)],
            )),
        )

    def test_separator_inside_parens_is_union(self):
        self.assertEqual(
            canonical(parse_formula('=(A1,B1)')),
            canonical(XlBinaryExpression(
                left=XlA1Reference(row=1, col=1),
                operator=XlBinaryOperator.UNION,
                right=XlA1Reference(row=1, col=2),
            )),
        )


class TestFormulaReferences(TestBase):

    def test_r1c1_axes(self):
        self.assertEqual(synthesize_formula(parse_formula('=R1C2')), 'R1C2')
        self.assertEqual(synthesize_formula(parse_formula('=R[1]C[-1]')), 'R[1]C[-1]')
        self.assertEqual(synthesize_formula(parse_formula('=RC')), 'RC')
        self.assertEqual(
            canonical(parse_formula('=R[1]C[-1]')),
            canonical(XlR1C1Reference(row=1, col=-1)),
        )

    def test_name_like_tokens_stay_names(self):
        for name in ('R1C1X', 'SUMXMY2', 'TRUE5', '_xlfn.SUM', '_xlnm.Print_Area'):
            self.assertEqual(
                canonical(parse_formula(F'={name}')),
                canonical(parse_formula(name)),
            )
            self.assertEqual(synthesize_formula(parse_formula(F'={name}')), name)

    def test_dollar_flags_per_axis(self):
        self.assertEqual(
            canonical(parse_formula('=$A$1+$B1+C$1')),
            canonical(XlBinaryExpression(
                left=XlBinaryExpression(
                    left=XlA1Reference(row=1, col=1, relative_row=False, relative_col=False),
                    operator=XlBinaryOperator.ADD,
                    right=XlA1Reference(row=1, col=2, relative_col=False),
                ),
                operator=XlBinaryOperator.ADD,
                right=XlA1Reference(row=1, col=3, relative_row=False),
            )),
        )
        self.assertEqual(synthesize_formula(parse_formula('=$A$1+$B1+C$1')), '$A$1+$B1+C$1')

    def test_sheet_qualification(self):
        self.assertEqual(synthesize_formula(parse_formula("='My Sheet'!A1")), "'My Sheet'!A1")
        self.assertEqual(synthesize_formula(parse_formula("='My''Sheet'!A1")), "'My''Sheet'!A1")
        self.assertEqual(synthesize_formula(parse_formula('=Sheet1!A1')), 'Sheet1!A1')
        self.assertEqual(
            synthesize_formula(parse_formula('=Sheet1:Sheet2!A1')),
            'Sheet1:Sheet2!A1',
        )
        self.assertEqual(
            canonical(parse_formula("='My Sheet':'Your Sheet'!A1")),
            canonical(parse_formula("='My Sheet':'Your Sheet'!A1")),
        )

    def test_call_of_macro_cell(self):
        self.assertEqual(
            canonical(parse_formula("='Doc1'!AJ102()")),
            canonical(XlFunctionCall(callee=XlA1Reference(sheets=('Doc1',), row=102, col=36))),
        )


class TestFormulaRoundTrip(TestBase):

    VECTORS = [
        '=-2^2',
        '=2^-2',
        '=-(2^2)',
        '=-2%',
        '=2^4%',
        '=-2^2%',
        '=2^3^2',
        '=2^(3^2)',
        '=(1+2)*3',
        '=1+2*3',
        '=(1+2)+3',
        '=1+(2+3)',
        '=A1-B1',
        '=A1 - B1',
        '=A1 B1',
        '=(A1,B1)',
        '=(A1 B1)',
        '=A1:B2 C1:D2',
        '=(A1:B2,C1:D2)',
        '=$A$1+$B1+C$1',
        '=SUM(A1,B1)',
        '=SUM(A1,B1,C1)',
        '=IF(A1,,B1)',
        '=IF(,A1,)',
        '=R1C1()',
        '=R1C2',
        '=R[1]C[-1]',
        '=RC',
        '=SUMXMY2',
        "='Doc1'!AJ102()",
        "='My Sheet'!A1",
        "='My''Sheet'!A1",
        '=Sheet1:Sheet2!A1',
        "='My Sheet':'Your Sheet'!A1",
        '=TRUE',
        '=FALSE',
        '=#N/A',
        '="#REF!"',
        '="a""b"',
        '={1,2;3,4}',
        '={-1,"x";TRUE,#REF!}',
        '={1}',
        '=1.5e3',
        '.5+.5',
        '=A1&"x"&B1',
        '=A1<B1',
        '=A1<>B1',
        '=A1>=B1',
        '=A1=EXEC(4)',
        '=NOT(A1=1)',
        '=x.y!foo',
        '=_xlfn.SUM(A1)',
        '=1+2*3^4%*5',
        '=-(2%)',
    ]

    def test_synthesis_reparse_is_canonical_and_fixpoint(self):
        for text in self.VECTORS:
            with self.subTest(text=text):
                tree = parse_formula(text)
                once = synthesize_formula(tree)
                reparsed = parse_formula(once)
                self.assertEqual(canonical(reparsed), canonical(tree))
                self.assertEqual(synthesize_formula(reparsed), once)

    def test_spelled_numbers_keep_their_source(self):
        self.assertEqual(synthesize_formula(parse_formula('=1.50')), '1.50')
        self.assertEqual(synthesize_formula(parse_formula('=.5')), '.5')
        self.assertEqual(synthesize_formula(parse_formula('=1e3')), '1e3')

    def test_missing_argument_prints_nothing(self):
        self.assertEqual(synthesize_formula(parse_formula('=IF(a,,b)')), 'IF(a,,b)')


class TestFormulaFailurePaths(TestBase):

    def test_unparseable_input_becomes_carrier(self):
        for text in ('=SUM(A1,B1', '== broken', "='unterminated", '=A1,', '=1,', '='):
            self.assertEqual(
                canonical(parse_formula(text)),
                canonical(XlUnparsedFormula(text=text)),
            )

    def test_whole_column_and_row_spans_become_carriers(self):
        # `A:C` would otherwise read as a range between the defined names A and C, and `1:3` as
        # a range between two numbers; the model has no node for either span
        for text in ('=SUM(A:C)', '=SUM($A:$C)', '=SUM(Sheet1!A:C)', '=SUM(1:3)', '=SUM(A:A)'):
            self.assertEqual(
                canonical(parse_formula(text)),
                canonical(XlUnparsedFormula(text=text)),
            )

    def test_carrier_prints_its_text(self):
        for text in ('=SUM(A1,B1', '== broken'):
            self.assertEqual(synthesize_formula(parse_formula(text)), text)

    def test_deeply_nested_input_does_not_raise(self):
        text = '=' + '(' * 4000 + '1' + ')' * 4000
        self.assertEqual(
            canonical(parse_formula(text)),
            canonical(XlUnparsedFormula(text=text)),
        )

    def test_how_deep_a_formula_nests_does_not_depend_on_the_recursion_limit_of_the_caller(self):
        text = '=' + 'CHAR(' * 100 + '1' + ')' * 100
        ambient = sys.getrecursionlimit()
        sys.setrecursionlimit(1000)
        try:
            tree = parse_formula(text)
        finally:
            sys.setrecursionlimit(ambient)
        # a carrier would print the leading equals sign along with the rest of the text
        self.assertEqual(synthesize_formula(tree), text[1:])


class TestFormulaInternational(TestBase):

    def test_semicolon_list_separator(self):
        international = International(list_separator=';')
        tree = parse_formula('=SUM(A1;B1)', international)
        self.assertEqual(synthesize_formula(tree, international), 'SUM(A1;B1)')
        self.assertEqual(synthesize_formula(tree), 'SUM(A1,B1)')

    def test_bracket_dialect(self):
        international = International(left_bracket='<', right_bracket='>')
        tree = parse_formula('=R<1>C<-1>', international)
        self.assertEqual(synthesize_formula(tree, international), 'R<1>C<-1>')
        self.assertEqual(synthesize_formula(tree), 'R[1]C[-1]')


class TestFormulaStoredText(TestBase):

    def test_stored_ooxml_formula_text_round_trips(self):
        """
        The `<f>` element text an OOXML workbook stores is the ground truth for the parser: every
        formula in the embedded sample must survive a synthesis and a re-parse unchanged.
        """
        count = 0
        for sheet in open_workbook(REVENG1).sheets():
            for cell in sheet.cells():
                if not isinstance(cell.formula, str):
                    continue
                count += 1
                with self.subTest(sheet=sheet.name, row=cell.row, col=cell.col):
                    tree = parse_formula(cell.formula)
                    once = synthesize_formula(tree)
                    reparsed = parse_formula(once)
                    self.assertEqual(canonical(reparsed), canonical(tree))
                    self.assertEqual(synthesize_formula(reparsed), once)
        self.assertEqual(count, 50)
