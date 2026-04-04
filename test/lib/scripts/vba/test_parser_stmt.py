from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaCallStatement,
    VbaConstDeclaration,
    VbaDeclareStatement,
    VbaDoLoopStatement,
    VbaEndStatement,
    VbaEnumDefinition,
    VbaErrorNode,
    VbaExitStatement,
    VbaExpressionStatement,
    VbaForEachStatement,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaGotoStatement,
    VbaGosubStatement,
    VbaIdentifier,
    VbaIfStatement,
    VbaIntegerLiteral,
    VbaLabelStatement,
    VbaLetStatement,
    VbaMemberAccess,
    VbaOnErrorStatement,
    VbaOptionStatement,
    VbaPropertyDeclaration,
    VbaRangeExpression,
    VbaRedimStatement,
    VbaResumeStatement,
    VbaReturnStatement,
    VbaSelectCaseStatement,
    VbaSetStatement,
    VbaStopStatement,
    VbaStringLiteral,
    VbaSubDeclaration,
    VbaTypeDefinition,
    VbaVariableDeclaration,
    VbaWhileStatement,
    VbaWithStatement,
)


class TestVbaParserStatements(TestBase):

    def _parse(self, source: str):
        return VbaParser(source).parse()

    def test_option_explicit(self):
        ast = self._parse('Option Explicit')
        self.assertEqual(len(ast.body), 1)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaOptionStatement)
        self.assertEqual(stmt.keyword, 'Explicit')

    def test_option_compare_binary(self):
        ast = self._parse('Option Compare Binary')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaOptionStatement)
        self.assertEqual(stmt.keyword, 'Compare')
        self.assertEqual(stmt.value, 'Binary')

    def test_option_base(self):
        ast = self._parse('Option Base 0')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaOptionStatement)
        self.assertEqual(stmt.keyword, 'Base')
        self.assertEqual(stmt.value, '0')

    def test_dim_declaration(self):
        ast = self._parse('Dim x As Long')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.declarators[0].name, 'x')
        self.assertEqual(stmt.declarators[0].type_name, 'Long')

    def test_dim_array(self):
        ast = self._parse('Dim arr(10) As String')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertTrue(stmt.declarators[0].is_array)

    def test_dim_multiple(self):
        ast = self._parse('Dim a As Long, b As String')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(len(stmt.declarators), 2)

    def test_const_declaration(self):
        ast = self._parse('Const PI As Double = 3.14')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaConstDeclaration)
        self.assertEqual(stmt.name, 'PI')
        self.assertEqual(stmt.type_name, 'Double')

    def test_sub_empty(self):
        ast = self._parse('Sub Test()\nEnd Sub')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(stmt.name, 'Test')
        self.assertEqual(len(stmt.body), 0)

    def test_sub_with_params(self):
        ast = self._parse('Sub Greet(ByVal name As String)\nEnd Sub')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(len(stmt.params), 1)
        self.assertEqual(stmt.params[0].name, 'name')
        self.assertEqual(stmt.params[0].passing, 'ByVal')
        self.assertEqual(stmt.params[0].type_name, 'String')

    def test_function_with_return_type(self):
        ast = self._parse('Function Add(a As Long, b As Long) As Long\nAdd = a + b\nEnd Function')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaFunctionDeclaration)
        self.assertEqual(stmt.return_type, 'Long')
        self.assertEqual(len(stmt.params), 2)
        self.assertEqual(len(stmt.body), 1)

    def test_property_get(self):
        ast = self._parse('Property Get Name() As String\nName = "test"\nEnd Property')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaPropertyDeclaration)
        self.assertEqual(stmt.kind, 'Get')
        self.assertEqual(stmt.name, 'Name')
        self.assertEqual(stmt.return_type, 'String')

    def test_property_let(self):
        ast = self._parse('Property Let Name(ByVal v As String)\nm_name = v\nEnd Property')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaPropertyDeclaration)
        self.assertEqual(stmt.kind, 'Let')

    def test_if_block(self):
        code = 'Sub T()\nIf x > 0 Then\ny = 1\nEnd If\nEnd Sub'
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertFalse(if_stmt.single_line)

    def test_if_else(self):
        code = 'Sub T()\nIf x > 0 Then\ny = 1\nElse\ny = 0\nEnd If\nEnd Sub'
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(len(if_stmt.else_body) > 0)

    def test_if_elseif(self):
        code = 'Sub T()\nIf x = 1 Then\ny = 1\nElseIf x = 2 Then\ny = 2\nElse\ny = 0\nEnd If\nEnd Sub'
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertEqual(len(if_stmt.elseif_clauses), 1)

    def test_single_line_if(self):
        code = 'Sub T()\nIf x > 0 Then y = 1 Else y = 0\nEnd Sub'
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)

    def test_for_next(self):
        code = 'Sub T()\nFor i = 1 To 10\nDebug.Print i\nNext i\nEnd Sub'
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)

    def test_for_step(self):
        code = 'Sub T()\nFor i = 10 To 1 Step -1\nNext\nEnd Sub'
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)
        self.assertIsNotNone(for_stmt.step)

    def test_for_each(self):
        code = 'Sub T()\nFor Each item In col\nDebug.Print item\nNext\nEnd Sub'
        ast = self._parse(code)
        foreach = ast.body[0].body[0]
        assert isinstance(foreach, VbaForEachStatement)

    def test_do_while_pre(self):
        code = 'Sub T()\nDo While x > 0\nx = x - 1\nLoop\nEnd Sub'
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertEqual(do_stmt.condition_type, 'While')
        self.assertEqual(do_stmt.condition_position, 'pre')

    def test_do_until_post(self):
        code = 'Sub T()\nDo\nx = x + 1\nLoop Until x > 10\nEnd Sub'
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertEqual(do_stmt.condition_type, 'Until')
        self.assertEqual(do_stmt.condition_position, 'post')

    def test_do_loop_infinite(self):
        code = 'Sub T()\nDo\nx = x + 1\nLoop\nEnd Sub'
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertIsNone(do_stmt.condition)

    def test_while_wend(self):
        code = 'Sub T()\nWhile x > 0\nx = x - 1\nWend\nEnd Sub'
        ast = self._parse(code)
        while_stmt = ast.body[0].body[0]
        assert isinstance(while_stmt, VbaWhileStatement)

    def test_select_case(self):
        code = 'Sub T()\nSelect Case x\nCase 1\ny = "one"\nCase 2, 3\ny = "two or three"\nCase Else\ny = "other"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 3)
        self.assertTrue(sel.cases[2].is_else)

    def test_with_statement(self):
        code = 'Sub T()\nWith obj\n.Name = "test"\nEnd With\nEnd Sub'
        ast = self._parse(code)
        with_stmt = ast.body[0].body[0]
        assert isinstance(with_stmt, VbaWithStatement)

    def test_set_statement(self):
        code = 'Sub T()\nSet x = CreateObject("Scripting.Dictionary")\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaSetStatement)

    def test_let_statement_explicit(self):
        code = 'Sub T()\nLet x = 5\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement)
        self.assertTrue(stmt.explicit)

    def test_implicit_assignment(self):
        code = 'Sub T()\nx = 5\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement)
        self.assertFalse(stmt.explicit)

    def test_call_statement_explicit(self):
        code = 'Sub T()\nCall MyFunc(1, 2)\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaCallStatement)

    def test_implicit_call_no_parens(self):
        code = 'Sub T()\nMsgBox "Hello"\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExpressionStatement)
        self.assertTrue(len(stmt.arguments) > 0)

    def test_goto(self):
        code = 'Sub T()\nGoTo Cleanup\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaGotoStatement)
        self.assertEqual(stmt.label, 'Cleanup')

    def test_gosub(self):
        code = 'Sub T()\nGoSub Handler\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaGosubStatement)

    def test_on_error_resume_next(self):
        code = 'Sub T()\nOn Error Resume Next\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, 'ResumeNext')

    def test_on_error_goto(self):
        code = 'Sub T()\nOn Error GoTo Handler\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, 'GoTo')
        self.assertEqual(stmt.label, 'Handler')

    def test_on_error_goto_0(self):
        code = 'Sub T()\nOn Error GoTo 0\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.label, '0')

    def test_exit_sub(self):
        code = 'Sub T()\nExit Sub\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, 'Sub')

    def test_exit_function(self):
        code = 'Function T() As Long\nExit Function\nEnd Function'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, 'Function')

    def test_exit_for(self):
        code = 'Sub T()\nFor i = 1 To 10\nExit For\nNext\nEnd Sub'
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)
        exit_stmt = for_stmt.body[0]
        assert isinstance(exit_stmt, VbaExitStatement)
        self.assertEqual(exit_stmt.kind, 'For')

    def test_return_statement(self):
        code = 'Sub T()\nReturn\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaReturnStatement)

    def test_stop_statement(self):
        code = 'Sub T()\nStop\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaStopStatement)

    def test_end_statement(self):
        code = 'Sub T()\nEnd\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaEndStatement)

    def test_resume_next(self):
        code = 'Sub T()\nResume Next\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaResumeStatement)
        self.assertEqual(stmt.label, 'Next')

    def test_label_with_colon(self):
        code = 'Sub T()\nCleanup:\nExit Sub\nEnd Sub'
        ast = self._parse(code)
        assert isinstance(ast.body[0].body[0], VbaLabelStatement)

    def test_line_number_label(self):
        code = 'Sub T()\n10 x = 1\nEnd Sub'
        ast = self._parse(code)
        self.assertTrue(len(ast.body[0].body) >= 1)

    def test_type_definition(self):
        code = 'Type MyType\nx As Long\ny As String\nEnd Type'
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaTypeDefinition)
        self.assertEqual(stmt.name, 'MyType')
        self.assertEqual(len(stmt.members), 2)

    def test_enum_definition(self):
        code = 'Enum Colors\nRed = 1\nGreen = 2\nBlue = 3\nEnd Enum'
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaEnumDefinition)
        self.assertEqual(stmt.name, 'Colors')
        self.assertEqual(len(stmt.members), 3)

    def test_declare_function(self):
        code = 'Declare Function GetTickCount Lib "kernel32" () As Long'
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaDeclareStatement)
        self.assertTrue(stmt.is_function)
        self.assertEqual(stmt.name, 'GetTickCount')

    def test_redim(self):
        code = 'Sub T()\nReDim arr(10)\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertFalse(stmt.preserve)

    def test_redim_preserve(self):
        code = 'Sub T()\nReDim Preserve arr(20)\nEnd Sub'
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertTrue(stmt.preserve)

    def test_public_sub(self):
        ast = self._parse('Public Sub Test()\nEnd Sub')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(stmt.scope, 'Public')

    def test_private_function(self):
        ast = self._parse('Private Function Foo() As Long\nEnd Function')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaFunctionDeclaration)
        self.assertEqual(stmt.scope, 'Private')

    def test_static_sub(self):
        ast = self._parse('Static Sub Test()\nEnd Sub')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertTrue(stmt.is_static)

    def test_optional_parameter(self):
        code = 'Sub T(Optional x As Long = 0)\nEnd Sub'
        ast = self._parse(code)
        param = ast.body[0].params[0]
        self.assertTrue(param.is_optional)
        self.assertIsNotNone(param.default)

    def test_select_case_range(self):
        code = 'Sub T()\nSelect Case x\nCase 1 To 10\ny = "range"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 1)
        test_expr = sel.cases[0].tests[0]
        assert isinstance(test_expr, VbaRangeExpression)
        assert isinstance(test_expr.start, VbaIntegerLiteral)
        assert isinstance(test_expr.end, VbaIntegerLiteral)
        self.assertEqual(test_expr.start.value, 1)
        self.assertEqual(test_expr.end.value, 10)

    def test_select_case_multiple_ranges(self):
        code = 'Sub T()\nSelect Case x\nCase 1 To 5, 10 To 20\ny = "range"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 1)
        self.assertEqual(len(sel.cases[0].tests), 2)
        for test_expr in sel.cases[0].tests:
            assert isinstance(test_expr, VbaRangeExpression)

    def test_select_case_comparison_bare_operator(self):
        code = 'Sub T()\nSelect Case x\nCase > 5\ny = "big"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 1)
        test_expr = sel.cases[0].tests[0]
        assert not isinstance(test_expr, VbaErrorNode), \
            'Case > 5 must not produce an error node'
        assert isinstance(test_expr, VbaBinaryExpression)
        self.assertEqual(test_expr.operator, '>')
        assert isinstance(test_expr.left, VbaIdentifier)
        self.assertEqual(test_expr.left.name.lower(), 'is')
        assert isinstance(test_expr.right, VbaIntegerLiteral)
        self.assertEqual(test_expr.right.value, 5)

    def test_select_case_comparison_with_is(self):
        code = 'Sub T()\nSelect Case x\nCase Is >= 10\ny = "big"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        test_expr = sel.cases[0].tests[0]
        assert isinstance(test_expr, VbaBinaryExpression)
        self.assertEqual(test_expr.operator, '>=')
        assert isinstance(test_expr.left, VbaIdentifier)
        self.assertEqual(test_expr.left.name.lower(), 'is')
        assert isinstance(test_expr.right, VbaIntegerLiteral)
        self.assertEqual(test_expr.right.value, 10)

    def test_select_case_comparison_equality(self):
        code = 'Sub T()\nSelect Case x\nCase Is = 3\ny = "three"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        test_expr = sel.cases[0].tests[0]
        assert isinstance(test_expr, VbaBinaryExpression)
        self.assertEqual(test_expr.operator, '=')
        assert isinstance(test_expr.left, VbaIdentifier)
        assert isinstance(test_expr.right, VbaIntegerLiteral)
        self.assertEqual(test_expr.right.value, 3)

    def test_select_case_multiple_comparisons(self):
        code = 'Sub T()\nSelect Case x\nCase < 0, >= 100\ny = "out"\nEnd Select\nEnd Sub'
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases[0].tests), 2)
        t0 = sel.cases[0].tests[0]
        assert isinstance(t0, VbaBinaryExpression)
        self.assertEqual(t0.operator, '<')
        assert isinstance(t0.right, VbaIntegerLiteral)
        self.assertEqual(t0.right.value, 0)
        t1 = sel.cases[0].tests[1]
        assert isinstance(t1, VbaBinaryExpression)
        self.assertEqual(t1.operator, '>=')
        assert isinstance(t1.right, VbaIntegerLiteral)
        self.assertEqual(t1.right.value, 100)

    def test_if_else_with_standalone_end(self):
        code = 'If x Then\ny = 1\nElse\nEnd\nEnd If'
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaIfStatement)
        self.assertEqual(len(stmt.else_body), 1)
        assert isinstance(stmt.else_body[0], VbaEndStatement)

    def test_with_dot_member_assignment(self):
        code = 'Sub T()\nWith obj\n.Name = "test"\nEnd With\nEnd Sub'
        ast = self._parse(code)
        with_stmt = ast.body[0].body[0]
        assert isinstance(with_stmt, VbaWithStatement)
        self.assertEqual(len(with_stmt.body), 1)
        stmt = with_stmt.body[0]
        assert isinstance(stmt, VbaLetStatement)
        assert isinstance(stmt.target, VbaMemberAccess)
        self.assertIsNone(stmt.target.object)
        self.assertEqual(stmt.target.member, 'Name')
        assert isinstance(stmt.value, VbaStringLiteral)
        self.assertEqual(stmt.value.value, 'test')
