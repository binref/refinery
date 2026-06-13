from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaByValArgument,
    VbaCallStatement,
    VbaConstDeclaration,
    VbaConstDeclarator,
    VbaDeclareStatement,
    VbaDebugPrintStatement,
    VbaDoLoopStatement,
    VbaEndStatement,
    VbaEnumDefinition,
    VbaErrorNode,
    VbaExitKind,
    VbaExitStatement,
    VbaExpressionStatement,
    VbaForEachStatement,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaGotoStatement,
    VbaGosubStatement,
    VbaIdentifier,
    VbaImplementsStatement,
    VbaElseIfClause,
    VbaIfStatement,
    VbaIntegerLiteral,
    VbaLabelStatement,
    VbaLetStatement,
    VbaLoopConditionPosition,
    VbaLoopConditionType,
    VbaMemberAccess,
    VbaNamedArgument,
    VbaOnBranchKind,
    VbaOnBranchStatement,
    VbaOnErrorAction,
    VbaOnErrorStatement,
    VbaOptionStatement,
    VbaParameterPassing,
    VbaPropertyDeclaration,
    VbaPropertyKind,
    VbaRangeExpression,
    VbaRedimStatement,
    VbaResumeStatement,
    VbaReturnStatement,
    VbaScopeModifier,
    VbaSelectCaseStatement,
    VbaSetStatement,
    VbaStopStatement,
    VbaStringLiteral,
    VbaSubDeclaration,
    VbaTypeDefinition,
    VbaUnaryExpression,
    VbaVariableDeclaration,
    VbaVariableDeclarator,
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

    def test_dim_withevents(self):
        ast = self._parse('Dim WithEvents obj As SomeClass')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(len(stmt.declarators), 1)
        d = stmt.declarators[0]
        assert isinstance(d, VbaVariableDeclarator)
        self.assertEqual(d.name, 'obj')
        self.assertEqual(d.type_name, 'SomeClass')
        self.assertTrue(d.with_events)

    def test_private_withevents(self):
        ast = self._parse('Private WithEvents m_App As Application')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.PRIVATE)
        d = stmt.declarators[0]
        assert isinstance(d, VbaVariableDeclarator)
        self.assertEqual(d.name, 'm_App')
        self.assertEqual(d.type_name, 'Application')
        self.assertTrue(d.with_events)

    def test_const_declaration(self):
        ast = self._parse('Const PI As Double = 3.14')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaConstDeclaration)
        self.assertEqual(len(stmt.declarators), 1)
        d = stmt.declarators[0]
        assert isinstance(d, VbaConstDeclarator)
        self.assertEqual(d.name, 'PI')
        self.assertEqual(d.type_name, 'Double')

    def test_const_declaration_multi(self):
        ast = self._parse('Const A = 1, B As Long = 2, C = 3')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaConstDeclaration)
        self.assertEqual(len(stmt.declarators), 3)
        self.assertEqual(stmt.declarators[0].name, 'A')
        self.assertEqual(stmt.declarators[0].type_name, '')
        self.assertEqual(stmt.declarators[1].name, 'B')
        self.assertEqual(stmt.declarators[1].type_name, 'Long')
        self.assertEqual(stmt.declarators[2].name, 'C')
        self.assertEqual(stmt.declarators[2].type_name, '')

    def test_sub_empty(self):
        ast = self._parse(cleandoc("""
            Sub Test()
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(stmt.name, 'Test')
        self.assertEqual(len(stmt.body), 0)

    def test_sub_with_params(self):
        ast = self._parse(cleandoc("""
            Sub Greet(ByVal name As String)
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(len(stmt.params), 1)
        self.assertEqual(stmt.params[0].name, 'name')
        self.assertEqual(stmt.params[0].passing, VbaParameterPassing.BY_VAL)
        self.assertEqual(stmt.params[0].type_name, 'String')

    def test_function_with_return_type(self):
        ast = self._parse(cleandoc("""
            Function Add(a As Long, b As Long) As Long
            Add = a + b
            End Function
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaFunctionDeclaration)
        self.assertEqual(stmt.return_type, 'Long')
        self.assertEqual(len(stmt.params), 2)
        self.assertEqual(len(stmt.body), 1)

    def test_property_get(self):
        ast = self._parse(cleandoc("""
            Property Get Name() As String
            Name = "test"
            End Property
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaPropertyDeclaration)
        self.assertEqual(stmt.kind, VbaPropertyKind.GET)
        self.assertEqual(stmt.name, 'Name')
        self.assertEqual(stmt.return_type, 'String')

    def test_property_let(self):
        ast = self._parse(cleandoc("""
            Property Let Name(ByVal v As String)
            m_name = v
            End Property
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaPropertyDeclaration)
        self.assertEqual(stmt.kind, VbaPropertyKind.LET)

    def test_if_block(self):
        code = cleandoc("""
            Sub T()
            If x > 0 Then
            y = 1
            End If
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertFalse(if_stmt.single_line)

    def test_if_endif_merged(self):
        code = cleandoc("""
            Sub T()
            If x > 0 Then
            y = 1
            EndIf
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertFalse(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 1)
        self.assertEqual(len(sub.body), 1)

    def test_if_else(self):
        code = cleandoc("""
            Sub T()
            If x > 0 Then
            y = 1
            Else
            y = 0
            End If
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(len(if_stmt.else_body) > 0)

    def test_if_elseif(self):
        code = cleandoc("""
            Sub T()
            If x = 1 Then
            y = 1
            ElseIf x = 2 Then
            y = 2
            Else
            y = 0
            End If
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertEqual(len(if_stmt.elseif_clauses), 1)

    def test_single_line_if(self):
        code = cleandoc("""
            Sub T()
            If x > 0 Then y = 1 Else y = 0
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)

    def test_for_next(self):
        code = cleandoc("""
            Sub T()
            For i = 1 To 10
            Debug.Print i
            Next i
            End Sub
        """)
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)

    def test_for_step(self):
        code = cleandoc("""
            Sub T()
            For i = 10 To 1 Step -1
            Next
            End Sub
        """)
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)
        self.assertIsNotNone(for_stmt.step)

    def test_for_each(self):
        code = cleandoc("""
            Sub T()
            For Each item In col
            Debug.Print item
            Next
            End Sub
        """)
        ast = self._parse(code)
        foreach = ast.body[0].body[0]
        assert isinstance(foreach, VbaForEachStatement)

    def test_for_next_comma_list(self):
        code = cleandoc("""
            Sub T()
            For i = 1 To 3
            For j = 1 To 3
            Debug.Print j
            Next j, i
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1)
        outer = sub.body[0]
        assert isinstance(outer, VbaForStatement)
        self.assertEqual(len(outer.body), 1)
        inner = outer.body[0]
        assert isinstance(inner, VbaForStatement)

    def test_do_while_pre(self):
        code = cleandoc("""
            Sub T()
            Do While x > 0
            x = x - 1
            Loop
            End Sub
        """)
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertEqual(do_stmt.condition_type, VbaLoopConditionType.WHILE)
        self.assertEqual(do_stmt.condition_position, VbaLoopConditionPosition.PRE)

    def test_do_until_post(self):
        code = cleandoc("""
            Sub T()
            Do
            x = x + 1
            Loop Until x > 10
            End Sub
        """)
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertEqual(do_stmt.condition_type, VbaLoopConditionType.UNTIL)
        self.assertEqual(do_stmt.condition_position, VbaLoopConditionPosition.POST)

    def test_do_loop_infinite(self):
        code = cleandoc("""
            Sub T()
            Do
            x = x + 1
            Loop
            End Sub
        """)
        ast = self._parse(code)
        do_stmt = ast.body[0].body[0]
        assert isinstance(do_stmt, VbaDoLoopStatement)
        self.assertIsNone(do_stmt.condition)

    def test_while_wend(self):
        code = cleandoc("""
            Sub T()
            While x > 0
            x = x - 1
            Wend
            End Sub
        """)
        ast = self._parse(code)
        while_stmt = ast.body[0].body[0]
        assert isinstance(while_stmt, VbaWhileStatement)

    def test_select_case(self):
        code = cleandoc("""
            Sub T()
            Select Case x
            Case 1
            y = "one"
            Case 2, 3
            y = "two or three"
            Case Else
            y = "other"
            End Select
            End Sub
        """)
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 3)
        self.assertTrue(sel.cases[2].is_else)

    def test_with_statement(self):
        code = cleandoc("""
            Sub T()
            With obj
            .Name = "test"
            End With
            End Sub
        """)
        ast = self._parse(code)
        with_stmt = ast.body[0].body[0]
        assert isinstance(with_stmt, VbaWithStatement)

    def test_set_statement(self):
        code = cleandoc("""
            Sub T()
            Set x = CreateObject("Scripting.Dictionary")
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaSetStatement)

    def test_let_statement_explicit(self):
        code = cleandoc("""
            Sub T()
            Let x = 5
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement)
        self.assertTrue(stmt.explicit)

    def test_implicit_assignment(self):
        code = cleandoc("""
            Sub T()
            x = 5
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement)
        self.assertFalse(stmt.explicit)

    def test_call_statement_explicit(self):
        code = cleandoc("""
            Sub T()
            Call MyFunc(1, 2)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaCallStatement)

    def test_implicit_call_no_parens(self):
        code = cleandoc("""
            Sub T()
            MsgBox "Hello"
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExpressionStatement)
        self.assertTrue(len(stmt.arguments) > 0)

    def test_goto(self):
        code = cleandoc("""
            Sub T()
            GoTo Cleanup
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaGotoStatement)
        self.assertEqual(stmt.label, 'Cleanup')

    def test_gosub(self):
        code = cleandoc("""
            Sub T()
            GoSub Handler
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaGosubStatement)

    def test_on_error_resume_next(self):
        code = cleandoc("""
            Sub T()
            On Error Resume Next
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, VbaOnErrorAction.RESUME_NEXT)

    def test_on_error_goto(self):
        code = cleandoc("""
            Sub T()
            On Error GoTo Handler
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, VbaOnErrorAction.GOTO)
        self.assertEqual(stmt.label, 'Handler')

    def test_on_error_goto_0(self):
        code = cleandoc("""
            Sub T()
            On Error GoTo 0
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.label, '0')

    def test_on_error_goto_minus_1(self):
        code = cleandoc("""
            Sub T()
            On Error GoTo -1
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, VbaOnErrorAction.GOTO)
        self.assertEqual(stmt.label, '-1')

    def test_on_goto_statement(self):
        code = cleandoc("""
            Sub T()
            On x GoTo 100, 200, 300
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnBranchStatement), \
            f'expected VbaOnBranchStatement but got {type(stmt).__name__}'
        self.assertEqual(stmt.kind, VbaOnBranchKind.GOTO)
        assert isinstance(stmt.expression, VbaIdentifier)
        self.assertEqual(stmt.expression.name, 'x')
        self.assertEqual(stmt.labels, ['100', '200', '300'])

    def test_on_gosub_statement(self):
        code = cleandoc("""
            Sub T()
            On n GoSub Label1, Label2
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnBranchStatement), \
            f'expected VbaOnBranchStatement but got {type(stmt).__name__}'
        self.assertEqual(stmt.kind, VbaOnBranchKind.GOSUB)
        assert isinstance(stmt.expression, VbaIdentifier)
        self.assertEqual(stmt.expression.name, 'n')
        self.assertEqual(stmt.labels, ['Label1', 'Label2'])

    def test_on_error_not_broken_by_on_goto(self):
        code = cleandoc("""
            Sub T()
            On Error GoTo Handler
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaOnErrorStatement), \
            f'expected VbaOnErrorStatement but got {type(stmt).__name__}'
        self.assertEqual(stmt.action, VbaOnErrorAction.GOTO)
        self.assertEqual(stmt.label, 'Handler')

    def test_goto_two_word_form(self):
        code = cleandoc("""
            Sub T()
            Go To done
            done:
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaGotoStatement)
        self.assertEqual(stmt.label, 'done')

    def test_gosub_two_word_form(self):
        code = cleandoc("""
            Sub T()
            Go Sub done
            done:
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaGosubStatement)
        self.assertEqual(stmt.label, 'done')

    def test_on_error_goto_two_word_form(self):
        code = cleandoc("""
            Sub T()
            On Error Go To 0
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaOnErrorStatement)
        self.assertEqual(stmt.action, VbaOnErrorAction.GOTO)
        self.assertEqual(stmt.label, '0')

    def test_exit_sub(self):
        code = cleandoc("""
            Sub T()
            Exit Sub
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, VbaExitKind.SUB)

    def test_exit_function(self):
        code = cleandoc("""
            Function T() As Long
            Exit Function
            End Function
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, VbaExitKind.FUNCTION)

    def test_exit_for(self):
        code = cleandoc("""
            Sub T()
            For i = 1 To 10
            Exit For
            Next
            End Sub
        """)
        ast = self._parse(code)
        for_stmt = ast.body[0].body[0]
        assert isinstance(for_stmt, VbaForStatement)
        exit_stmt = for_stmt.body[0]
        assert isinstance(exit_stmt, VbaExitStatement)
        self.assertEqual(exit_stmt.kind, VbaExitKind.FOR)

    def test_exit_unknown_keyword(self):
        code = cleandoc("""
            Sub T()
            Exit While
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1,
            'Exit with unknown keyword must produce exactly one error node, '
            'not cascade into a spurious While statement')
        assert isinstance(sub.body[0], VbaErrorNode)

    def test_lset_statement(self):
        code = cleandoc("""
            Sub T()
            LSet x = y
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement), \
            f'expected VbaLetStatement but got {type(stmt).__name__}'
        assert isinstance(stmt.target, VbaIdentifier)
        self.assertEqual(stmt.target.name, 'x')
        assert isinstance(stmt.value, VbaIdentifier)
        self.assertEqual(stmt.value.name, 'y')
        self.assertEqual(stmt.keyword.lower(), 'lset',
            'LSet keyword must be preserved in the AST node')

    def test_rset_statement(self):
        code = cleandoc("""
            Sub T()
            RSet a = b
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaLetStatement), \
            f'expected VbaLetStatement but got {type(stmt).__name__}'
        assert isinstance(stmt.target, VbaIdentifier)
        self.assertEqual(stmt.target.name, 'a')
        assert isinstance(stmt.value, VbaIdentifier)
        self.assertEqual(stmt.value.name, 'b')
        self.assertEqual(stmt.keyword.lower(), 'rset',
            'RSet keyword must be preserved in the AST node')

    def test_lset_keyword_distinct_from_let(self):
        # LSet and Let must produce different keyword values; previously both produced 'Let'
        ast_lset = self._parse(cleandoc("""
            Sub T()
            LSet x = y
            End Sub
        """))
        ast_let = self._parse(cleandoc("""
            Sub T()
            Let x = y
            End Sub
        """))
        stmt_lset = ast_lset.body[0].body[0]
        stmt_let = ast_let.body[0].body[0]
        assert isinstance(stmt_lset, VbaLetStatement)
        assert isinstance(stmt_let, VbaLetStatement)
        self.assertNotEqual(stmt_lset.keyword.lower(), stmt_let.keyword.lower(),
            'LSet and Let must have distinct keyword values in the AST')

    def test_return_statement(self):
        code = cleandoc("""
            Sub T()
            Return
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaReturnStatement)

    def test_stop_statement(self):
        code = cleandoc("""
            Sub T()
            Stop
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaStopStatement)

    def test_end_statement(self):
        code = cleandoc("""
            Sub T()
            End
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaEndStatement)

    def test_resume_next(self):
        code = cleandoc("""
            Sub T()
            Resume Next
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaResumeStatement)
        self.assertEqual(stmt.label, 'Next')

    def test_label_with_colon(self):
        code = cleandoc("""
            Sub T()
            Cleanup:
            Exit Sub
            End Sub
        """)
        ast = self._parse(code)
        assert isinstance(ast.body[0].body[0], VbaLabelStatement)

    def test_line_number_label(self):
        code = cleandoc("""
            Sub T()
            10 x = 1
            End Sub
        """)
        ast = self._parse(code)
        self.assertTrue(len(ast.body[0].body) >= 1)

    def test_type_definition(self):
        code = cleandoc("""
            Type MyType
            x As Long
            y As String
            End Type
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaTypeDefinition)
        self.assertEqual(stmt.name, 'MyType')
        self.assertEqual(len(stmt.members), 2)

    def test_type_definition_fused_end(self):
        code = cleandoc("""
            Type MyType
            x As Long
            EndType
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaTypeDefinition)
        self.assertEqual(stmt.name, 'MyType')
        self.assertEqual(len(stmt.members), 1)

    def test_enum_definition(self):
        code = cleandoc("""
            Enum Colors
            Red = 1
            Green = 2
            Blue = 3
            End Enum
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaEnumDefinition)
        self.assertEqual(stmt.name, 'Colors')
        self.assertEqual(len(stmt.members), 3)

    def test_enum_definition_fused_end(self):
        code = cleandoc("""
            Enum Colors
            Red = 1
            EndEnum
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaEnumDefinition)
        self.assertEqual(stmt.name, 'Colors')
        self.assertEqual(len(stmt.members), 1)

    def test_declare_function(self):
        code = 'Declare Function GetTickCount Lib "kernel32" () As Long'
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaDeclareStatement)
        self.assertTrue(stmt.is_function)
        self.assertEqual(stmt.name, 'GetTickCount')

    def test_redim(self):
        code = cleandoc("""
            Sub T()
            ReDim arr(10)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertFalse(stmt.preserve)

    def test_redim_preserve(self):
        code = cleandoc("""
            Sub T()
            ReDim Preserve arr(20)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertTrue(stmt.preserve)

    def test_redim_member_access(self):
        code = cleandoc("""
            Sub T()
            ReDim obj.arr(10)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertFalse(stmt.preserve)
        self.assertEqual(stmt.declarators[0].name, 'obj.arr')
        self.assertTrue(stmt.declarators[0].is_array)

    def test_redim_me_member_access(self):
        code = cleandoc("""
            Sub T()
            ReDim Me.data(5)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertEqual(stmt.declarators[0].name, 'Me.data')
        self.assertTrue(stmt.declarators[0].is_array)

    def test_redim_with_expression(self):
        code = cleandoc("""
            Sub T()
            ReDim .items(20)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertEqual(stmt.declarators[0].name, '.items')
        self.assertTrue(stmt.declarators[0].is_array)

    def test_redim_preserve_member_access(self):
        code = cleandoc("""
            Sub T()
            ReDim Preserve obj.arr(n + 1)
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaRedimStatement)
        self.assertTrue(stmt.preserve)
        self.assertEqual(stmt.declarators[0].name, 'obj.arr')
        self.assertTrue(stmt.declarators[0].is_array)

    def test_public_sub(self):
        ast = self._parse(cleandoc("""
            Public Sub Test()
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.PUBLIC)

    def test_private_function(self):
        ast = self._parse(cleandoc("""
            Private Function Foo() As Long
            End Function
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaFunctionDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.PRIVATE)

    def test_static_sub(self):
        ast = self._parse(cleandoc("""
            Static Sub Test()
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertTrue(stmt.is_static)

    def test_optional_parameter(self):
        code = cleandoc("""
            Sub T(Optional x As Long = 0)
            End Sub
        """)
        ast = self._parse(code)
        param = ast.body[0].params[0]
        self.assertTrue(param.is_optional)
        self.assertIsNotNone(param.default)

    def test_param_byval_optional(self):
        code = cleandoc("""
            Sub T(ByVal Optional x As Long = 0)
            End Sub
        """)
        ast = self._parse(code)
        param = ast.body[0].params[0]
        self.assertTrue(param.is_optional)
        self.assertEqual(param.passing, VbaParameterPassing.BY_VAL)
        self.assertEqual(param.name, 'x')

    def test_param_byref_optional(self):
        code = cleandoc("""
            Sub T(ByRef Optional y As String)
            End Sub
        """)
        ast = self._parse(code)
        param = ast.body[0].params[0]
        self.assertTrue(param.is_optional)
        self.assertEqual(param.passing, VbaParameterPassing.BY_REF)
        self.assertEqual(param.name, 'y')

    def test_select_case_range(self):
        code = cleandoc("""
            Sub T()
            Select Case x
            Case 1 To 10
            y = "range"
            End Select
            End Sub
        """)
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
        code = cleandoc("""
            Sub T()
            Select Case x
            Case 1 To 5, 10 To 20
            y = "range"
            End Select
            End Sub
        """)
        ast = self._parse(code)
        sel = ast.body[0].body[0]
        assert isinstance(sel, VbaSelectCaseStatement)
        self.assertEqual(len(sel.cases), 1)
        self.assertEqual(len(sel.cases[0].tests), 2)
        for test_expr in sel.cases[0].tests:
            assert isinstance(test_expr, VbaRangeExpression)

    def test_select_case_comparison_bare_operator(self):
        code = cleandoc("""
            Sub T()
            Select Case x
            Case > 5
            y = "big"
            End Select
            End Sub
        """)
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
        code = cleandoc("""
            Sub T()
            Select Case x
            Case Is >= 10
            y = "big"
            End Select
            End Sub
        """)
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
        code = cleandoc("""
            Sub T()
            Select Case x
            Case Is = 3
            y = "three"
            End Select
            End Sub
        """)
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
        code = cleandoc("""
            Sub T()
            Select Case x
            Case < 0, >= 100
            y = "out"
            End Select
            End Sub
        """)
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

    def test_select_case_fused_endselect(self):
        code = cleandoc("""
            Sub T()
            Select Case x
            Case 1
            y = 1
            EndSelect
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaSelectCaseStatement)
        self.assertEqual(len(stmt.cases), 1)
        self.assertEqual(len(stmt.cases[0].body), 1)

    def test_end_statement_in_case_clause(self):
        code = cleandoc("""
            Sub T()
            Select Case x
            Case 1
            End
            End Select
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        select = sub.body[0]
        assert isinstance(select, VbaSelectCaseStatement)
        self.assertEqual(len(select.cases), 1)
        self.assertEqual(len(select.cases[0].body), 1,
            'standalone End statement must not be silently dropped before End Select')
        assert isinstance(select.cases[0].body[0], VbaEndStatement)

    def test_debug_print_comma_separator(self):
        code = cleandoc("""
            Sub T()
            Debug.Print "a", "b"
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        stmt = sub.body[0]
        assert isinstance(stmt, VbaDebugPrintStatement)
        self.assertEqual(len(stmt.arguments), 2)
        self.assertEqual(stmt.separators, [','])

    def test_attribute_does_not_corrupt_following_code(self):
        code = cleandoc("""
            Attribute VB_Name = "Module1"
            Sub T()
            x = 1
            End Sub
        """)
        ast = self._parse(code)
        sub = [n for n in ast.body if isinstance(n, VbaSubDeclaration)]
        self.assertEqual(len(sub), 1)
        self.assertEqual(len(sub[0].body), 1)

    def test_if_else_with_standalone_end(self):
        code = cleandoc("""
            If x Then
            y = 1
            Else
            End
            End If
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaIfStatement)
        self.assertEqual(len(stmt.else_body), 1)
        assert isinstance(stmt.else_body[0], VbaEndStatement)

    def test_with_dot_member_assignment(self):
        code = cleandoc("""
            Sub T()
            With obj
            .Name = "test"
            End With
            End Sub
        """)
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

    def test_exit_sub_lowercase(self):
        code = cleandoc("""
            Sub T()
            exit sub
            End Sub
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, VbaExitKind.SUB)

    def test_exit_function_uppercase(self):
        code = cleandoc("""
            Function T() As Long
            EXIT FUNCTION
            End Function
        """)
        ast = self._parse(code)
        stmt = ast.body[0].body[0]
        assert isinstance(stmt, VbaExitStatement)
        self.assertEqual(stmt.kind, VbaExitKind.FUNCTION)

    def test_dim_lowercase(self):
        ast = self._parse('dim x As Long')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.DIM)
        self.assertEqual(stmt.declarators[0].name, 'x')

    def test_public_sub_lowercase(self):
        ast = self._parse(cleandoc("""
            public Sub Foo()
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.PUBLIC)

    def test_property_get_lowercase(self):
        ast = self._parse(cleandoc("""
            Property get Foo() As Long
            End Property
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaPropertyDeclaration)
        self.assertEqual(stmt.kind, VbaPropertyKind.GET)

    def test_line_number_label_with_statement(self):
        code = cleandoc("""
            Sub T()
            10 x = 1
            End Sub
        """)
        ast = self._parse(code)
        body = ast.body[0].body
        self.assertEqual(len(body), 2)
        assert isinstance(body[0], VbaLabelStatement)
        self.assertEqual(body[0].label, '10')
        assert isinstance(body[1], VbaLetStatement)

    def test_single_line_if_implicit_goto_then(self):
        code = cleandoc("""
            Sub T()
            If x Then 100
            100 x = 1
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 1)
        goto_stmt = if_stmt.body[0]
        assert isinstance(goto_stmt, VbaGotoStatement), \
            f'expected VbaGotoStatement but got {type(goto_stmt).__name__}'
        self.assertEqual(goto_stmt.label, '100')

    def test_single_line_if_implicit_goto_else(self):
        code = cleandoc("""
            Sub T()
            If x Then y = 1 Else 200
            200 z = 2
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)
        self.assertEqual(len(if_stmt.else_body), 1)
        goto_stmt = if_stmt.else_body[0]
        assert isinstance(goto_stmt, VbaGotoStatement), \
            f'expected VbaGotoStatement but got {type(goto_stmt).__name__}'
        self.assertEqual(goto_stmt.label, '200')

    def test_single_line_if_implicit_goto_with_continuation(self):
        code = cleandoc("""
            Sub T()
            If x Then 100: y = 1
            End Sub
        """)
        ast = self._parse(code)
        if_stmt = ast.body[0].body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 2)
        goto_stmt = if_stmt.body[0]
        assert isinstance(goto_stmt, VbaGotoStatement), \
            f'expected VbaGotoStatement but got {type(goto_stmt).__name__}'
        self.assertEqual(goto_stmt.label, '100')
        assert isinstance(if_stmt.body[1], VbaLetStatement)

    def test_static_dim_in_body_lowercase(self):
        code = cleandoc("""
            Sub T()
            static x As Long
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.scope, VbaScopeModifier.STATIC)
        self.assertEqual(len(stmt.declarators), 1)
        self.assertEqual(stmt.declarators[0].name, 'x')
        self.assertEqual(stmt.declarators[0].type_name, 'Long')

    def test_single_line_if_colon_after_then(self):
        code = cleandoc("""
            Sub T()
            If True Then: MsgBox "hi"
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(sub.name, 'T')
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 1)

    def test_block_if_with_colon_after_then(self):
        code = cleandoc("""
            Sub T()
            If x Then :
            y = 1
            End If
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertFalse(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 1)

    def test_single_line_if_colon_multiple_stmts(self):
        code = cleandoc("""
            Sub T()
            If x Then: a = 1: b = 2
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertTrue(if_stmt.single_line)
        self.assertEqual(len(if_stmt.body), 2)

    def test_nested_single_line_if_else_association(self):
        code = cleandoc("""
            Sub T()
            If a Then If b Then c = 1 Else d = 2 Else e = 3
            End Sub
        """)
        ast = self._parse(code)
        outer = ast.body[0].body[0]
        assert isinstance(outer, VbaIfStatement)
        self.assertTrue(outer.single_line)
        self.assertEqual(len(outer.body), 1)
        inner = outer.body[0]
        assert isinstance(inner, VbaIfStatement), \
            f'expected nested VbaIfStatement but got {type(inner).__name__}'
        self.assertTrue(inner.single_line)
        self.assertEqual(len(inner.body), 1)
        assert isinstance(inner.body[0], VbaLetStatement)
        self.assertEqual(inner.body[0].target.name, 'c')
        self.assertEqual(len(inner.else_body), 1)
        assert isinstance(inner.else_body[0], VbaLetStatement)
        self.assertEqual(inner.else_body[0].target.name, 'd')
        self.assertEqual(len(outer.else_body), 1, 'outer Else branch must contain one statement')
        assert isinstance(outer.else_body[0], VbaLetStatement)
        self.assertEqual(outer.else_body[0].target.name, 'e')

    def test_triple_nested_single_line_if(self):
        code = cleandoc("""
            Sub T()
            If a Then If b Then If c Then x = 1 Else y = 2 Else z = 3 Else w = 4
            End Sub
        """)
        ast = self._parse(code)
        outer = ast.body[0].body[0]
        assert isinstance(outer, VbaIfStatement)
        mid = outer.body[0]
        assert isinstance(mid, VbaIfStatement)
        inner = mid.body[0]
        assert isinstance(inner, VbaIfStatement)
        self.assertEqual(inner.else_body[0].target.name, 'y')
        self.assertEqual(mid.else_body[0].target.name, 'z')
        self.assertEqual(len(outer.else_body), 1, 'outermost Else must contain one statement')
        self.assertEqual(outer.else_body[0].target.name, 'w')

    def test_dim_fixed_length_string_integer(self):
        ast = self._parse('Dim s As String * 20')
        self.assertEqual(len(ast.body), 1)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(len(stmt.declarators), 1)
        self.assertEqual(stmt.declarators[0].name, 's')
        self.assertEqual(stmt.declarators[0].type_name, 'String * 20')

    def test_dim_fixed_length_string_constant(self):
        ast = self._parse('Dim s As String * MAX_LEN')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.declarators[0].type_name, 'String * MAX_LEN')

    def test_type_member_fixed_length_string(self):
        ast = self._parse(cleandoc("""
            Type MyType
            name As String * 50
            End Type
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaTypeDefinition)
        self.assertEqual(len(stmt.members), 1)
        self.assertEqual(stmt.members[0].name, 'name')
        self.assertEqual(stmt.members[0].type_name, 'String * 50')

    def test_param_fixed_length_string(self):
        ast = self._parse(cleandoc("""
            Sub Test(s As String * 10)
            End Sub
        """))
        stmt = ast.body[0]
        assert isinstance(stmt, VbaSubDeclaration)
        self.assertEqual(len(stmt.params), 1)
        self.assertEqual(stmt.params[0].type_name, 'String * 10')

    def test_implements_simple_name(self):
        ast = self._parse('Implements IFoo')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaImplementsStatement)
        self.assertEqual(stmt.name, 'IFoo')

    def test_implements_dotted_name(self):
        ast = self._parse('Implements SomeLib.IFoo')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaImplementsStatement)
        self.assertEqual(stmt.name, 'SomeLib.IFoo')

    def test_implements_deeply_qualified_name(self):
        ast = self._parse('Implements Project.Module.IBar')
        stmt = ast.body[0]
        assert isinstance(stmt, VbaImplementsStatement)
        self.assertEqual(stmt.name, 'Project.Module.IBar')

    def test_debug_assert(self):
        code = cleandoc("""
            Sub T()
            Debug.Assert x > 0
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaDebugPrintStatement)
        self.assertEqual(stmt.method, 'Assert')
        self.assertEqual(len(stmt.arguments), 1)

    def test_dim_shared(self):
        code = cleandoc("""
            Sub T()
            Dim Shared x As Long
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaVariableDeclaration)
        self.assertEqual(stmt.declarators[0].name, 'x')
        self.assertEqual(stmt.declarators[0].type_name, 'Long')

    def test_friend_sub(self):
        code = cleandoc("""
            Friend Sub MySub()
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(sub.name, 'MySub')
        self.assertEqual(sub.scope, VbaScopeModifier.FRIEND)

    def test_byval_in_call_argument(self):
        code = cleandoc("""
            Sub T()
            Call Foo(ByVal x)
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaCallStatement)
        from refinery.lib.scripts.vba.model import VbaCallExpression
        assert isinstance(stmt.callee, VbaCallExpression)
        self.assertEqual(len(stmt.callee.arguments), 1)
        arg = stmt.callee.arguments[0]
        assert isinstance(arg, VbaByValArgument)
        assert isinstance(arg.expression, VbaIdentifier)
        self.assertEqual(arg.expression.name, 'x')

    def test_byval_in_parenthesized_call(self):
        code = cleandoc("""
            Sub T()
            x = Foo(ByVal y)
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)
        from refinery.lib.scripts.vba.model import VbaCallExpression
        assert isinstance(stmt.value, VbaCallExpression)
        self.assertEqual(len(stmt.value.arguments), 1)
        arg = stmt.value.arguments[0]
        assert isinstance(arg, VbaByValArgument)
        assert isinstance(arg.expression, VbaIdentifier)
        self.assertEqual(arg.expression.name, 'y')

    def test_byval_in_implicit_call(self):
        code = cleandoc("""
            Sub T()
            Foo ByVal x
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaExpressionStatement)
        self.assertEqual(len(stmt.arguments), 1)
        arg = stmt.arguments[0]
        assert isinstance(arg, VbaByValArgument)
        assert isinstance(arg.expression, VbaIdentifier)
        self.assertEqual(arg.expression.name, 'x')

    def test_named_argument_in_call(self):
        code = cleandoc("""
            Sub T()
            Foo bar:=42
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaExpressionStatement)
        self.assertEqual(len(stmt.arguments), 1)
        arg = stmt.arguments[0]
        assert isinstance(arg, VbaNamedArgument)
        self.assertEqual(arg.name, 'bar')
        assert isinstance(arg.expression, VbaIntegerLiteral)
        self.assertEqual(arg.expression.value, 42)

    def test_named_argument_in_parenthesized_call(self):
        code = cleandoc("""
            Sub T()
            x = Foo(bar:=42)
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)
        from refinery.lib.scripts.vba.model import VbaCallExpression
        assert isinstance(stmt.value, VbaCallExpression)
        self.assertEqual(len(stmt.value.arguments), 1)
        arg = stmt.value.arguments[0]
        assert isinstance(arg, VbaNamedArgument)
        self.assertEqual(arg.name, 'bar')

    def test_multiple_named_arguments(self):
        code = cleandoc("""
            Sub T()
            MsgBox Prompt:="Hello", Title:="Test"
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaExpressionStatement)
        self.assertEqual(len(stmt.arguments), 2)
        assert isinstance(stmt.arguments[0], VbaNamedArgument)
        self.assertEqual(stmt.arguments[0].name, 'Prompt')
        assert isinstance(stmt.arguments[1], VbaNamedArgument)
        self.assertEqual(stmt.arguments[1].name, 'Title')

    def test_open_statement_does_not_steal_subsequent_body(self):
        # Previously, the For keyword inside "Open f For Input As #1" triggered
        # the For-loop parser, which consumed subsequent statements as loop body.
        code = cleandoc("""
            Sub T()
            Open "f.txt" For Input As #1
            x = 1
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        # The sub must contain exactly two statements: the Open line and x = 1.
        # Before the fix the For-loop swallowed x = 1 and End Sub, leaving one statement.
        self.assertEqual(len(sub.body), 2,
            'Open statement must not cause the For-loop parser to consume subsequent statements')
        assert isinstance(sub.body[1], VbaLetStatement), \
            f'second statement should be x = 1, got {type(sub.body[1]).__name__}'

    def test_line_input_is_single_statement(self):
        # Previously "Line Input #1, a" was split: "Line" became a bare expression
        # statement and "Input #1, a" a second statement, with the variable lost
        # to a date-literal tokenisation of "#1, a".
        code = cleandoc("""
            Sub T()
            Line Input #1, a
            x = 1
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        # Must be exactly two statements; before the fix there were three (Line / Input / x=1).
        self.assertEqual(len(sub.body), 2,
            'Line Input must be parsed as a single statement, not split across two')

    def test_conditional_compilation_does_not_corrupt_following_code(self):
        # Conditional compilation directives (#If, #Else, #End If, #Const) start
        # with '#' followed by a keyword.  The lexer must not feed these into
        # _read_date_literal(), which would produce a malformed DATE_LITERAL token
        # and desynchronize the parser.
        code = cleandoc("""
            Sub T()
            #If VBA7 Then
            x = 1
            #Else
            x = 2
            #End If
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        # The directive lines should be silently discarded; only x = 1 and x = 2
        # should remain as statements in the Sub body.
        self.assertEqual(len(sub.body), 2,
            'Conditional compilation directives must be discarded, not emitted as expression statements')

    def test_else_if_two_word_form(self):
        # "Else If" (two words) must produce ElseIfClause, not nested If inside else_body.
        code = cleandoc("""
            Sub T()
            If x = 1 Then
            y = 1
            Else If x = 2 Then
            y = 2
            End If
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        if_stmt = sub.body[0]
        assert isinstance(if_stmt, VbaIfStatement)
        self.assertEqual(len(if_stmt.elseif_clauses), 1,
            '"Else If" must produce an ElseIfClause, not a nested If inside else_body')
        self.assertEqual(len(if_stmt.else_body), 0)

    def test_not_expression_offset(self):
        code = cleandoc("""
            Sub T()
            x = Not y
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)
        assert isinstance(stmt.value, VbaUnaryExpression)
        self.assertEqual(stmt.value.operator, 'Not')
        self.assertEqual(stmt.value.offset, code.index('Not'),
            'Not expression offset must point at the Not keyword, not the operand')

    def test_go_as_variable_name(self):
        code = cleandoc("""
            Sub T()
            go = 1
            End Sub
        """)
        ast = self._parse(code)
        sub = ast.body[0]
        assert isinstance(sub, VbaSubDeclaration)
        self.assertEqual(len(sub.body), 1,
            '"go" used as a variable name must not be silently consumed')
        stmt = sub.body[0]
        assert isinstance(stmt, VbaLetStatement)

    def test_type_member_offset(self):
        code = cleandoc("""
            Type MyType
            x As Long
            End Type
        """)
        ast = self._parse(code)
        td = ast.body[0]
        assert isinstance(td, VbaTypeDefinition)
        self.assertEqual(td.members[0].offset, code.index('x'),
            'Type member offset must point at the member name')

    def test_enum_member_offset(self):
        code = cleandoc("""
            Enum Colors
            Red = 1
            End Enum
        """)
        ast = self._parse(code)
        ed = ast.body[0]
        assert isinstance(ed, VbaEnumDefinition)
        self.assertEqual(ed.members[0].offset, code.index('Red'),
            'Enum member offset must point at the member name')

    def test_else_if_two_word_offset(self):
        code = cleandoc("""
            If a Then
            x = 1
            Else If b Then
            y = 2
            End If
        """)
        ast = self._parse(code)
        stmt = ast.body[0]
        assert isinstance(stmt, VbaIfStatement)
        self.assertEqual(len(stmt.elseif_clauses), 1)
        clause = stmt.elseif_clauses[0]
        assert isinstance(clause, VbaElseIfClause)
        self.assertEqual(clause.offset, code.index('Else If'),
            'Two-word Else If clause offset must point at Else, not If')
