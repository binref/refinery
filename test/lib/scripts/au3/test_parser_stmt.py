from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.model import (
    Au3ArrayLiteral,
    Au3Assignment,
    Au3BinaryExpression,
    Au3CaseRange,
    Au3ContinueCaseStatement,
    Au3ContinueLoopStatement,
    Au3DefaultLiteral,
    Au3Directive,
    Au3DoUntilStatement,
    Au3EnumDeclaration,
    Au3ExitLoopStatement,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IfStatement,
    Au3Include,
    Au3IncludeOnce,
    Au3IntLiteral,
    Au3MemberAccess,
    Au3ReDimStatement,
    Au3ReturnStatement,
    Au3ScopeKind,
    Au3SelectCase,
    Au3SelectStatement,
    Au3StringLiteral,
    Au3SwitchCase,
    Au3SwitchStatement,
    Au3Variable,
    Au3VariableDeclaration,
    Au3WithMember,
    Au3WithStatement,
)
from refinery.lib.scripts.au3.parser import Au3Parser


class TestAu3ParserStmt(TestBase):

    def _parse(self, source: str):
        script = Au3Parser(source).parse()
        self.assertEqual(script.errors, [])
        return script

    def _one(self, source: str):
        script = self._parse(source)
        self.assertEqual(len(script.body), 1)
        return script.body[0]

    def test_if_block_with_elseif_and_else(self):
        stmt = self._one(
            'If $a Then\n'
            '    $x = 1\n'
            'ElseIf $b Then\n'
            '    $x = 2\n'
            'ElseIf $c Then\n'
            '    $x = 3\n'
            'Else\n'
            '    $x = 4\n'
            'EndIf\n'
        )
        self.assertIsInstance(stmt, Au3IfStatement)
        self.assertEqual(len(stmt.body), 1)
        self.assertEqual(len(stmt.elseifs), 2)
        self.assertEqual(stmt.elseifs[1].test.name, 'c')
        self.assertEqual(len(stmt.else_body), 1)

    def test_if_condition_is_comparison_not_assignment(self):
        stmt = self._one('If $x = 1 Then\n$y = 2\nEndIf\n')
        self.assertIsInstance(stmt, Au3IfStatement)
        self.assertEqual(stmt.test.operator, '=')
        self.assertEqual(stmt.test.left.name, 'x')
        self.assertEqual(len(stmt.body), 1)
        self.assertIsInstance(stmt.body[0].expression, Au3Assignment)

    def test_if_single_line(self):
        stmt = self._one('If $x = 1 Then $y = 2\n')
        self.assertIsInstance(stmt, Au3IfStatement)
        self.assertEqual(stmt.test.operator, '=')
        self.assertEqual(len(stmt.body), 1)
        self.assertIsInstance(stmt.body[0].expression, Au3Assignment)
        self.assertEqual(stmt.elseifs, [])
        self.assertEqual(stmt.else_body, None)

    def test_if_single_line_same_tree_as_block(self):
        single = self._one('If $x Then $y = 1\n')
        block = self._one('If $x Then\n$y = 1\nEndIf\n')
        self.assertEqual(
            [type(s) for s in single.body],
            [type(s) for s in block.body],
        )

    def test_if_case_insensitive_keywords(self):
        stmt = self._one('if 1 then\nendif\n')
        self.assertIsInstance(stmt, Au3IfStatement)

    def test_while(self):
        stmt = self._one('While $x < 10\n$x += 1\nWend\n')
        self.assertIsInstance(stmt.test, Au3BinaryExpression)
        self.assertEqual(stmt.test.operator, '<')
        self.assertIsInstance(stmt.body[0].expression, Au3Assignment)

    def test_do_until(self):
        stmt = self._one('Do\n$x += 1\nUntil $x = 10\n')
        self.assertIsInstance(stmt, Au3DoUntilStatement)
        self.assertEqual(len(stmt.body), 1)
        self.assertEqual(stmt.test.operator, '=')

    def test_for_to_step(self):
        stmt = self._one('For $i = 0 To 10 Step 2\n$s &= $i\nNext\n')
        self.assertIsInstance(stmt, Au3ForStatement)
        self.assertEqual(stmt.variable.name, 'i')
        self.assertEqual(stmt.start.value, 0)
        self.assertEqual(stmt.limit.value, 10)
        self.assertEqual(stmt.step.value, 2)

    def test_for_to_without_step(self):
        stmt = self._one('For $i = 1 To 3\nNext\n')
        self.assertIsInstance(stmt, Au3ForStatement)
        self.assertEqual(stmt.step, None)

    def test_for_in(self):
        stmt = self._one('For $x In $array\n$s &= $x\nNext\n')
        self.assertIsInstance(stmt, Au3ForInStatement)
        self.assertEqual(stmt.variable.name, 'x')
        self.assertEqual(stmt.iterable.name, 'array')

    def test_select(self):
        stmt = self._one(
            'Select\n'
            'Case $x = 1\n$a = 1\n'
            'Case $x = 2\n$a = 2\n'
            'Case Else\n$a = 0\n'
            'EndSelect\n'
        )
        self.assertIsInstance(stmt, Au3SelectStatement)
        self.assertEqual(len(stmt.cases), 3)
        self.assertIsInstance(stmt.cases[0], Au3SelectCase)
        self.assertEqual(stmt.cases[1].test.operator, '=')
        self.assertEqual(stmt.cases[2].test, None)

    def test_switch_ranges_and_comma_list(self):
        stmt = self._one(
            'Switch $x\n'
            'Case 1, 5 To 9, 20\n$a = 1\n'
            'Case Else\n$a = 0\n'
            'EndSwitch\n'
        )
        self.assertIsInstance(stmt, Au3SwitchStatement)
        case = stmt.cases[0]
        self.assertIsInstance(case, Au3SwitchCase)
        self.assertEqual(case.values[0].value, 1)
        self.assertIsInstance(case.values[1], Au3CaseRange)
        self.assertEqual(case.values[1].start.value, 5)
        self.assertEqual(case.values[1].end.value, 9)
        self.assertEqual(case.values[2].value, 20)
        self.assertEqual(stmt.cases[1].values, None)

    def test_switch_string_case(self):
        stmt = self._one('Switch $s\nCase "a"\n$a = 1\nEndSwitch\n')
        self.assertIsInstance(stmt.cases[0].values[0], Au3StringLiteral)

    def test_with(self):
        stmt = self._one('With $obj\n.prop = 1\n.other = 2\nEndWith\n')
        self.assertIsInstance(stmt, Au3WithStatement)
        self.assertIsInstance(stmt.object, Au3Variable)
        self.assertEqual(len(stmt.body), 2)
        for inner in stmt.body:
            self.assertIsInstance(inner.expression.target, Au3WithMember)

    def test_with_member_access_chain(self):
        stmt = self._one('With $obj\n.x.y = 1\nEndWith\n')
        target = stmt.body[0].expression.target
        self.assertIsInstance(target, Au3MemberAccess)
        self.assertIsInstance(target.object, Au3WithMember)

    def test_declaration_dim(self):
        stmt = self._one('Dim $x\n')
        self.assertIsInstance(stmt, Au3VariableDeclaration)
        self.assertEqual(stmt.scope, Au3ScopeKind.DIM)
        self.assertEqual(len(stmt.declarations), 1)
        self.assertEqual(stmt.declarations[0].variable.name, 'x')

    def test_declaration_local_with_initializer(self):
        stmt = self._one('Local $x = 1\n')
        self.assertEqual(stmt.scope, Au3ScopeKind.LOCAL)
        self.assertEqual(stmt.declarations[0].initializer.value, 1)

    def test_declaration_global_const(self):
        stmt = self._one('Global Const $x = 1\n')
        self.assertEqual(stmt.scope, Au3ScopeKind.GLOBAL)
        self.assertTrue(stmt.is_const)

    def test_declaration_static(self):
        stmt = self._one('Static Local $x = 1\n')
        self.assertEqual(stmt.scope, Au3ScopeKind.LOCAL)
        self.assertTrue(stmt.is_static)

    def test_declaration_multiple_declarators(self):
        stmt = self._one('Local $a = 1, $b[2], $c\n')
        self.assertEqual(len(stmt.declarations), 3)
        self.assertEqual(stmt.declarations[0].initializer.value, 1)
        self.assertEqual(len(stmt.declarations[1].dimensions), 1)
        self.assertEqual(stmt.declarations[1].dimensions[0].value, 2)
        self.assertEqual(stmt.declarations[2].initializer, None)

    def test_declaration_dimensions(self):
        stmt = self._one('Local $grid[3][4]\n')
        declarator = stmt.declarations[0]
        self.assertEqual(len(declarator.dimensions), 2)
        self.assertEqual(declarator.dimensions[0].value, 3)
        self.assertEqual(declarator.dimensions[1].value, 4)
        self.assertEqual(declarator.initializer, None)

    def test_declaration_empty_dimension(self):
        stmt = self._one('Local $a[] = [1, 2]\n')
        declarator = stmt.declarations[0]
        self.assertEqual(declarator.dimensions, [None])
        self.assertIsInstance(declarator.initializer, Au3ArrayLiteral)

    def test_declaration_dimensions_and_initializer(self):
        stmt = self._one('Local $a[2] = [3, 7]\n')
        declarator = stmt.declarations[0]
        self.assertEqual(len(declarator.dimensions), 1)
        self.assertIsInstance(declarator.initializer, Au3ArrayLiteral)

    def test_enum_default_step(self):
        stmt = self._one('Enum $a, $b, $c\n')
        self.assertIsInstance(stmt, Au3EnumDeclaration)
        self.assertEqual(stmt.step_operator, '+')
        self.assertEqual(stmt.step_value, 1)
        self.assertEqual(len(stmt.declarations), 3)
        self.assertEqual(stmt.declarations[0].initializer, None)

    def test_enum_with_initializers(self):
        stmt = self._one('Enum $a = 5, $b = $a * 2\n')
        self.assertEqual(stmt.declarations[0].initializer.value, 5)
        self.assertEqual(stmt.declarations[1].initializer.operator, '*')

    def test_enum_step_variants(self):
        for code, operator, value in (
            ('Enum Step +3 $a\n', '+', 3),
            ('Enum Step -2 $a\n', '-', 2),
            ('Enum Step *2 $a, $b\n', '*', 2),
        ):
            stmt = self._one(code)
            self.assertEqual(stmt.step_operator, operator)
            self.assertEqual(stmt.step_value, value)

    def test_enum_scope_and_const(self):
        stmt = self._one('Global Const Enum $a = 1\n')
        self.assertEqual(stmt.scope, Au3ScopeKind.GLOBAL)
        self.assertTrue(stmt.is_const)

    def test_redim(self):
        stmt = self._one('ReDim $a[10], $b[2][3]\n')
        self.assertIsInstance(stmt, Au3ReDimStatement)
        self.assertEqual(len(stmt.targets), 2)
        self.assertEqual(stmt.targets[0].dimensions[0].value, 10)
        self.assertEqual(len(stmt.targets[1].dimensions), 2)

    def test_function(self):
        stmt = self._one('Func Add($a, $b)\nReturn $a + $b\nEndFunc\n')
        self.assertIsInstance(stmt, Au3FunctionDeclaration)
        self.assertEqual(stmt.name.name, 'add')
        self.assertIsInstance(stmt.name, Au3Identifier)
        self.assertEqual(len(stmt.params), 2)
        self.assertFalse(stmt.is_volatile)
        self.assertEqual(len(stmt.body), 1)
        self.assertIsInstance(stmt.body[0], Au3ReturnStatement)

    def test_function_volatile(self):
        stmt = self._one('Volatile Func OnAutoItExit()\nEndFunc\n')
        self.assertTrue(stmt.is_volatile)

    def test_function_parameter_modifiers(self):
        stmt = self._one('Func F(ByRef $a, Const $b, $c = 1, ByRef Const $d)\nEndFunc\n')
        params = stmt.params
        self.assertTrue(params[0].by_ref)
        self.assertFalse(params[0].is_const)
        self.assertTrue(params[1].is_const)
        self.assertFalse(params[1].by_ref)
        self.assertEqual(params[2].default.value, 1)
        self.assertTrue(params[3].by_ref)
        self.assertTrue(params[3].is_const)

    def test_function_parameter_default_string(self):
        stmt = self._one("Func F($s = 'x')\nEndFunc\n")
        self.assertEqual(stmt.params[0].default.value, 'x')

    def test_return_with_and_without_value(self):
        script = self._parse('Func F()\nReturn\nReturn 1\nEndFunc\n')
        self.assertEqual(script.body[0].body[0].value, None)
        self.assertEqual(script.body[0].body[1].value.value, 1)

    def test_exit(self):
        script = self._parse('Exit\nExit 1\n')
        self.assertEqual(script.body[0].code, None)
        self.assertEqual(script.body[1].code.value, 1)

    def test_exit_loop_and_continue_loop_levels(self):
        script = self._parse('While 1\nExitLoop\nContinueLoop 2\nWend\n')
        body = script.body[0].body
        self.assertIsInstance(body[0], Au3ExitLoopStatement)
        self.assertEqual(body[0].level, None)
        self.assertIsInstance(body[1], Au3ContinueLoopStatement)
        self.assertEqual(body[1].level.value, 2)

    def test_continue_case(self):
        script = self._parse('Switch 1\nCase 1\nContinueCase\nCase 2\n$a = 1\nEndSwitch\n')
        self.assertIsInstance(script.body[0].cases[0].body[0], Au3ContinueCaseStatement)

    def test_return_default_value(self):
        script = self._parse('Func F($x = Default)\nReturn $x\nEndFunc\n')
        self.assertIsInstance(script.body[0].params[0].default, Au3DefaultLiteral)

    def test_include_library(self):
        stmt = self._one('#include <File.au3>\n')
        self.assertIsInstance(stmt, Au3Include)
        self.assertTrue(stmt.library)
        self.assertEqual(stmt.path, 'File.au3')

    def test_include_local(self):
        stmt = self._one('#include "lib\\helper.au3"\n')
        self.assertIsInstance(stmt, Au3Include)
        self.assertFalse(stmt.library)
        self.assertEqual(stmt.path, 'lib\\helper.au3')

    def test_include_once(self):
        stmt = self._one('#include-once\n')
        self.assertIsInstance(stmt, Au3IncludeOnce)

    def test_directive_passthrough(self):
        stmt = self._one('#OnAutoItStartRegister "MyStartFunc"\n')
        self.assertIsInstance(stmt, Au3Directive)
        self.assertEqual(stmt.text, '#OnAutoItStartRegister "MyStartFunc"')

    def test_directive_requireadmin(self):
        stmt = self._one('#RequireAdmin\n')
        self.assertIsInstance(stmt, Au3Directive)

    def test_leading_comment(self):
        script = self._parse('; before\n$x = 1\n')
        self.assertEqual(script.body[0].leading_comments, ['; before'])

    def test_trailing_comment(self):
        script = self._parse('$x = 1 ; after\n')
        self.assertEqual(script.body[0].trailing_comments, ['; after'])

    def test_comment_between_statements_is_leading_of_next(self):
        script = self._parse('$x = 1\n; middle\n$y = 2\n')
        self.assertEqual(script.body[0].trailing_comments, [])
        self.assertEqual(script.body[1].leading_comments, ['; middle'])

    def test_comment_after_last_statement(self):
        script = self._parse('$x = 1\n; tail\n')
        self.assertEqual(script.body[0].trailing_comments, ['; tail'])

    def test_comment_inside_function_body(self):
        script = self._parse('Func F()\n; setup\n$a = 1\nEndFunc\n')
        func = script.body[0]
        self.assertEqual(func.body[0].leading_comments, ['; setup'])

    def test_expression_statement_call(self):
        stmt = self._one('MsgBox(0, "t", "m")\n')
        self.assertEqual(stmt.expression.callee.name, 'msgbox')
        self.assertEqual(len(stmt.expression.arguments), 3)
        self.assertIsInstance(stmt.expression.arguments[0], Au3IntLiteral)
        self.assertIsInstance(stmt.expression.arguments[2], Au3StringLiteral)

    def test_nested_blocks(self):
        script = self._parse(
            'While 1\n'
            'For $i = 1 To 2\n'
            'If $i = 1 Then ContinueLoop\n'
            'Next\n'
            'Wend\n'
        )
        outer = script.body[0]
        inner = outer.body[0]
        self.assertIsInstance(inner, Au3ForStatement)
        self.assertIsInstance(inner.body[0], Au3IfStatement)
        self.assertEqual(len(inner.body[0].body), 1)

    def test_empty_script(self):
        script = self._parse('')
        self.assertEqual(script.body, [])

    def test_blank_lines_are_skipped(self):
        script = self._parse('\n\n$x = 1\n\n\n$y = 2\n\n')
        self.assertEqual(len(script.body), 2)

    def test_object_creation_in_initializer(self):
        stmt = self._one('Local $m = ObjCreate("Scripting.Dictionary")\n')
        initializer = stmt.declarations[0].initializer
        self.assertEqual(initializer.callee.name, 'objcreate')

    def test_deeply_nested_error_free(self):
        script = self._parse('Func F()\nIf 1 Then\nWhile 0\nSelect\nCase 0\n$a = 1\n'
                             'EndSelect\nWend\nEndIf\nEndFunc\n')
        self.assertEqual(script.errors, [])
        self.assertIsInstance(script.body[0], Au3FunctionDeclaration)
