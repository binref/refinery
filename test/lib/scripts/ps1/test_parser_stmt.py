from __future__ import annotations

import inspect
import unittest

from typing import TypeVar

from test import TestBase

from refinery.lib.scripts import Block, Statement
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1Code,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoLoop,
    Ps1EnumDefinition,
    Ps1ErrorNode,
    Ps1ExitStatement,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FileRedirection,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IfStatement,
    Ps1InputRedirection,
    Ps1IntegerLiteral,
    Ps1MergingRedirection,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1RedirectionStream,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_T = TypeVar('_T')


class TestPs1ParserStatements(TestBase):

    def _parse_stmt(self, source: str):
        p = Ps1Parser(source)
        script = p.parse()
        self.assertIsInstance(script, Ps1Script)
        self.assertTrue(len(script.body) > 0)
        return script.body[0]

    def test_if_statement(self):
        stmt = self._parse_stmt('if ($x -eq 1) { $y = 2 }')
        self.assertIsInstance(stmt, Ps1IfStatement)
        self.assertEqual(len(stmt.clauses), 1)
        self.assertIsNone(stmt.else_block)

    def test_if_else(self):
        stmt = self._parse_stmt('if ($x) { 1 } else { 2 }')
        self.assertIsInstance(stmt, Ps1IfStatement)
        self.assertIsNotNone(stmt.else_block)

    def test_if_elseif_else(self):
        stmt = self._parse_stmt(
            'if ($x -eq 1) { "a" } elseif ($x -eq 2) { "b" } else { "c" }')
        self.assertIsInstance(stmt, Ps1IfStatement)
        self.assertEqual(len(stmt.clauses), 2)
        self.assertIsNotNone(stmt.else_block)

    def test_while_loop(self):
        stmt = self._parse_stmt('while ($true) { $x++ }')
        self.assertIsInstance(stmt, Ps1WhileLoop)

    def test_do_while_loop(self):
        stmt = self._parse_stmt('do { $x++ } while ($x -lt 10)')
        self.assertIsInstance(stmt, Ps1DoLoop)
        self.assertFalse(stmt.is_until)

    def test_do_until_loop(self):
        stmt = self._parse_stmt('do { $x-- } until ($x -eq 0)')
        self.assertIsInstance(stmt, Ps1DoLoop)
        self.assertTrue(stmt.is_until)

    def test_for_loop(self):
        stmt = self._parse_stmt('for ($i=0; $i -lt 10; $i++) { $x += $i }')
        self.assertIsInstance(stmt, Ps1ForLoop)
        self.assertIsNotNone(stmt.initializer)
        self.assertIsNotNone(stmt.condition)
        self.assertIsNotNone(stmt.iterator)

    def test_foreach_loop(self):
        stmt = self._parse_stmt('foreach ($item in $list) { Write-Host $item }')
        self.assertIsInstance(stmt, Ps1ForEachLoop)
        self.assertIsNotNone(stmt.variable)
        self.assertIsNotNone(stmt.iterable)

    def test_switch_statement(self):
        stmt = self._parse_stmt(
            'switch ($x) { 1 { "one" } 2 { "two" } default { "other" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertEqual(len(stmt.clauses), 3)
        self.assertIsNone(stmt.clauses[2][0])

    def test_switch_keyword_as_clause_condition(self):
        stmt = self._parse_stmt(
            'switch ($x) { return { "matched" } default { "other" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertEqual(len(stmt.clauses), 2)
        cond, _ = stmt.clauses[0]
        self.assertIsInstance(cond, Ps1StringLiteral)
        self.assertEqual(cond.value, 'return')
        self.assertIsNone(stmt.clauses[1][0])

    def test_switch_clause_condition_is_one_command_argument(self):
        """
        A clause condition is read the way a command reads its argument, so `Get-Thing` is the one
        string the clause matches. Read as an expression instead, the dash is a subtraction and the
        clause matches whatever `Get` minus `Thing` evaluates to.
        """
        stmt = self._parse_stmt('switch ($x) { Get-Thing { 1 } Set-Thing { 2 } 1+2 { 3 } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        conditions = [condition for condition, _ in stmt.clauses]
        for condition in conditions:
            self.assertIsInstance(condition, Ps1StringLiteral)
        self.assertEqual(
            [condition.value for condition in conditions], ['Get-Thing', 'Set-Thing', '1+2'])
        self.assertEqual(
            [node for node in stmt.walk() if isinstance(node, Ps1BinaryExpression)], [])

    def test_switch_clause_condition_keeps_a_wildcard_whole(self):
        stmt = self._parse_stmt('switch -Wildcard ($x) { *.exe { 1 } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertEqual(len(stmt.clauses), 1)
        condition, _ = stmt.clauses[0]
        self.assertIsInstance(condition, Ps1StringLiteral)
        self.assertEqual(condition.value, '*.exe')

    def test_switch_clause_condition_joins_comma_separated_values(self):
        stmt = self._parse_stmt('switch ($x) { 1,2 { "either" } default { "other" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertEqual(len(stmt.clauses), 2)
        condition, _ = stmt.clauses[0]
        self.assertIsInstance(condition, Ps1ArrayLiteral)
        for element in condition.elements:
            self.assertIsInstance(element, Ps1IntegerLiteral)
        self.assertEqual([element.value for element in condition.elements], [1, 2])
        self.assertIsNone(stmt.clauses[1][0])
        bodies = []
        for _, block in stmt.clauses:
            self.assertEqual(len(block.body), 1)
            statement = block.body[0]
            self.assertIsInstance(statement, Ps1ExpressionStatement)
            self.assertIsInstance(statement.expression, Ps1StringLiteral)
            bodies.append(statement.expression.value)
        self.assertEqual(bodies, ['either', 'other'])

    def test_switch_with_flags(self):
        stmt = self._parse_stmt('switch -Regex ($input) { "a*" { "matched" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertTrue(stmt.regex)

    def test_switch_file_flag_bare_path(self):
        stmt = self._parse_stmt('switch -File $path { "a" { 1 } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertTrue(stmt.file)
        self.assertIsNotNone(stmt.value)
        self.assertEqual(len(stmt.clauses), 1)

    def test_switch_file_flag_string_path(self):
        stmt = self._parse_stmt(r'switch -File C:\log.txt { "error" { 1 } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertTrue(stmt.file)
        self.assertIsNotNone(stmt.value)
        self.assertEqual(len(stmt.clauses), 1)

    def test_try_catch(self):
        stmt = self._parse_stmt('try { Get-Item } catch { Write-Error $_ }')
        self.assertIsInstance(stmt, Ps1TryCatchFinally)
        self.assertEqual(len(stmt.catch_clauses), 1)

    def test_try_catch_typed(self):
        stmt = self._parse_stmt(
            'try { $x } catch [System.IO.IOException] { "io" } catch { "other" }')
        self.assertIsInstance(stmt, Ps1TryCatchFinally)
        self.assertEqual(len(stmt.catch_clauses), 2)
        self.assertEqual(stmt.catch_clauses[0].types, ['System.IO.IOException'])

    def test_try_catch_finally(self):
        stmt = self._parse_stmt('try { $x } catch { } finally { cleanup }')
        self.assertIsInstance(stmt, Ps1TryCatchFinally)
        self.assertIsNotNone(stmt.finally_block)

    def test_trap(self):
        stmt = self._parse_stmt('trap [System.Exception] { continue }')
        self.assertIsInstance(stmt, Ps1TrapStatement)
        self.assertEqual(stmt.type_name, 'System.Exception')

    def test_function_definition(self):
        stmt = self._parse_stmt('function Get-Data { param($x) return $x }')
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        self.assertEqual(stmt.name, 'Get-Data')
        self.assertFalse(stmt.is_filter)

    def test_filter_definition(self):
        stmt = self._parse_stmt('filter Even { if ($_ % 2 -eq 0) { $_ } }')
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        self.assertTrue(stmt.is_filter)

    def test_function_scope_qualified_name(self):
        stmt = self._parse_stmt('function global:MyFunc { return 1 }')
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        self.assertEqual(stmt.name, 'global:MyFunc')

    def test_function_script_scope(self):
        stmt = self._parse_stmt('function script:Initialize { }')
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        self.assertEqual(stmt.name, 'script:Initialize')

    def test_enum_members_hold_their_values_without_spaces_around_the_equals_sign(self):
        stmt = self._parse_stmt('enum E { A=1; B=2 }')
        self.assertIsInstance(stmt, Ps1EnumDefinition)
        self.assertEqual(stmt.name, 'E')
        self.assertEqual([member.name for member in stmt.members], ['A', 'B'])
        for member in stmt.members:
            self.assertIsInstance(member.value, Ps1IntegerLiteral)
        self.assertEqual([member.value.value for member in stmt.members], [1, 2])

    def test_return_statement(self):
        stmt = self._parse_stmt('return 42')
        self.assertIsInstance(stmt, Ps1ReturnStatement)

    def test_return_empty(self):
        stmt = self._parse_stmt('return')
        self.assertIsInstance(stmt, Ps1ReturnStatement)
        self.assertIsNone(stmt.pipeline)

    def test_throw_statement(self):
        stmt = self._parse_stmt('throw "error"')
        self.assertIsInstance(stmt, Ps1ThrowStatement)

    def test_break_statement(self):
        stmt = self._parse_stmt('break')
        self.assertIsInstance(stmt, Ps1BreakStatement)

    def test_break_with_bare_label(self):
        stmt = self._parse_stmt('break outer')
        self.assertIsInstance(stmt, Ps1BreakStatement)
        self.assertIsNotNone(stmt.label)

    def test_continue_statement(self):
        stmt = self._parse_stmt('continue')
        self.assertIsInstance(stmt, Ps1ContinueStatement)

    def test_exit_statement(self):
        stmt = self._parse_stmt('exit 0')
        self.assertIsInstance(stmt, Ps1ExitStatement)

    def test_data_section(self):
        stmt = self._parse_stmt('data mydata { "test" }')
        self.assertIsInstance(stmt, Ps1DataSection)
        self.assertEqual(stmt.name, 'mydata')

    def test_data_section_supported_command(self):
        stmt = self._parse_stmt(
            'data myData -SupportedCommand ConvertFrom-StringData { "a=1" }')
        self.assertIsInstance(stmt, Ps1DataSection)
        self.assertEqual(stmt.name, 'myData')
        self.assertEqual(len(stmt.commands), 1)
        self.assertIsNotNone(stmt.body)

    def test_data_section_supported_command_list(self):
        stmt = self._parse_stmt(
            'data myData -SupportedCommand ConvertFrom-StringData, Get-Date { "a=1" }')
        self.assertIsInstance(stmt, Ps1DataSection)
        self.assertEqual(len(stmt.commands), 2)

    def test_command_invocation(self):
        stmt = self._parse_stmt('Write-Host "hello"')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        self.assertIsInstance(stmt.expression, Ps1CommandInvocation)

    def test_pipeline(self):
        stmt = self._parse_stmt('$x | Sort-Object | Select-Object -First 1')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        expr = stmt.expression
        self.assertIsInstance(expr, Ps1Pipeline)
        self.assertEqual(len(expr.elements), 3)

    def test_multiple_statements(self):
        p = Ps1Parser('$x = 1; $y = 2; $z = 3')
        script = p.parse()
        self.assertEqual(len(script.body), 3)

    def test_multiline_script(self):
        src = '$x = 1\n$y = 2\n$z = $x + $y'
        p = Ps1Parser(src)
        script = p.parse()
        self.assertEqual(len(script.body), 3)

    def test_param_block_at_script_level(self):
        src = 'param($x, $y)\n$x + $y'
        p = Ps1Parser(src)
        script = p.parse()
        self.assertIsNotNone(script.param_block)
        self.assertEqual(len(script.param_block.parameters), 2)

    def test_param_block_after_attribute_with_doubled_quotes(self):
        src = '[ValidateScript("test""quoted")] param($x)'
        p = Ps1Parser(src)
        script = p.parse()
        self.assertIsNotNone(script.param_block)
        self.assertEqual(len(script.param_block.parameters), 1)

    def test_param_block_after_attribute_with_doubled_single_quotes(self):
        src = "[ValidatePattern('it''s')] param($x)"
        p = Ps1Parser(src)
        script = p.parse()
        self.assertIsNotNone(script.param_block)
        self.assertEqual(len(script.param_block.parameters), 1)

    def test_begin_process_end_blocks(self):
        src = 'begin { $x = 0 }\nprocess { $x++ }\nend { $x }'
        p = Ps1Parser(src)
        script = p.parse()
        self.assertIsNotNone(script.begin_block)
        self.assertIsNotNone(script.process_block)
        self.assertIsNotNone(script.end_block)

    def test_function_with_named_blocks(self):
        src = '''function Process-Data {
    param($data)
    begin { $results = @() }
    process { $results += $_ }
    end { $results }
}'''
        stmt = self._parse_stmt(src)
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        self.assertIsNotNone(stmt.body.begin_block)
        self.assertIsNotNone(stmt.body.process_block)
        self.assertIsNotNone(stmt.body.end_block)

    def test_digit_starting_command_argument(self):
        stmt = self._parse_stmt('Get-Process 7z')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1StringLiteral)
        self.assertEqual(arg.value.value, '7z')

    def test_command_with_switch_parameter(self):
        stmt = self._parse_stmt('Get-ChildItem -Recurse')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertTrue(len(cmd.arguments) >= 1)

    def test_dotted_argument_after_paren_command_name(self):
        stmt = self._parse_stmt(".('New-Object') System.IO.StreamReader")
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1StringLiteral)
        self.assertEqual(arg.value.value, 'System.IO.StreamReader')

    def test_dotted_argument_bare_command(self):
        stmt = self._parse_stmt('New-Object System.IO.MemoryStream')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1StringLiteral)
        self.assertEqual(arg.value.value, 'System.IO.MemoryStream')

    def test_unary_comma_after_if_not_consumed(self):
        p = Ps1Parser('if ($true) { 1 }\n,2')
        script = p.parse()
        self.assertEqual(len(script.body), 2)
        self.assertIsInstance(script.body[0], Ps1IfStatement)
        second = script.body[1]
        self.assertIsInstance(second, Ps1ExpressionStatement)
        self.assertIsInstance(second.expression, Ps1ArrayLiteral)

    def test_labeled_while(self):
        stmt = self._parse_stmt(':outer while ($true) { break :outer }')
        self.assertIsInstance(stmt, Ps1WhileLoop)
        self.assertEqual(stmt.label, ':outer')

    def test_labeled_foreach(self):
        stmt = self._parse_stmt(':loop foreach ($x in $y) { continue :loop }')
        self.assertIsInstance(stmt, Ps1ForEachLoop)
        self.assertEqual(stmt.label, ':loop')

    def test_labeled_for(self):
        stmt = self._parse_stmt(':myloop for ($i = 0; $i -lt 10; $i++) { break :myloop }')
        self.assertIsInstance(stmt, Ps1ForLoop)
        self.assertEqual(stmt.label, ':myloop')

    def test_labeled_do_while(self):
        stmt = self._parse_stmt(':repeat do { $x++ } while ($x -lt 5)')
        self.assertIsInstance(stmt, Ps1DoLoop)
        self.assertEqual(stmt.label, ':repeat')

    def test_labeled_switch(self):
        stmt = self._parse_stmt(':sw switch ($x) { 1 { "one" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertEqual(stmt.label, ':sw')

    def test_break_with_label(self):
        stmt = self._parse_stmt('break :outer')
        self.assertIsInstance(stmt, Ps1BreakStatement)
        self.assertIsNotNone(stmt.label)
        self.assertEqual(stmt.label.value, ':outer')

    def test_continue_with_label(self):
        stmt = self._parse_stmt('continue :loop')
        self.assertIsInstance(stmt, Ps1ContinueStatement)
        self.assertIsNotNone(stmt.label)
        self.assertEqual(stmt.label.value, ':loop')

    def test_catch_comma_separated_types(self):
        stmt = self._parse_stmt(
            'try { $x } catch [System.IO.IOException],'
            ' [System.UnauthorizedAccessException] { "err" }')
        self.assertIsInstance(stmt, Ps1TryCatchFinally)
        self.assertEqual(len(stmt.catch_clauses), 1)
        self.assertEqual(stmt.catch_clauses[0].types, [
            'System.IO.IOException',
            'System.UnauthorizedAccessException',
        ])

    def test_while_without_label(self):
        stmt = self._parse_stmt('while ($true) { break }')
        self.assertIsInstance(stmt, Ps1WhileLoop)
        self.assertIsNone(stmt.label)

    def test_command_name_with_embedded_single_quotes(self):
        stmt = self._parse_stmt("N'ew-Ob'ject System.Net.WebClient")
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertIsInstance(cmd.name, Ps1StringLiteral)
        self.assertIn('ew-Ob', cmd.name.value)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1StringLiteral)
        self.assertEqual(arg.value.value, 'System.Net.WebClient')

    def test_command_name_with_embedded_double_quotes(self):
        stmt = self._parse_stmt('N"ew-Ob"ject System.Net.WebClient')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertIsInstance(cmd.name, Ps1StringLiteral)
        self.assertIn('ew-Ob', cmd.name.value)
        self.assertEqual(len(cmd.arguments), 1)

    def test_argument_with_embedded_variable(self):
        stmt = self._parse_stmt('Write-Host prefix$var')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)

    def test_command_with_inline_block_comment(self):
        stmt = self._parse_stmt('Write-Host <# pick greeting #> "hello"')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)

    def test_dot_source_relative_path(self):
        stmt = self._parse_stmt(r'. .\script.ps1')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.invocation_operator, '.')
        self.assertIsNotNone(cmd.name)
        self.assertIsInstance(cmd.name, Ps1StringLiteral)
        self.assertEqual(cmd.name.value, r'.\script.ps1')

    def test_native_command_double_dash_argument(self):
        stmt = self._parse_stmt('git --no-pager log')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 2)
        self.assertEqual(cmd.arguments[0].kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(cmd.arguments[0].value, Ps1StringLiteral)
        self.assertEqual(cmd.arguments[0].value.value, '--no-pager')
        self.assertEqual(cmd.arguments[1].kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(cmd.arguments[1].value, Ps1StringLiteral)
        self.assertEqual(cmd.arguments[1].value.value, 'log')

    def test_dotfile_command_argument(self):
        stmt = self._parse_stmt('Copy-Item .gitignore dest')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 2)
        self.assertEqual(cmd.arguments[0].kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(cmd.arguments[0].value, Ps1StringLiteral)
        self.assertEqual(cmd.arguments[0].value.value, '.gitignore')
        self.assertEqual(cmd.arguments[1].kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(cmd.arguments[1].value, Ps1StringLiteral)
        self.assertEqual(cmd.arguments[1].value.value, 'dest')

    def test_wildcard_command_argument(self):
        stmt = self._parse_stmt('Get-ChildItem *.txt')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        self.assertEqual(cmd.arguments[0].kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(cmd.arguments[0].value, Ps1StringLiteral)
        self.assertEqual(cmd.arguments[0].value.value, '*.txt')

    def test_comma_separated_command_arguments_form_array(self):
        stmt = self._parse_stmt('Write-Host 1,2,3')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1ArrayLiteral)
        self.assertEqual(len(arg.value.elements), 3)
        self.assertIsInstance(arg.value.elements[0], Ps1IntegerLiteral)
        self.assertEqual(arg.value.elements[0].value, 1)
        self.assertEqual(arg.value.elements[1].value, 2)
        self.assertEqual(arg.value.elements[2].value, 3)

    def test_comma_separated_mixed_arguments(self):
        stmt = self._parse_stmt('Write-Host 1,2 -Separator "x"')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        first_arg = cmd.arguments[0]
        self.assertIsInstance(first_arg, Ps1CommandArgument)
        self.assertEqual(first_arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(first_arg.value, Ps1ArrayLiteral)
        self.assertEqual(len(first_arg.value.elements), 2)

    def test_comma_separated_variables(self):
        stmt = self._parse_stmt('Write-Output $a,$b,$c')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertIsInstance(arg, Ps1CommandArgument)
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1ArrayLiteral)
        self.assertEqual(len(arg.value.elements), 3)
        for elem in arg.value.elements:
            self.assertIsInstance(elem, Ps1Variable)

    def test_hyphenated_command_name_as_argument(self):
        """
        `Set-Alias myAlias New-Object` must keep `New-Object` as one argument, not split it into
        `New` and `-Object`.
        """
        stmt = self._parse_stmt('Set-Alias myAlias New-Object')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 2)
        second = cmd.arguments[1]
        self.assertIsInstance(second, Ps1CommandArgument)
        self.assertEqual(second.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(second.value, Ps1StringLiteral)
        self.assertEqual(second.value.value, 'New-Object')

    def test_variable_path_argument_stays_separate(self):
        """
        A command argument that splices a variable into a path parses as one expandable string,
        keeping the variable rather than flattening it to text.
        """
        stmt = self._parse_stmt(r'SV zGK $ENV:aPpdatA\file.exe')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        has_expandable = any(
            isinstance(arg, Ps1CommandArgument)
            and isinstance(arg.value, Ps1ExpandableString)
            for arg in cmd.arguments
        )
        self.assertTrue(has_expandable)

    def test_command_with_redirection_in_parens(self):
        """
        A redirection like `2>&1` inside a parenthesized command is consumed by the parser, not left
        as stray tokens.
        """
        stmt = self._parse_stmt('(iex $d 2>&1)')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        expr = stmt.expression
        self.assertIsInstance(expr, Ps1ParenExpression)
        cmd = expr.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.name.value, 'iex')

    def test_file_redirection_output(self):
        stmt = self._parse_stmt('cmd > file.txt')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 1)
        r = cmd.redirections[0]
        self.assertIsInstance(r, Ps1FileRedirection)
        self.assertEqual(r.stream, Ps1RedirectionStream.OUTPUT)
        self.assertFalse(r.append)
        self.assertIsInstance(r.target, Ps1StringLiteral)
        self.assertEqual(r.target.value, 'file.txt')

    def test_file_redirection_append(self):
        stmt = self._parse_stmt('cmd >> file.txt')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 1)
        r = cmd.redirections[0]
        self.assertIsInstance(r, Ps1FileRedirection)
        self.assertEqual(r.stream, Ps1RedirectionStream.OUTPUT)
        self.assertTrue(r.append)

    def test_merging_redirection(self):
        stmt = self._parse_stmt('cmd 2>&1')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 1)
        r = cmd.redirections[0]
        self.assertIsInstance(r, Ps1MergingRedirection)
        self.assertEqual(r.from_stream, Ps1RedirectionStream.ERROR)
        self.assertEqual(r.to_stream, Ps1RedirectionStream.OUTPUT)

    def test_file_redirection_error_to_null(self):
        stmt = self._parse_stmt('cmd 2>$null')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 1)
        r = cmd.redirections[0]
        self.assertIsInstance(r, Ps1FileRedirection)
        self.assertEqual(r.stream, Ps1RedirectionStream.ERROR)
        self.assertFalse(r.append)
        self.assertIsInstance(r.target, Ps1Variable)
        self.assertEqual(r.target.name, 'null')

    def test_file_redirection_all_streams(self):
        stmt = self._parse_stmt('cmd *>$null')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 1)
        r = cmd.redirections[0]
        self.assertIsInstance(r, Ps1FileRedirection)
        self.assertEqual(r.stream, Ps1RedirectionStream.ALL)

    def test_mixed_redirections(self):
        stmt = self._parse_stmt('cmd 2>&1 > log.txt')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.redirections), 2)
        self.assertIsInstance(cmd.redirections[0], Ps1MergingRedirection)
        self.assertIsInstance(cmd.redirections[1], Ps1FileRedirection)

    def test_arguments_and_redirections_coexist(self):
        stmt = self._parse_stmt('Write-Host hello 2>&1')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        self.assertEqual(len(cmd.redirections), 1)
        self.assertIsInstance(cmd.redirections[0], Ps1MergingRedirection)

    def test_reserved_input_operator_is_not_an_output_redirection(self):
        """
        PowerShell 5.1 reports `The '<' operator is reserved for future use` for `echo a < b` and
        builds the command `echo a` for it. The operator denotes no write, so nothing it leaves in
        the tree may read as one.
        """
        stmt = self._parse_stmt('echo a < b')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.name.value, 'echo')
        self.assertEqual(len(cmd.arguments), 1)
        argument = cmd.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertIsInstance(argument.value, Ps1StringLiteral)
        self.assertEqual(argument.value.value, 'a')
        self.assertEqual(len(cmd.redirections), 1)
        redirection = cmd.redirections[0]
        self.assertIsInstance(redirection, Ps1InputRedirection)
        self.assertNotIsInstance(redirection, Ps1FileRedirection)

    def test_reserved_input_operator_keeps_the_output_redirection_of_its_command(self):
        """
        `Get-Content < in.txt > out.txt` is the same reserved-operator error under 5.1, and the
        command 5.1 builds for it keeps its name and its `> out.txt` write. The only file this
        script writes is out.txt.
        """
        stmt = self._parse_stmt('Get-Content < in.txt > out.txt')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.name.value, 'Get-Content')
        self.assertEqual(cmd.arguments, [])
        self.assertEqual(len(cmd.redirections), 2)
        writes = [r for r in cmd.redirections if isinstance(r, Ps1FileRedirection)]
        reads = [r for r in cmd.redirections if isinstance(r, Ps1InputRedirection)]
        self.assertEqual(len(reads), 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].stream, Ps1RedirectionStream.OUTPUT)
        self.assertFalse(writes[0].append)
        self.assertIsInstance(writes[0].target, Ps1StringLiteral)
        self.assertEqual(writes[0].target.value, 'out.txt')

    def test_input_operator_without_whitespace_stays_inside_the_argument(self):
        """
        5.1 lexes `echo a<b` as `echo` followed by the single bare word `a<b`, with no error and no
        redirection: a `<` only becomes an operator when whitespace separates it.
        """
        stmt = self._parse_stmt('echo a<b')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.name.value, 'echo')
        self.assertEqual(cmd.redirections, [])
        self.assertEqual(len(cmd.arguments), 1)
        argument = cmd.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertIsInstance(argument.value, Ps1StringLiteral)
        self.assertEqual(argument.value.value, 'a<b')

    def test_generic_arg_doubled_dquote_escape(self):
        stmt = self._parse_stmt('Write-Host prefix"abc""def"suffix')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1ExpandableString)
        dq_part = arg.value.parts[1]
        self.assertIsInstance(dq_part, Ps1StringLiteral)
        self.assertEqual(dq_part.value, 'abc"def')

    def test_generic_arg_unclosed_dquote_preserves_all_chars(self):
        stmt = self._parse_stmt('Write-Host a"bc')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(len(cmd.arguments), 1)
        arg = cmd.arguments[0]
        self.assertEqual(arg.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(arg.value, Ps1ExpandableString)
        last_part = arg.value.parts[-1]
        self.assertIsInstance(last_part, Ps1StringLiteral)
        self.assertEqual(last_part.value, 'bc')

    def test_param_block_parent_set_at_script_level(self):
        p = Ps1Parser('param($x); $x + 1')
        script = p.parse()
        self.assertIsNotNone(script.param_block)
        self.assertIs(script.param_block.parent, script)

    def test_param_block_parent_set_in_function_body(self):
        stmt = self._parse_stmt('function Foo { param($x, $y); $x + $y }')
        self.assertIsInstance(stmt, Ps1FunctionDefinition)
        body = stmt.body
        self.assertIsNotNone(body.param_block)
        self.assertIs(body.param_block.parent, body)


class TestPs1TypeLiteralOwnsItsLexerMode(TestBase):
    """
    A `catch`, a `trap` and a class declaration each read a type name at a point the lexer reaches
    in whatever mode the preceding construct left behind. A command leaves argument mode, and there
    a bare token does not end at `]`, so the type name absorbs its own closing bracket and then
    every statement after it, up to the end of the script.

    Which mode a `try` body leaves behind is decided by its *last* statement: an expression body
    leaves expression mode and the read succeeds, which is why the existing typed-catch tests never
    saw this. Every try body below therefore ends in a command, and every assertion counts the
    statements that follow the construct, since that is what a swallowed type name consumes.
    """

    @staticmethod
    def _parse(source: str) -> Ps1Script:
        return Ps1Parser(source).parse()

    def test_a_typed_catch_after_a_command_body_keeps_its_type_body_and_successor(self):
        script = self._parse(
            "try { Write-Host x } catch [System.Exception] { Start-Process calc }\n"
            "Write-Host 'keep'")
        self.assertEqual(len(script.body), 2)
        stmt = script.body[0]
        self.assertIsInstance(stmt, Ps1TryCatchFinally)
        self.assertEqual(stmt.catch_clauses[0].types, ['System.Exception'])
        self.assertEqual(len(stmt.catch_clauses[0].body.body), 1)

    def test_a_second_typed_catch_after_a_command_body_is_a_clause_of_its_own(self):
        script = self._parse('try { Get-Process } catch [A] { 1 } catch [B] { 2 }')
        self.assertEqual(len(script.body), 1)
        self.assertEqual(
            [clause.types for clause in script.body[0].catch_clauses], [['A'], ['B']])

    def test_comma_separated_types_after_a_command_body_stay_separate(self):
        script = self._parse('try { Get-Process } catch [A],[B] { 1 }')
        self.assertEqual(len(script.body), 1)
        self.assertEqual([clause.types for clause in script.body[0].catch_clauses], [['A', 'B']])

    def test_a_type_on_its_own_line_after_a_command_body_is_still_the_clause_type(self):
        script = self._parse("try { Write-Host x }\ncatch\n[A]\n{ Start-Process calc }")
        self.assertEqual(len(script.body), 1)
        self.assertEqual([clause.types for clause in script.body[0].catch_clauses], [['A']])

    def test_a_generic_type_after_a_command_body_keeps_its_inner_brackets(self):
        script = self._parse(
            'try { Get-Process } catch [System.Collections.Generic.List[int]] { 1 }')
        self.assertEqual(
            [clause.types for clause in script.body[0].catch_clauses],
            [['System.Collections.Generic.List[int]']])

    def test_a_typed_param_in_a_block_argument_keeps_the_body_around_it(self):
        """
        A block handed to the call operator is an argument, so the attribute reader is reached in
        argument mode exactly as the `catch` type reader was. The type name then swallowed the
        parameter, the body and every statement after the block.
        """
        script = self._parse("& { param([int]$x) $x }\nWrite-Host 'keep'")
        self.assertEqual(len(script.body), 2)
        block = self._only_block(script)
        self.assertIsNotNone(block.param_block)
        self.assertEqual(len(block.body), 1)

    def test_a_typed_param_in_a_dot_sourced_block_keeps_the_body_around_it(self):
        script = self._parse(". { param([string]$s) Write-Host $s }\nWrite-Host 'keep'")
        self.assertEqual(len(script.body), 2)
        self.assertEqual(len(self._only_block(script).body), 1)

    @staticmethod
    def _only_block(script: Ps1Script) -> Ps1ScriptBlock:
        blocks = [node for node in script.walk() if isinstance(node, Ps1ScriptBlock)]
        if len(blocks) != 1:
            raise AssertionError(F'expected one script block, found {len(blocks)}')
        return blocks[0]

    def test_a_trap_after_a_command_keeps_its_type_body_and_successor(self):
        script = self._parse("Write-Host a\ntrap [System.Exception] { Start-Process calc }\n$x")
        self.assertEqual(len(script.body), 3)
        stmt = script.body[1]
        self.assertIsInstance(stmt, Ps1TrapStatement)
        self.assertEqual(stmt.type_name, 'System.Exception')
        self.assertEqual(len(stmt.body.body), 1)


class TestPs1ACommandNameKeepsTheStructureItSpells(TestBase):
    """
    A command runs what its name evaluates to, so `& $(Get-Command ls)` runs the command that the
    sub-expression finds, and `dir | @{ a = 1 }` pipes into the hash literal it spells. A name that
    collapses into the bare word its opening token spells keeps neither what stands inside it nor
    the token that closes it, and the closing token is then left over where a statement should be.
    """

    def _parse(self, source: str) -> Ps1Script:
        script = Ps1Parser(source).parse()
        errors = [node.text for node in script.walk() if isinstance(node, Ps1ErrorNode)]
        self.assertEqual(errors, [], source)
        return script

    def _invoked_name(self, source: str) -> Expression:
        """
        The name of the command that the call operator in `source` invokes.
        """
        script = self._parse(source)
        self.assertEqual(len(script.body), 1)
        statement = script.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        command = statement.expression
        self.assertIsInstance(command, Ps1CommandInvocation)
        self.assertEqual(command.invocation_operator, '&')
        self.assertEqual(command.arguments, [])
        return command.name

    def test_a_sub_expression_names_the_command_it_yields(self):
        name = self._invoked_name('& $(Get-Command ls)')
        self.assertIsInstance(name, Ps1SubExpression)
        self.assertEqual(len(name.body), 1)
        statement = name.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        inner = statement.expression
        self.assertIsInstance(inner, Ps1CommandInvocation)
        self.assertIsInstance(inner.name, Ps1StringLiteral)
        self.assertEqual(inner.name.value, 'Get-Command')
        self.assertEqual(len(inner.arguments), 1)
        argument = inner.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(argument.value, Ps1StringLiteral)
        self.assertEqual(argument.value.value, 'ls')

    def test_an_array_expression_names_the_command_it_yields(self):
        name = self._invoked_name('& @(1, 2)')
        self.assertIsInstance(name, Ps1ArrayExpression)
        self.assertEqual(len(name.body), 1)
        statement = name.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        self.assertIsInstance(statement.expression, Ps1ArrayLiteral)
        elements = statement.expression.elements
        for element in elements:
            self.assertIsInstance(element, Ps1IntegerLiteral)
        self.assertEqual([element.value for element in elements], [1, 2])

    def test_a_here_string_names_the_command_it_spells(self):
        name = self._invoked_name(inspect.cleandoc("""
            & @'
            notepad
            '@
        """))
        self.assertIsInstance(name, Ps1HereString)
        self.assertEqual(name.value, 'notepad')

    def test_a_hash_literal_names_the_command_it_is_invoked_as(self):
        name = self._invoked_name('& @{ a = 1 }')
        self.assertIsInstance(name, Ps1HashLiteral)
        self.assertEqual(len(name.pairs), 1)
        key, value = name.pairs[0]
        self.assertIsInstance(key, Ps1StringLiteral)
        self.assertEqual(key.value, 'a')
        self.assertIsInstance(value, Ps1IntegerLiteral)
        self.assertEqual(value.value, 1)


class TestPs1AnElementAfterAPipeIsReadLikeTheFirstOne(TestBase):
    """
    PowerShell reads every pipeline element with the expression rule before it reads a command, not
    only the first: `dir | @{ a = 1 }` reports that an expression may come first only, and then keeps
    the hash literal it spells. Reading the elements behind a pipe as commands without exception
    names a command after every expression that reaches one.
    """

    def _elements(self, source: str) -> list:
        script = Ps1Parser(source).parse()
        self.assertEqual(len(script.body), 1)
        statement = script.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        pipeline = statement.expression
        self.assertIsInstance(pipeline, Ps1Pipeline)
        return [element.expression for element in pipeline.elements]

    def test_a_hash_literal_behind_a_pipe_stays_the_hash_literal_it_spells(self):
        first, second = self._elements('dir | @{ a = 1 }')
        self.assertIsInstance(first, Ps1CommandInvocation)
        self.assertIsInstance(second, Ps1HashLiteral)
        key, value = second.pairs[0]
        self.assertIsInstance(key, Ps1StringLiteral)
        self.assertEqual(key.value, 'a')
        self.assertIsInstance(value, Ps1IntegerLiteral)
        self.assertEqual(value.value, 1)

    def test_a_number_behind_a_pipe_stays_the_number_it_spells(self):
        first, second = self._elements('1 | 2')
        self.assertIsInstance(first, Ps1IntegerLiteral)
        self.assertIsInstance(second, Ps1IntegerLiteral)
        self.assertEqual(second.value, 2)

    def test_a_keyword_behind_a_pipe_names_the_command_it_spells(self):
        first, second = self._elements('Get-Process | ForEach-Object { $_ }')
        self.assertIsInstance(first, Ps1CommandInvocation)
        self.assertIsInstance(second, Ps1CommandInvocation)
        self.assertIsInstance(second.name, Ps1StringLiteral)
        self.assertEqual(second.name.value, 'ForEach-Object')

    def test_an_expression_behind_a_pipe_keeps_the_redirection_behind_it(self):
        script = Ps1Parser('Get-Process | $x > out.txt').parse()
        pipeline = script.body[0].expression
        self.assertIsInstance(pipeline, Ps1Pipeline)
        element = pipeline.elements[1]
        self.assertIsInstance(element.expression, Ps1Variable)
        self.assertEqual(len(element.redirections), 1)
        redirection = element.redirections[0]
        self.assertIsInstance(redirection, Ps1FileRedirection)
        self.assertEqual(redirection.stream, Ps1RedirectionStream.OUTPUT)
        self.assertIsInstance(redirection.target, Ps1StringLiteral)
        self.assertEqual(redirection.target.value, 'out.txt')


class TestPs1AnArgumentThatIsNoExpressionLeavesTheTerminator(TestBase):
    """
    `Write-Host [` prints a bracket: the argument is the word the bracket spells, and the newline or
    the semicolon behind it still ends the statement. An argument reader that keeps the terminator
    for itself reads the statement behind it as more of its own arguments, and inside a script block
    it takes the closing brace along, so the block ends where the script does.
    """

    @staticmethod
    def _parse(source: str) -> Ps1Script:
        return Ps1Parser(source).parse()

    def _command_of(self, statement: Statement) -> Ps1CommandInvocation:
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        command = statement.expression
        self.assertIsInstance(command, Ps1CommandInvocation)
        return command

    def _assertTheBracketIsTheOnlyArgument(self, statement: Statement):
        command = self._command_of(statement)
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'Write-Host')
        self.assertEqual(len(command.arguments), 1)
        argument = command.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(argument.value, Ps1StringLiteral)
        self.assertEqual(argument.value.value, '[')

    def _assertIsCommandNamed(self, statement: Statement, name: str):
        command = self._command_of(statement)
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, name)

    def _block_of(self, statement: Statement) -> Ps1ScriptBlock:
        command = self._command_of(statement)
        self.assertEqual(command.invocation_operator, '&')
        self.assertIsInstance(command.name, Ps1ScriptBlock)
        return command.name

    def test_a_newline_behind_the_bracket_ends_the_statement(self):
        script = self._parse(inspect.cleandoc("""
            Write-Host [
            Get-Date
            Write-Host 'keep'
        """))
        self.assertEqual(len(script.body), 3)
        self._assertTheBracketIsTheOnlyArgument(script.body[0])
        self._assertIsCommandNamed(script.body[1], 'Get-Date')
        self._assertIsCommandNamed(script.body[2], 'Write-Host')

    def test_a_semicolon_behind_the_bracket_ends_the_statement(self):
        script = self._parse(inspect.cleandoc("""
            Write-Host [; Get-Date
            Write-Host 'keep'
        """))
        self.assertEqual(len(script.body), 3)
        self._assertTheBracketIsTheOnlyArgument(script.body[0])
        self._assertIsCommandNamed(script.body[1], 'Get-Date')
        self._assertIsCommandNamed(script.body[2], 'Write-Host')

    def test_a_newline_behind_the_bracket_in_a_block_leaves_the_brace_to_the_block(self):
        script = self._parse(inspect.cleandoc("""
            & { Write-Host [
            Get-Date }
            Write-Host 'keep'
        """))
        self.assertEqual(len(script.body), 2)
        block = self._block_of(script.body[0])
        self.assertEqual(len(block.body), 2)
        self._assertTheBracketIsTheOnlyArgument(block.body[0])
        self._assertIsCommandNamed(block.body[1], 'Get-Date')
        self._assertIsCommandNamed(script.body[1], 'Write-Host')

    def test_a_semicolon_behind_the_bracket_in_a_block_leaves_the_brace_to_the_block(self):
        script = self._parse(inspect.cleandoc("""
            & { Write-Host [; Get-Date }
            Write-Host 'keep'
        """))
        self.assertEqual(len(script.body), 2)
        block = self._block_of(script.body[0])
        self.assertEqual(len(block.body), 2)
        self._assertTheBracketIsTheOnlyArgument(block.body[0])
        self._assertIsCommandNamed(block.body[1], 'Get-Date')
        self._assertIsCommandNamed(script.body[1], 'Write-Host')


class TestPs1ACommaOpeningAnArgumentLeavesTheCommandWhole(TestBase):
    """
    A comma cannot open an argument: 5.1 reports `Missing argument in parameter list` for
    `Start-Process -ArgumentList ,$a -Wait`, and the tree it recovers is still the one command,
    holding `-ArgumentList`, `$a` and `-Wait`. The comma is dropped and nothing behind it is lost,
    and `Invoke-Command -ScriptBlock {1} -ArgumentList ,$arr` recovers the same way.

    A reader that gives up the rest of the command at the comma deletes an invocation and the
    script block it carries, which is everything such a script does.
    """

    def _command(self, source: str) -> Ps1CommandInvocation:
        script = Ps1Parser(source).parse()
        self.assertEqual(len(script.body), 1, source)
        statement = script.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        command = statement.expression
        self.assertIsInstance(command, Ps1CommandInvocation)
        return command

    def _switch(self, argument: Ps1CommandArgument | Expression, name: str):
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.SWITCH)
        self.assertEqual(argument.name, name)

    def _positional(self, argument: Ps1CommandArgument | Expression) -> Expression:
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(argument.value, Expression)
        return argument.value

    def test_a_comma_before_an_argument_keeps_the_switch_behind_it(self):
        command = self._command('Start-Process -ArgumentList ,$a -Wait')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'Start-Process')
        self.assertEqual(len(command.arguments), 3)
        listed, value, wait = command.arguments
        self._switch(listed, '-ArgumentList')
        variable = self._positional(value)
        self.assertIsInstance(variable, Ps1Variable)
        self.assertEqual(variable.name, 'a')
        self._switch(wait, '-Wait')

    def test_a_comma_before_the_last_argument_keeps_the_script_block_of_the_command(self):
        command = self._command('Invoke-Command -ScriptBlock {1} -ArgumentList ,$arr')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'Invoke-Command')
        self.assertEqual(len(command.arguments), 4)
        scriptblock, block, listed, value = command.arguments
        self._switch(scriptblock, '-ScriptBlock')
        body = self._positional(block)
        self.assertIsInstance(body, Ps1ScriptBlock)
        self.assertEqual(len(body.body), 1)
        statement = body.body[0]
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        self.assertIsInstance(statement.expression, Ps1IntegerLiteral)
        self.assertEqual(statement.expression.value, 1)
        self._switch(listed, '-ArgumentList')
        variable = self._positional(value)
        self.assertIsInstance(variable, Ps1Variable)
        self.assertEqual(variable.name, 'arr')

    def test_the_comma_is_all_that_the_recovered_command_loses(self):
        """
        The recovered tree is the tree of the same command written without the comma: the elements
        are asserted by shape rather than by identity, because a comma that survives as an element
        of its own also reads as one command and would pass a count of the elements alone.
        """
        def shape(source: str):
            command = self._command(source)
            self.assertIsInstance(command.name, Ps1StringLiteral)
            elements = [command.name.value]
            for argument in command.arguments:
                if isinstance(argument, Ps1CommandArgument):
                    elements.append((argument.kind, argument.name, type(argument.value).__name__))
                else:
                    elements.append(type(argument).__name__)
            return elements
        self.assertEqual(
            shape('Start-Process -ArgumentList ,$a -Wait'),
            shape('Start-Process -ArgumentList $a -Wait'),
        )
        self.assertEqual(
            shape('Invoke-Command -ScriptBlock {1} -ArgumentList ,$arr'),
            shape('Invoke-Command -ScriptBlock {1} -ArgumentList $arr'),
        )


_ON_THE_NEXT_LINE = inspect.cleandoc("""
    Get-Date
    BODY
""")

_AFTER_A_PIPELINE = inspect.cleandoc("""
    Get-Date | Out-Null
    BODY
""")

_AFTER_AN_ASSIGNMENT = inspect.cleandoc("""
    $a = 1
    BODY
""")

_STATEMENT_POSITIONS = {
    'at the start of the script'         : 'BODY',
    'after a semicolon'                  : 'Get-Date; BODY',
    'on the next line'                   : _ON_THE_NEXT_LINE,
    'after a pipeline'                   : _AFTER_A_PIPELINE,
    'after an assignment'                : _AFTER_AN_ASSIGNMENT,
    'in a script block'                  : '& { BODY }',
    'in a dot sourced block'             : '. { BODY }',
    'in a script block argument'         : 'Invoke-Command -ScriptBlock { BODY }',
    'in a pipeline block argument'       : '1,2 | ForEach-Object { BODY }',
    'in an assigned block'               : '$sb = { BODY }',
    'in a function body'                 : 'function Invoke-Thing { BODY }',
    'in a parameterized function body'   : 'function Invoke-Thing($a) { BODY }',
    'in a parameterized filter body'     : 'filter Select-Thing($a) { BODY }',
    'in a class method body'             : 'class Thing { [void] Run() { BODY } }',
    'in a parameterized class method'    : 'class Thing { [void] Run($a) { BODY } }',
    'in an if body'                      : 'if ($true) { BODY }',
    # The measured row spells this condition `Test-Path .`, which the parser reads as two statements
    # of which the second dot sources its own successor. That defect is a command argument's and not
    # a statement start's, so the condition here is one that reaches the body it is here to place.
    'in an if body after a command test' : 'if (Test-Path $p) { BODY }',
    'in an else body'                    : 'if ($false) { Get-Date } else { BODY }',
    'in a while body'                    : 'while ($true) { BODY }',
    'in a for body'                      : 'for ($i = 0; $i -lt 2; $i++) { BODY }',
    'in a foreach body'                  : 'foreach ($i in 1,2) { BODY }',
    'in a try body'                      : 'try { BODY } catch { Get-Date }',
    'in a catch body'                    : 'try { Get-Date } catch { BODY }',
    'in a finally body'                  : 'try { Get-Date } finally { BODY }',
    'in a switch case body'              : 'switch (1) { 1 { BODY } }',
    'after a param declaration'          : '& { param($p) BODY }',
    'in a block inside a block'          : '& { & { BODY } }',
    'as a later statement in a block'    : '& { Get-Date | Out-Null; BODY }',
    'as a later statement in an if body' : 'if ($true) { Get-Date | Out-Null; BODY }',
}

_PARAM_POSITIONS = {
    position: _STATEMENT_POSITIONS[position] for position in [
        'at the start of the script',
        'in a script block',
        'in a dot sourced block',
        'in a script block argument',
        'in a pipeline block argument',
        'in an assigned block',
        'in a function body',
        'in a block inside a block',
    ]
}


_KEYWORDS = [
    'begin',
    'break',
    'catch',
    'class',
    'continue',
    'data',
    'define',
    'do',
    'dynamicparam',
    'else',
    'elseif',
    'end',
    'enum',
    'exit',
    'filter',
    'finally',
    'for',
    'foreach',
    'from',
    'function',
    'hidden',
    'if',
    'in',
    'inlinescript',
    'parallel',
    'param',
    'process',
    'return',
    'sequence',
    'static',
    'switch',
    'throw',
    'trap',
    'try',
    'until',
    'using',
    'var',
    'while',
    'workflow',
]
"""
The reserved words that `about_Language_Keywords` lists for PowerShell 5.1.
"""


def _one_name_per_keyword(pattern: str) -> list[str]:
    return [pattern.format(keyword) for keyword in _KEYWORDS]


_NAMES_JOINED_BY_A_DASH = _one_name_per_keyword('{}-Object')
_NAMES_JOINED_BY_A_DOT = _one_name_per_keyword('{}.exe')
_NAMES_JOINED_BY_A_BACKSLASH = _one_name_per_keyword(R'{}\run.exe')
_NAMES_JOINED_BY_NOTHING = _one_name_per_keyword('{}er')

_KEYWORD_PREFIXED_NAMES = [
    *_NAMES_JOINED_BY_A_DASH,
    *_NAMES_JOINED_BY_A_DOT,
    *_NAMES_JOINED_BY_A_BACKSLASH,
    *_NAMES_JOINED_BY_NOTHING,
]

_MEASURED_KEYWORD_PREFIXED_NAMES = [
    'Exit-PSSession',
    'end.bat',
    'process.exe',
    'class.ps1',
    'ForEach-Object',
]


def _at_every_position(positions: dict[str, str]):
    """
    Marks a check for expansion by `_one_test_per_position` into one test per entry of `positions`.
    """
    def attach(check):
        check.positions = positions
        return check
    return attach


def _one_test_per_position(cls):
    """
    Expands every check marked by `_at_every_position` into one test method per position. A check
    that walks the table itself reports the whole table as a single result, which hides a position
    that regresses on its own behind the ones that still pass.
    """
    for name, check in list(vars(cls).items()):
        positions = getattr(check, 'positions', None)
        if positions is None:
            continue
        for position, template in positions.items():
            def test(self, check=check, template=template):
                check(self, template)
            test.__name__ = F'test_{name.removeprefix("check_")}_{position.replace(" ", "_")}'
            setattr(cls, test.__name__, test)
    return cls


@_one_test_per_position
class TestPs1EveryStatementOwnsItsLexerMode(TestBase):
    """
    PowerShell decides once per statement whether it reads a command or an expression, and it never
    inherits that decision from the statement or the construct before it: 5.1 resolves `foo=123` as
    a command whose *name* is `foo=123` and increments `$v` for `$v++`, in every position either was
    measured in. The two modes disagree about where a token ends — in argument mode `$v++` and `1+2`
    are single barewords and `-join` is a parameter name, in expression mode `foo=123` is an
    assignment — so a statement read in the wrong mode parses into a well-formed tree of the wrong
    shape rather than into an error.

    Each check therefore reads the shape the parser produced rather than comparing positions against
    one another: a parser that is wrong in the same way everywhere satisfies invariance and fails
    every check here. `_one_test_per_position` runs each check in every position a statement can
    stand in, as a test of its own.

    A command name runs to whitespace, so a name that merely begins with a keyword is a name and
    not the statement its first letters spell. The character that joins the keyword to the rest of
    the name is varied independently of the keyword, because a parser that only recognizes the
    dashed form reads `Exit-PSSession` as a command and still loses `end.bat` and `process.exe`
    entirely.

    How a body was declared does not change how it is read either: `end.bat`, `process.exe` and
    `class.ps1` are each one command in a script block, in `function f { }`, in `function f($a)`,
    in `filter f($a)` and in a class method alike, so each of those declarations is a position of
    its own here. The forms that carry a parameter list are the ones that can lose their body to
    the list.
    """

    def _statement_at(self, template: str, body: str) -> Statement:
        """
        The statement that `body` becomes once it is substituted into `template`.
        """
        source = template.replace('BODY', body)
        script = Ps1Parser(source).parse()
        errors = [node.text for node in script.walk() if isinstance(node, Ps1ErrorNode)]
        self.assertEqual(errors, [], source)
        start = template.index('BODY')
        end = start + len(body)
        for node in script.walk_in_order():
            if not isinstance(node, (Block, Ps1Code)):
                continue
            for statement in node.body:
                # Statements are visited outermost first, and the scaffolding around the body starts
                # before it, so the first statement inside the substituted span is the body's own.
                if start <= statement.offset <= end:
                    return statement
        raise AssertionError(F'{body} is no statement of its own in {source}')

    def _expression_at(self, template: str, body: str) -> Expression:
        statement = self._statement_at(template, body)
        self.assertIsInstance(statement, Ps1ExpressionStatement)
        return statement.expression

    def _command_at(self, template: str, body: str) -> Ps1CommandInvocation:
        expression = self._expression_at(template, body)
        self.assertIsInstance(expression, Ps1CommandInvocation)
        return expression

    def _command_name_at(self, template: str, body: str) -> str:
        command = self._command_at(template, body)
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.invocation_operator, '')
        return command.name.value

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_postfix_increment_is_an_increment(self, template: str):
        expr = self._expression_at(template, '$v++')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '++')
        self.assertFalse(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_postfix_decrement_is_a_decrement(self, template: str):
        expr = self._expression_at(template, '$v--')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '--')
        self.assertFalse(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_prefix_decrement_is_a_decrement(self, template: str):
        expr = self._expression_at(template, '--$v')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '--')
        self.assertTrue(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_an_exclamation_mark_is_a_negation(self, template: str):
        expr = self._expression_at(template, '!$v')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '!')
        self.assertTrue(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_leading_not_is_a_negation(self, template: str):
        expr = self._expression_at(template, '-not $v')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-not')
        self.assertTrue(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_leading_dash_operator_is_an_operator(self, template: str):
        expr = self._expression_at(template, '-join $v')
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '-join')
        self.assertTrue(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_leading_sum_is_an_addition(self, template: str):
        expr = self._expression_at(template, '1+2')
        self.assertIsInstance(expr, Ps1BinaryExpression)
        self.assertEqual(expr.operator, '+')
        self.assertIsInstance(expr.left, Ps1IntegerLiteral)
        self.assertEqual(expr.left.value, 1)
        self.assertIsInstance(expr.right, Ps1IntegerLiteral)
        self.assertEqual(expr.right.value, 2)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_an_equals_sign_belongs_to_the_command_name(self, template: str):
        command = self._command_at(template, 'foo=123')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'foo=123')
        self.assertEqual(command.invocation_operator, '')
        self.assertEqual(command.arguments, [])

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_command_name_holding_an_equals_sign_still_takes_an_argument(self, template: str):
        command = self._command_at(template, 'foo=123 bar')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'foo=123')
        self.assertEqual(len(command.arguments), 1)
        argument = command.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(argument.value, Ps1StringLiteral)
        self.assertEqual(argument.value.value, 'bar')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_plus_sign_belongs_to_the_command_name(self, template: str):
        self.assertEqual(self._command_name_at(template, 'foo+123'), 'foo+123')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_an_unspaced_dash_belongs_to_the_command_name(self, template: str):
        self.assertEqual(self._command_name_at(template, 'foo-bar'), 'foo-bar')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_spaced_dash_starts_a_switch_instead(self, template: str):
        command = self._command_at(template, 'foo -bar')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, 'foo')
        self.assertEqual(len(command.arguments), 1)
        argument = command.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.SWITCH)
        self.assertEqual(argument.name, '-bar')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_an_absolute_path_is_one_command_name(self, template: str):
        self.assertEqual(self._command_name_at(template, r'C:\x\y.exe'), r'C:\x\y.exe')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_relative_path_is_a_command_of_its_own_and_not_a_dot_source(self, template: str):
        self.assertEqual(self._command_name_at(template, r'.\a.ps1'), r'.\a.ps1')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_dot_apart_from_its_target_is_a_dot_source(self, template: str):
        command = self._command_at(template, r'. .\a.ps1')
        self.assertEqual(command.invocation_operator, '.')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, r'.\a.ps1')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_foreach_alias_takes_a_block_as_an_argument(self, template: str):
        command = self._command_at(template, '% { $_ }')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, '%')
        self.assertEqual(len(command.arguments), 1)
        argument = command.arguments[0]
        self.assertIsInstance(argument, Ps1CommandArgument)
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(argument.value, Ps1ScriptBlock)
        self.assertEqual(len(argument.value.body), 1)
        inner = argument.value.body[0]
        self.assertIsInstance(inner, Ps1ExpressionStatement)
        self.assertIsInstance(inner.expression, Ps1Variable)
        self.assertEqual(inner.expression.name, '_')

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_foreach_alias_keeps_its_switch_beside_the_block(self, template: str):
        command = self._command_at(template, '% -Begin { 1 }')
        self.assertIsInstance(command.name, Ps1StringLiteral)
        self.assertEqual(command.name.value, '%')
        self.assertEqual(len(command.arguments), 2)
        switch, block = command.arguments
        self.assertIsInstance(switch, Ps1CommandArgument)
        self.assertEqual(switch.kind, Ps1CommandArgumentKind.SWITCH)
        self.assertEqual(switch.name, '-Begin')
        self.assertIsInstance(block, Ps1CommandArgument)
        self.assertEqual(block.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertIsInstance(block.value, Ps1ScriptBlock)
        self.assertEqual(len(block.value.body), 1)
        inner = block.value.body[0]
        self.assertIsInstance(inner, Ps1ExpressionStatement)
        self.assertIsInstance(inner.expression, Ps1IntegerLiteral)
        self.assertEqual(inner.expression.value, 1)

    def _assertEveryNameIsOneBareCommand(self, template: str, names: list[str]):
        for name in names:
            with self.subTest(name=name):
                command = self._command_at(template, name)
                self.assertIsInstance(command.name, Ps1StringLiteral)
                self.assertEqual(command.name.value, name)
                self.assertEqual(command.invocation_operator, '')
                self.assertEqual(command.arguments, [])

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_keyword_joined_to_a_name_by_a_dash_is_a_command_name(self, template: str):
        self._assertEveryNameIsOneBareCommand(template, _NAMES_JOINED_BY_A_DASH)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_keyword_joined_to_a_name_by_a_dot_is_a_command_name(self, template: str):
        self._assertEveryNameIsOneBareCommand(template, _NAMES_JOINED_BY_A_DOT)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_keyword_joined_to_a_name_by_a_backslash_is_a_command_name(self, template: str):
        self._assertEveryNameIsOneBareCommand(template, _NAMES_JOINED_BY_A_BACKSLASH)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_keyword_joined_to_a_name_by_nothing_is_a_command_name(self, template: str):
        self._assertEveryNameIsOneBareCommand(template, _NAMES_JOINED_BY_NOTHING)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_measured_keyword_prefixed_name_is_a_command_name(self, template: str):
        self._assertEveryNameIsOneBareCommand(template, _MEASURED_KEYWORD_PREFIXED_NAMES)

    @_at_every_position(_STATEMENT_POSITIONS)
    def check_a_keyword_prefixed_name_heads_the_command_the_block_belongs_to(self, template: str):
        for name in _KEYWORD_PREFIXED_NAMES:
            with self.subTest(name=name):
                command = self._command_at(template, F'{name} {{ $_ }}')
                self.assertIsInstance(command.name, Ps1StringLiteral)
                self.assertEqual(command.name.value, name)
                self.assertEqual(command.invocation_operator, '')
                self.assertEqual(len(command.arguments), 1)
                argument = command.arguments[0]
                self.assertIsInstance(argument, Ps1CommandArgument)
                self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
                self.assertIsInstance(argument.value, Ps1ScriptBlock)

    @_at_every_position(_PARAM_POSITIONS)
    def check_a_typed_parameter_declaration_leaves_the_body_in_expression_mode(self, template: str):
        code = self._statement_at(template, 'param([int]$v) $v++').parent
        self.assertIsInstance(code, Ps1Code)
        self.assertIsNotNone(code.param_block)
        self.assertEqual(len(code.param_block.parameters), 1)
        declaration = code.param_block.parameters[0]
        self.assertEqual(len(declaration.attributes), 1)
        self.assertIsInstance(declaration.attributes[0], Ps1TypeExpression)
        self.assertEqual(declaration.attributes[0].name, 'int')
        self.assertEqual(declaration.variable.name, 'v')
        self.assertEqual(len(code.body), 1)
        expr = code.body[0].expression
        self.assertIsInstance(expr, Ps1UnaryExpression)
        self.assertEqual(expr.operator, '++')
        self.assertFalse(expr.prefix)
        self.assertIsInstance(expr.operand, Ps1Variable)
        self.assertEqual(expr.operand.name, 'v')

    def test_a_relative_path_and_a_dot_source_of_it_differ_only_in_the_invocation_operator(self):
        """
        `.\\a.ps1` runs the script in a scope of its own while `. .\\a.ps1` runs it in the caller's,
        so reading the first as a dot source invents a write to every variable the caller holds.
        """
        program = self._command_at('BODY', r'.\a.ps1')
        sourced = self._command_at('BODY', r'. .\a.ps1')
        self.assertEqual(program.invocation_operator, '')
        self.assertEqual(sourced.invocation_operator, '.')
        self.assertIsInstance(program.name, Ps1StringLiteral)
        self.assertIsInstance(sourced.name, Ps1StringLiteral)
        self.assertEqual(program.name.value, sourced.name.value)
        self.assertEqual(program.name.value, r'.\a.ps1')
        self.assertEqual(program.arguments, [])
        self.assertEqual(sourced.arguments, [])


_CONDITION_POSITIONS = {
    'in an if condition'      : 'if (NAME) { Get-Date }',
    'in an elseif condition'  : 'if ($false) { Get-Date } elseif (NAME) { Get-Date }',
    'in a while condition'    : 'while (NAME) { Get-Date }',
    'in a do while condition' : 'do { Get-Date } while (NAME)',
    'in a do until condition' : 'do { Get-Date } until (NAME)',
}


@_one_test_per_position
class TestPs1AConditionReadsACommandNameWhole(TestBase):
    """
    The parentheses of an `if`, a `while` or a `do` hold a pipeline, and a command name runs to
    whitespace there exactly as it does at a statement start, so `if (Exit-PSSession) { ... }` tests
    what that one command returns. A parser that reads the leading keyword as the statement it
    spells ends the condition at the keyword and reads the rest, the body block included, as
    something else, which leaves a script that no longer branches on what it was written to test.
    """

    def _condition_at(self, template: str, name: str) -> Expression:
        """
        The condition that `name` becomes once it is substituted into `template`. The body blocks
        are read here as well, because a condition that ends before its closing parenthesis takes
        the block behind it along, and a tree that lost its body still holds a condition to return.
        """
        source = template.replace('NAME', name)
        script = Ps1Parser(source).parse()
        errors = [node.text for node in script.walk() if isinstance(node, Ps1ErrorNode)]
        self.assertEqual(errors, [], source)
        self.assertEqual(len(script.body), 1, source)
        for block in script.walk():
            if not isinstance(block, Block):
                continue
            self.assertEqual(len(block.body), 1, source)
            statement = block.body[0]
            self.assertIsInstance(statement, Ps1ExpressionStatement, source)
            body = statement.expression
            self.assertIsInstance(body, Ps1CommandInvocation, source)
            self.assertIsInstance(body.name, Ps1StringLiteral, source)
            self.assertEqual(body.name.value, 'Get-Date', source)
        start = template.index('NAME')
        end = start + len(name)
        for node in script.walk():
            if isinstance(node, Ps1IfStatement):
                conditions = [condition for condition, _ in node.clauses]
            elif isinstance(node, (Ps1WhileLoop, Ps1DoLoop)):
                conditions = [node.condition]
            else:
                continue
            for condition in conditions:
                if condition is not None and start <= condition.offset <= end:
                    return condition
        raise AssertionError(F'{name} is no condition of its own in {source}')

    def _assertEveryNameIsOneCommandCondition(self, template: str, names: list[str]):
        for name in names:
            with self.subTest(name=name):
                condition = self._condition_at(template, name)
                self.assertIsInstance(condition, Ps1CommandInvocation)
                self.assertIsInstance(condition.name, Ps1StringLiteral)
                self.assertEqual(condition.name.value, name)
                self.assertEqual(condition.invocation_operator, '')
                self.assertEqual(condition.arguments, [])

    @_at_every_position(_CONDITION_POSITIONS)
    def check_a_keyword_prefixed_name_is_one_command(self, template: str):
        self._assertEveryNameIsOneCommandCondition(template, _KEYWORD_PREFIXED_NAMES)

    @_at_every_position(_CONDITION_POSITIONS)
    def check_a_measured_keyword_prefixed_name_is_one_command(self, template: str):
        self._assertEveryNameIsOneCommandCondition(template, _MEASURED_KEYWORD_PREFIXED_NAMES)


class TestPs1ADoubleDashIsAnArgumentAndNotAStatement(TestBase):
    """
    A `--` ends the parameters of the command it stands in and is itself the last of them. Every
    expectation below was read off a 5.1 host, which builds one command in each case and reports no
    error:

        f -- x           f | parameter -- | 'x'
        f -- -- x        f | parameter -- | '--' | 'x'
        f -- -Recurse    f | parameter -- | '-Recurse'
        f -Recurse       f | parameter -Recurse

    5.1 names that parameter `-` where we name a switch by the whole word it was written as, which
    is why `--` is the name here and `-Recurse` is the name there.

    The marker is only the space-isolated `--`: a `--` glued to a value (`$x--`, `--$x`, `f--`) is
    one word the lexer reads whole and never ends the parameters, which the boundary test below
    pins on both sides.
    """

    def _shaped(self, node: object, kind: type[_T]) -> _T:
        if not isinstance(node, kind):
            self.fail(F'expected a {kind.__name__}, not a {type(node).__name__}')
        return node

    def _arguments(self, source: str) -> list[Ps1CommandArgument]:
        script = Ps1Parser(source).parse()
        commands = [node for node in script.walk() if isinstance(node, Ps1CommandInvocation)]
        self.assertEqual(len(script.body), 1)
        self.assertEqual(len(commands), 1)
        command, = commands
        self.assertEqual(self._shaped(command.name, Ps1StringLiteral).value, 'f')
        return [self._shaped(argument, Ps1CommandArgument) for argument in command.arguments]

    def _assertIsTheWord(self, argument: Ps1CommandArgument, word: str):
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.POSITIONAL)
        self.assertEqual(self._shaped(argument.value, Ps1StringLiteral).value, word)

    def _assertEndsTheParameters(self, argument: Ps1CommandArgument):
        self.assertEqual(argument.kind, Ps1CommandArgumentKind.SWITCH)
        self.assertEqual(argument.name, '--')

    def test_a_double_dash_argument_leaves_the_command_whole(self):
        dashes, word = self._arguments('f -- x')
        self._assertEndsTheParameters(dashes)
        self._assertIsTheWord(word, 'x')

    def test_only_the_first_double_dash_ends_the_parameters(self):
        first, second, word = self._arguments('f -- -- x')
        self._assertEndsTheParameters(first)
        self._assertIsTheWord(second, '--')
        self._assertIsTheWord(word, 'x')

    def test_a_switch_behind_a_double_dash_is_a_word(self):
        dashes, recurse = self._arguments('f -- -Recurse')
        self._assertEndsTheParameters(dashes)
        self._assertIsTheWord(recurse, '-Recurse')

    def test_the_space_before_a_double_dash_is_what_makes_it_the_marker(self):
        self.assertEqual(
            [(argument.kind, argument.name) for argument in self._arguments('f $x -- y')],
            [
                (Ps1CommandArgumentKind.POSITIONAL, ''),
                (Ps1CommandArgumentKind.SWITCH, '--'),
                (Ps1CommandArgumentKind.POSITIONAL, ''),
            ],
        )
        self.assertEqual(
            [argument.kind for argument in self._arguments('f $x-- y')],
            [Ps1CommandArgumentKind.POSITIONAL, Ps1CommandArgumentKind.POSITIONAL],
        )


class TestPs1AFunctionNamedForAnAliasCharacterDoesNotSwallowTheScript(TestBase):
    """
    `function % { … }` defines the name `%`, so the statement written after it belongs to the
    script and the two are two statements, not one definition that swallows the rest. PowerShell
    5.1 takes any token that could begin a command name as the function name, refusing only its
    punctuators and unary operators; a bare `%` is not among those. No deobfuscation pass is
    involved; parsing alone does it.
    """

    def test_a_statement_after_a_percent_function_stays_in_the_script(self):
        script = Ps1Parser(inspect.cleandoc(
            """
            function % { 'b' }
            Write-Host 'AFTER'
            """
        )).parse()
        self.assertEqual(len(script.body), 2)
