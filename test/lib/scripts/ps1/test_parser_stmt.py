from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayLiteral,
    Ps1BreakStatement,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoUntilLoop,
    Ps1DoWhileLoop,
    Ps1ExitStatement,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1Pipeline,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1WhileLoop,
)


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
        self.assertIsInstance(stmt, Ps1DoWhileLoop)

    def test_do_until_loop(self):
        stmt = self._parse_stmt('do { $x-- } until ($x -eq 0)')
        self.assertIsInstance(stmt, Ps1DoUntilLoop)

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

    def test_switch_with_flags(self):
        stmt = self._parse_stmt('switch -Regex ($input) { "a*" { "matched" } }')
        self.assertIsInstance(stmt, Ps1SwitchStatement)
        self.assertTrue(stmt.regex)

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

    def test_break_with_label(self):
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
        self.assertIsInstance(stmt, Ps1DoWhileLoop)
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

    def test_dot_source_relative_path(self):
        stmt = self._parse_stmt(r'. .\script.ps1')
        self.assertIsInstance(stmt, Ps1ExpressionStatement)
        cmd = stmt.expression
        self.assertIsInstance(cmd, Ps1CommandInvocation)
        self.assertEqual(cmd.invocation_operator, '.')
        self.assertIsNotNone(cmd.name)
        self.assertIsInstance(cmd.name, Ps1StringLiteral)
        self.assertEqual(cmd.name.value, r'.\script.ps1')
