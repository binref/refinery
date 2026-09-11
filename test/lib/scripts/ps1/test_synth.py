from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node, UnspellableNode
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def _written(node: Node) -> str:
    return Ps1Synthesizer().convert(node)


def _numeral(spelling: str) -> Expression:
    """
    The literal node the parser builds for a numeral written as `spelling`, taken from the one slot
    that reads a whole numeral with its sign: the right hand side of an assignment.
    """
    statement, = Ps1Parser(F'$t = {spelling}').parse().body
    assert isinstance(statement, Ps1ExpressionStatement)
    assignment = statement.expression
    assert isinstance(assignment, Ps1AssignmentExpression)
    value = assignment.value
    assert isinstance(value, Expression), spelling
    return value


def _write_output(value: Expression) -> Ps1CommandInvocation:
    """
    `Write-Output` with `value` as its one positional argument, built rather than parsed: every
    spelling this slot has to bracket is one no source can put here, because 5.1 reads each of them
    as a word instead.
    """
    return Ps1CommandInvocation(
        name=Ps1StringLiteral(value='Write-Output', raw='Write-Output'),
        arguments=[Ps1CommandArgument(value=value)],
    )


class TestPs1Synthesizer(TestBase):

    def _round_trip(self, source: str):
        synth = Ps1Synthesizer()
        ast1 = Ps1Parser(source).parse()
        out1 = synth.convert(ast1)
        ast2 = Ps1Parser(out1).parse()
        out2 = synth.convert(ast2)
        self.assertEqual(out1, out2, F'Round-trip failed:\nInput: {source!r}\nFirst: {out1!r}\nSecond: {out2!r}')
        return out1

    def test_roundtrip_assignment(self):
        self._round_trip('$x = 1 + 2')

    def test_roundtrip_if(self):
        self._round_trip('if ($x -eq 1) { $y = 2 }')

    def test_roundtrip_if_else(self):
        self._round_trip('if ($x) { 1 } else { 2 }')

    def test_roundtrip_while(self):
        self._round_trip('while ($true) { $x++ }')

    def test_roundtrip_do_while(self):
        self._round_trip('do { $x++ } while ($x -lt 10)')

    def test_roundtrip_do_until(self):
        self._round_trip('do { $x-- } until ($x -eq 0)')

    def test_roundtrip_for(self):
        self._round_trip('for ($i=0; $i -lt 10; $i++) { $x += $i }')

    def test_roundtrip_foreach(self):
        self._round_trip('foreach ($i in 1..10) { Write-Host $i }')

    def test_roundtrip_switch(self):
        self._round_trip(
            'switch ($x) { 1 { "one" } 2 { "two" } default { "other" } }')

    def test_roundtrip_try_catch(self):
        self._round_trip('try { Get-Item $p } catch { Write-Error $_ }')

    def test_roundtrip_try_catch_finally(self):
        self._round_trip(
            'try { $x } catch [System.Exception] { "err" } finally { cleanup }')

    def test_roundtrip_trap(self):
        self._round_trip('trap [System.IO.IOException] { continue }')

    def test_roundtrip_function(self):
        self._round_trip('function Get-Data { param($x) return $x }')

    def test_roundtrip_filter(self):
        self._round_trip('filter Even { if ($_ % 2 -eq 0) { $_ } }')

    def test_roundtrip_pipeline(self):
        self._round_trip('$x | Sort-Object | Select-Object -First 1')

    def test_roundtrip_command(self):
        self._round_trip('Write-Host "hello world"')

    def test_roundtrip_hash_literal(self):
        self._round_trip('@{ a = 1; b = 2 }')

    def test_roundtrip_array_expression(self):
        self._round_trip('$a = @(1, 2, 3)')

    def test_roundtrip_cast(self):
        self._round_trip('[int]$x = "42"')

    def test_roundtrip_member_access(self):
        self._round_trip('$s.Length')

    def test_roundtrip_method_call(self):
        self._round_trip('$s.ToUpper()')

    def test_roundtrip_static_call(self):
        self._round_trip('[System.Text.Encoding]::UTF8.GetBytes("test")')

    def test_roundtrip_index(self):
        self._round_trip('$arr[0]')

    def test_roundtrip_range(self):
        self._round_trip('1..10')

    def test_roundtrip_unary_not(self):
        self._round_trip('-not $x')

    def test_roundtrip_return(self):
        self._round_trip('return 42')

    def test_roundtrip_throw(self):
        self._round_trip('throw "error"')

    def test_roundtrip_break(self):
        self._round_trip('break outer')

    def test_roundtrip_exit(self):
        self._round_trip('exit 0')

    def test_roundtrip_data_section(self):
        self._round_trip('data mydata { "test" }')

    def test_roundtrip_complex_expression(self):
        self._round_trip('$result = ($a + $b) * ($c - $d)')

    def test_roundtrip_format_operator(self):
        self._round_trip('"hello {0}" -f "world"')

    def test_roundtrip_multiline(self):
        src = '$x = 1\n$y = 2\n$z = $x + $y'
        self._round_trip(src)

    def test_roundtrip_nested_if(self):
        self._round_trip(
            'if ($a) { if ($b) { 1 } else { 2 } } else { 3 }')

    def test_roundtrip_chained_methods(self):
        self._round_trip('$s.Trim().ToLower().Replace("a", "b")')

    def test_roundtrip_dotted_command_name(self):
        self._round_trip('powershell.exe -windowstyle hidden "test"')

    def test_roundtrip_nested_index(self):
        self._round_trip('$a[0][1]')

    def test_roundtrip_star_argument(self):
        self._round_trip('Get-Culture | fl -Property * | Out-String -Stream')

    def test_roundtrip_command_arg_star_simple(self):
        self._round_trip('cmd -Prop *')

    def test_roundtrip_member_chain_after_invocation(self):
        self._round_trip(
            '(. (Get-Item Variable:E).Value.InVoke("x") Net.WebClient)')

    def test_roundtrip_file_redirection(self):
        self._round_trip('cmd > file.txt')

    def test_roundtrip_file_redirection_append(self):
        self._round_trip('cmd >> file.txt')

    def test_roundtrip_merging_redirection(self):
        self._round_trip('cmd 2>&1')

    def test_roundtrip_error_to_null(self):
        self._round_trip('cmd 2>$null')

    def test_roundtrip_all_streams_to_null(self):
        self._round_trip('cmd *>$null')

    def test_roundtrip_mixed_redirections(self):
        self._round_trip('cmd 2>&1 > log.txt')

    def test_roundtrip_redirection_in_pipeline(self):
        self._round_trip('cmd 2>&1 | Out-File log.txt')

    def test_roundtrip_reserved_input_redirection(self):
        self._round_trip('Get-Content < in.txt')

    def test_roundtrip_reserved_input_redirection_with_output_redirection(self):
        self._round_trip('Get-Content < in.txt > out.txt')

    def test_unary_sign_not_glued_to_signed_operand(self):
        # `- -5` (negation of a negative literal) must not synthesize to `--5`, which would re-lex
        # as the decrement operator and change the meaning; a separating space is required.
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('- -5').parse()), '- -5')
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('+ +5').parse()), '+ +5')

    def test_a_sign_the_tree_holds_as_an_operator_is_kept_off_the_numeral(self):
        """
        `- 2147483648` is unary minus over an `Int64` literal and `-2147483648` is one `Int32`
        literal, so a sign printed against the digits behind it changes the type of what runs. The
        constructed tree is the one a pass builds when it folds a numeral into the slot a
        parenthesis or a variable used to occupy, where nothing separated the sign from it.
        """
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('- 5').parse()), '- 5')
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('+ 5').parse()), '+ 5')
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('- 5.5').parse()), '- 5.5')
        negated = Ps1UnaryExpression(
            operator='-',
            operand=Ps1IntegerLiteral(raw='2147483648'),
            prefix=True,
        )
        self.assertEqual(Ps1Synthesizer().convert(negated), '- 2147483648')

    def test_a_sign_the_numeral_itself_spells_stays_against_its_digits(self):
        # Separating this sign is the same defect in the other direction: `-2147483648` written as
        # `- 2147483648` is an Int64 where the tree held an Int32.
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('-2147483648').parse()), '-2147483648')
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('-1.5').parse()), '-1.5')

    def test_a_sign_before_something_that_is_not_a_numeral_is_written_against_it(self):
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('-$x').parse()), '-$x')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('-(2147483648)').parse()), '-(2147483648)')

    def test_a_sign_the_source_wrote_against_a_receiver_stays_against_it(self):
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('-1kb.GetType()').parse()), '-1kb.GetType()')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('-0xFF.ToString().Length').parse()),
            '-0xFF.ToString().Length')

    def test_a_sign_the_source_kept_off_a_receiver_is_not_written_against_it(self):
        """
        `- 1kb.GetType()` negates what one kilobyte answers, where `-1kb.GetType()` asks *minus* one
        kilobyte instead, and `- -1kb.GetType()` written as `--1kb.GetType()` is the decrement
        operator. The operand is a member access in each case, so what decides is the first
        character its rendering begins with rather than anything the operand node itself is.
        """
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('- 1kb.GetType()').parse()), '- 1kb.GetType()')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('+ 1kb.GetType()').parse()), '+ 1kb.GetType()')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('- -1kb.GetType()').parse()), '- -1kb.GetType()')
        negated = Ps1UnaryExpression(
            operator='-',
            operand=Ps1InvokeMember(object=Ps1RealLiteral(raw='1kb'), member='GetType'),
            prefix=True,
        )
        self.assertEqual(Ps1Synthesizer().convert(negated), '- 1kb.GetType()')

    def test_a_bracket_the_operand_needs_survives_the_sign_deciding_on_a_space(self):
        negated = Ps1UnaryExpression(
            operator='-',
            operand=Ps1BinaryExpression(
                left=Ps1IntegerLiteral(raw='1'),
                operator='+',
                right=Ps1IntegerLiteral(raw='2'),
            ),
            prefix=True,
        )
        self.assertEqual(Ps1Synthesizer().convert(negated), '-(1 + 2)')

    def test_scoped_braced_variable_keeps_braces_outside(self):
        # `${env:Path}` must re-emit with the braces around the whole `scope:name`, not as
        # `$env:{Path}`, which PowerShell parses as `$env:` followed by a `{Path}` script block.
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('${env:Path}').parse()), '${env:Path}')

    def test_drive_qualified_variable_preserves_drive(self):
        # A drive-qualified variable must keep its drive name; collapsing it to the `DRIVE` enum
        # value would emit the non-existent variable `$drive:foo`.
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('$c:foo').parse()), '$c:foo')

    def test_catch_multiple_types_comma_separated(self):
        # Multiple catch type filters must be comma-separated; a space between them is a parse error.
        out = Ps1Synthesizer().convert(Ps1Parser('try { $x } catch [A],[B] { $y }').parse())
        self.assertEqual(
            out, 'try {\n  $x\n} catch [A], [B] {\n  $y\n}')

    def test_one_element_array_keeps_the_comma_that_builds_it(self):
        # Without the leading comma the element is written on its own and is no longer an array:
        # the constructor below is then handed the buffer's bytes as separate arguments and throws.
        self.assertEqual(Ps1Synthesizer().convert(Ps1Parser('$x = ,1').parse()), '$x = ,1')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('New-Object IO.MemoryStream(,$b)').parse()),
            'New-Object IO.MemoryStream (,$b)')

    def test_attribute_keeps_its_argument_list_when_empty(self):
        # `[CmdletBinding]` without the parentheses reads back as a type constraint rather than an
        # attribute, and is then dropped; the `[int]` below is lost to the same confusion.
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('function f { [CmdletBinding()] param($x) }').parse()),
            'function f {\n  [CmdletBinding()]\n  Param($x)\n}')
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('class C { [ValidateNotNull()] [int] $P }').parse()),
            'class C {\n  [ValidateNotNull()][int]$P\n}')

    def test_a_word_that_moves_into_a_bracket_is_re_spelled(self):
        # A comma-built argument needs a bracket to stay one argument, and what stands inside a
        # bracket is read as a pipeline: 5.1 rejects `foo (a, b)` with MissingArgument and accepts
        # `foo ('a', 'b')`, so the quotes are what make the bracket legal rather than a preference.
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('foo a, b').parse()), "foo ('a', 'b')")
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('Get-Item -Path a, b').parse()),
            "Get-Item -Path ('a', 'b')")

    def test_a_word_keeps_its_spelling_in_a_slot_that_reads_one(self):
        """
        A command's name and arguments, a hash key, a redirection target, a jump label and a switch
        pattern are the slots where PowerShell reads a bare word as a value; 5.1 flags none of these
        words as a command name except the command's own. Each source is already in the
        synthesizer's own rendering, so what is asserted is that nothing is re-spelled.
        """
        for source in (
            'echo a b c',
            'Copy-Item . dest',
            'x > out.txt',
            'x < in.txt',
            '@{\n  a = 1\n}',
            ':o while ($x) {\n  break :o\n}',
            'switch ($a) {\n  foo {\n    1\n  }\n}',
        ):
            with self.subTest(source=source):
                self.assertEqual(Ps1Synthesizer().convert(Ps1Parser(source).parse()), source)

    def test_a_shape_the_language_cannot_write_is_refused(self):
        # A comma operator with nothing to build an array out of has no spelling, and an
        # empty-element array literal cannot be printed at all.
        self.assertEqual(
            Ps1Synthesizer().convert(Ps1Parser('$x = ,').parse()), '$x = ,')
        self.assertRaises(
            UnspellableNode,
            Ps1Synthesizer().convert, Ps1ArrayLiteral(elements=[]))


class TestPs1SlotsThatSwallowASpelling(TestBase):
    """
    A spelling that is legal on its own can be read as something else by the slot it lands in, and
    the synthesizer may never write one that is. Two slots do it, both measured on 5.1: a command
    argument, where a leading sign or a bracketed type name belongs to the word rather than to the
    value, and a member, static-member or index receiver, where a numeral runs on into the access
    written behind it.
    """

    def test_a_source_that_already_writes_a_legal_spelling_comes_back_unchanged(self):
        for source in (
            '-1kb.GetType()',
            '- 1kb.GetType()',
            '0xFF.GetType()',
            '1.5.GetType()',
            '1L.GetType()',
            '1e3.GetType()',
            '10d.GetType()',
            "'abc'.ToUpper()",
            'Write-Output 1',
            'Write-Output -1',
            'Write-Output 0xFF',
            'Write-Output 1kb',
            'Write-Output "abc".Length',
            'Write-Output (-1)',
            'Write-Output ([byte]5)',
        ):
            with self.subTest(source):
                self.assertEqual(_written(Ps1Parser(source).parse()), source)

    def test_a_member_receiver_is_bracketed_exactly_where_the_dot_would_join_it(self):
        """
        `3.` opens a real number, so `3.GetType()` is the one word `3.GetType` and 5.1 rejects the
        script; a numeral whose spelling has already ended keeps the dot for the member. A sign
        belongs to the numeral it is written against, which is why `-1` behaves as `1` does and
        `-1kb` as `1kb` does.
        """
        written = {
            spelling: _written(Ps1InvokeMember(object=_numeral(spelling), member='GetType'))
            for spelling in ('3', '0xFF', '1.5', '1kb', '1L', '1e3', '10d', '-1', '-1kb')
        }
        self.assertEqual(written, {
            '3'    : '(3).GetType()',
            '0xFF' : '0xFF.GetType()',
            '1.5'  : '1.5.GetType()',
            '1kb'  : '1kb.GetType()',
            '1L'   : '1L.GetType()',
            '1e3'  : '1e3.GetType()',
            '10d'  : '10d.GetType()',
            '-1'   : '(-1).GetType()',
            '-1kb' : '-1kb.GetType()',
        })

    def test_a_static_member_or_index_receiver_is_bracketed_whatever_the_numeral_is(self):
        """
        Neither a bracket nor a colon ends a numeral, so `3[0]`, `0xFF[0]` and `0xFF::MaxValue` are
        each one word on 5.1 however the numeral was spelled.
        """
        static = {
            spelling: _written(Ps1MemberAccess(
                object=_numeral(spelling),
                member='MaxValue',
                access=Ps1AccessKind.STATIC,
            ))
            for spelling in ('3', '0xFF', '1.5', '1kb')
        }
        indexed = {
            spelling: _written(Ps1IndexExpression(
                object=_numeral(spelling),
                index=Ps1IntegerLiteral(raw='0'),
            ))
            for spelling in ('3', '0xFF', '1.5', '1kb')
        }
        self.assertEqual(static, {
            '3'    : '(3)::MaxValue',
            '0xFF' : '(0xFF)::MaxValue',
            '1.5'  : '(1.5)::MaxValue',
            '1kb'  : '(1kb)::MaxValue',
        })
        self.assertEqual(indexed, {
            '3'    : '(3)[0]',
            '0xFF' : '(0xFF)[0]',
            '1.5'  : '(1.5)[0]',
            '1kb'  : '(1kb)[0]',
        })

    def test_a_bracketed_receiver_is_written_straight_against_the_access_that_reads_it(self):
        # `(3) .ToString()` is a parse error on 5.1, so the bracket a receiver needs may never
        # bring a separating space with it.
        for written in (
            _written(Ps1InvokeMember(object=_numeral('3'), member='ToString')),
            _written(Ps1MemberAccess(object=_numeral('3'), member='MaxValue')),
            _written(Ps1MemberAccess(
                object=_numeral('3'),
                member='MaxValue',
                access=Ps1AccessKind.STATIC,
            )),
            _written(Ps1IndexExpression(object=_numeral('3'), index=Ps1IntegerLiteral(raw='0'))),
        ):
            with self.subTest(written):
                self.assertEqual(written[:3], '(3)')
                self.assertEqual(' ' in written, False)

    def test_a_numeral_a_command_argument_would_read_as_a_word_is_bracketed(self):
        """
        `Write-Output 1` passes an Int32 and `Write-Output (-1)` passes an Int32, but
        `Write-Output -1` passes the String `-1`, and `+1`, `-1.5`, `-1L` and `-0.0` are words the
        same way. A positive numeral is the control that says the bracket belongs to the sign in
        this slot rather than to numerals as such.
        """
        written = {
            spelling: _written(_write_output(_numeral(spelling)))
            for spelling in ('1', '0xFF', '1kb', '10d', '1e3', '-1', '+1', '-1.5', '-1L', '-0.0')
        }
        self.assertEqual(written, {
            '1'    : 'Write-Output 1',
            '0xFF' : 'Write-Output 0xFF',
            '1kb'  : 'Write-Output 1kb',
            '10d'  : 'Write-Output 10d',
            '1e3'  : 'Write-Output 1e3',
            '-1'   : 'Write-Output (-1)',
            '+1'   : 'Write-Output (+1)',
            '-1.5' : 'Write-Output (-1.5)',
            '-1L'  : 'Write-Output (-1L)',
            '-0.0' : 'Write-Output (-0.0)',
        })

    def test_a_cast_in_a_command_argument_is_bracketed(self):
        # `f [byte]5` lexes as the single word `[byte]5` where `f ([byte]5)` is the cast, so the
        # bracket is what makes the argument the Byte the tree holds.
        cast = Ps1CastExpression(type_name='byte', operand=Ps1IntegerLiteral(raw='5'))
        self.assertEqual(_written(_write_output(cast)), 'Write-Output ([byte]5)')
        self.assertEqual(
            _written(_write_output(Ps1TypeExpression(name='byte'))), 'Write-Output ([byte])')

    def test_a_receiver_inside_a_command_argument_is_still_read_in_command_mode(self):
        """
        An argument goes on being lexed as one until something opens a new slot, so a numeral
        several levels under it is still in the argument's text. The same member access therefore
        needs a bracket in `Write-Output` that it does not need on its own.
        """
        self.assertEqual(
            _written(Ps1InvokeMember(object=_numeral('0xFF'), member='GetType')),
            '0xFF.GetType()')
        self.assertEqual(
            _written(_write_output(Ps1InvokeMember(object=_numeral('0xFF'), member='GetType'))),
            'Write-Output (0xFF).GetType()')
        self.assertEqual(
            _written(_write_output(Ps1MemberAccess(
                object=Ps1InvokeMember(object=_numeral('0xFF'), member='GetType'),
                member='FullName',
            ))),
            'Write-Output (0xFF).GetType().FullName')


class TestPs1AMemberOperatorPrintsBackAgainstTheValueItBoundTo(TestBase):
    """
    A member access, a static member access and an index print against the value they read from, and
    a member named with digits prints like any other: 5.1 reads `$x.5` as the property `5` of `$x`.
    What a source was made of can be read off the printed script, because a source read as two
    statements prints the newline that parts them where one read as a single access prints none.
    """

    def test_a_value_and_the_operator_written_against_it_come_back_as_they_were_written(self):
        for source in (
            '$x.5',
            '(1).5',
            "'a'.5",
            '@(1).5',
            '1e3.5',
            '1kb.5',
            '0xFF.5',
            '1.5.5',
            '$x[0].5',
            '$x.5.6',
            '$x::5',
            '$x[5]',
            "'a'[0]",
            '1..5',
            '$x = 1..5',
            '[int]::MaxValue',
            '[int].Name',
            'f $x.5',
            'f $x[0]',
            'f $x[-1]',
        ):
            with self.subTest(source):
                self.assertEqual(_written(Ps1Parser(source).parse()), source)

    def test_a_gap_before_the_dot_prints_two_statements_where_a_block_comment_prints_one(self):
        sources = ('$x .5', '1e3 .5', '$x <# c #>.5', '$x<# c #>.5')
        printed = {source: _written(Ps1Parser(source).parse()) for source in sources}
        self.assertEqual(printed, {
            '$x .5'        : '$x\n.5',
            '1e3 .5'       : '1e3\n.5',
            '$x <# c #>.5' : '$x\n.5',
            '$x<# c #>.5'  : '$x.5',
        })
