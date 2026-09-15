import ntpath
import random
import re
import unittest

from inspect import getdoc

from refinery.lib.scripts.bat import BatchEmulator, BatchLexer, BatchParser, BatchState, ExecutionContext
from refinery.lib.scripts.bat.emulator import CommandFailure, Error
from refinery.lib.scripts.bat.synth import SynCommand
from refinery.lib.scripts.bat.model import AstGroup, AstPipeline, AstSequence, InvalidLabel, EmulatorException, Redirect, RedirectIO
from refinery.lib.scripts.bat.util import batchrange, batchint, u16, unquote, uncaret, enquote

from .. import TestBase


def emulate(cls):
    if code := getdoc(cls):
        code = F'{code}\n'
        return BatchEmulator(code)
    raise ValueError


def docs(cls):
    if code := getdoc(cls):
        return F'{code.strip()}\n'
    raise ValueError


class TestBatchLexer(TestBase):

    def test_whitespace_collapse_01(self):
        lexer = BatchLexer(';;;@ echo foo>,; =="==" bar')
        lexed = list(lexer.tokens(0))
        self.assertEqual(lexed, [
            ';',
            ';',
            ';',
            '@',
            ' ',
            'echo',
            ' ',
            'foo',
            RedirectIO(Redirect.OutCreate, 1, '=='),
            ' ',
        ])

    def test_whitespace_collapse_02(self):
        lexer = BatchLexer(';;;@ echo foo>,; =="==" bar\n')
        lexed = list(lexer.tokens(0))
        self.assertEqual(lexed, [
            ';',
            ';',
            ';',
            '@',
            ' ',
            'echo',
            ' ',
            'foo',
            RedirectIO(Redirect.OutCreate, 1, '=='),
            ' ',
            'bar',
            '\n',
        ])

    def test_arithmetic_if(self):
        lexer = BatchLexer('if 4 ^LE^Q s (true) else (a | b | c)', BatchState())
        lexed = list(lexer.tokens(0))
        self.assertEqual(lexed, [
            'if',
            ' ',
            '4',
            ' ',
            'LEQ',
            ' ',
            's',
            ' ',
            '(',
            'true',
            ')',
            ' ',
            'else',
            ' ',
            '(',
            'a',
            ' ',
            '|',
            ' ',
            'b',
            ' ',
            '|',
            ' ',
            'c',
            ')',
        ])

    def test_regression_set_with_escapes(self):
        @docs
        class code:
            """
            @echo off
            set ^"FOO=FIRST
            echo %FOO%
            set ^^"^BA^R=S"E"C^O^^^"N"D
            """

        lexer = BatchLexer(code, BatchState())
        lexed = lexer.tokens(0)

        self.assertEqual(next(lexed), '@')
        self.assertEqual(next(lexed), 'echo')
        self.assertEqual(next(lexed), ' ')
        self.assertEqual(next(lexed), 'off')
        self.assertEqual(next(lexed), '\n')

        self.assertEqual(next(lexed), 'set')
        lexer.parse_set()
        self.assertEqual(next(lexed), ' ')
        self.assertEqual(next(lexed), '"FOO=FIRST')
        self.assertEqual(next(lexed), '\n')

        lexer.state.environment['FOO'] = 'FIRST'
        self.assertEqual(next(lexed), 'echo')
        self.assertEqual(next(lexed), ' ')
        self.assertEqual(next(lexed), 'FIRST')
        self.assertEqual(next(lexed), '\n')

        self.assertEqual(next(lexed), 'set')
        lexer.parse_set()
        self.assertEqual(next(lexed), ' ')
        self.assertEqual(next(lexed), '^"^BA^R=S"E"C^O^^^"N"D')
        self.assertEqual(next(lexed), '\n')


class TestBatchParser(TestBase):

    def test_cannot_silence_after_redirect_happened(self):
        parser = BatchParser(';;>test.txt===@echo hi\n')
        parsed = list(parser.parse(0))
        self.assertEqual(len(parsed), 1)
        parsed = parsed[0].head
        assert isinstance(parsed, AstPipeline)
        parsed = parsed.parts[0]
        self.assertFalse(parsed.silenced)
        self.assertDictEqual(parsed.redirects, {1: RedirectIO(Redirect.OutCreate, 1, 'test.txt')})
        self.assertListEqual(parsed.fragments, ['@echo', ' ', 'hi'])

    def test_regression_group_not_identified(self):
        parser = BatchParser(';@;@@(chcp 43^7)', BatchState())
        parsed = list(parser.parse(0))
        self.assertEqual(len(parsed), 1)
        parsed = parsed[0]
        assert isinstance(parsed, AstSequence)
        assert isinstance(parsed.head, AstPipeline)
        assert isinstance(parsed.head.parts[0], AstGroup)

    def test_regression_invalid_space_character(self):
        text = 'IOLAqbKJcLfrETVUMAcXH/CNyCn09b1QMn9qaOxrwmd7hgPdD8VFEKz23KDf25DD3LWhxzQugT4'
        parser = BatchParser(text, BatchState())
        cmd, = parser.parse(0)
        self.assertEqual(str(cmd), text)

    def test_full_paths(self):
        text = r'C:\WINDOWS\system32\scrnsave.scr /s\r\n'
        parser = BatchParser(text)
        cmd, = parser.parse(0)
        syn = SynCommand(cmd.head.parts[0])
        self.assertEqual(syn.verb, r'C:\WINDOWS\system32\scrnsave.scr')

    def test_regression_set_with_escapes(self):
        @docs
        class code:
            """
            @echo off
            set ^"FOO=FIRST
            echo %FOO%
            set ^^"^BA^R=S"E"C^O^^^"N"D
            """

        parser = BatchParser(code, BatchState())
        parsed = list(parser.parse(0))
        self.assertEqual(len(parsed), 4)
        parsed = parsed[3]
        assert isinstance(parsed, AstSequence)
        assert isinstance(parsed.head, AstPipeline)

        self.assertEqual(len(parsed.tail), 0)
        self.assertEqual(len(parsed.head.parts), 1)
        self.assertEqual(len(t := parsed.head.parts[0].fragments), 3)
        self.assertEqual(t[0], 'set')
        self.assertEqual(t[1], ' ')
        self.assertEqual(t[2], '^"^BA^R=S"E"C^O^^^"N"D')


class TestBatchState(TestBase):

    def test_error_zero_is_falsy_int_but_truthy(self):
        from refinery.lib.scripts.bat.state import ErrorZero
        ez = ErrorZero.Val
        self.assertEqual(int(ez), 0)
        self.assertTrue(bool(ez))

    def test_error_zero_str(self):
        from refinery.lib.scripts.bat.state import ErrorZero
        self.assertEqual(str(ErrorZero.Val), '0')


class TestBatchEmulator(TestBase):

    def test_arithmetic_if(self):
        def _bat(s: str):
            for e in BatchEmulator(F'if {s} (true) else (false)').emulate_commands(allow_junk=True):
                return e

        self.assertEqual(_bat('"^="==^='), 'false')
        self.assertEqual(_bat('^=^===^=^='), 'true')
        self.assertEqual(_bat('A ==    A'), 'true')
        self.assertEqual(_bat('"^=="==^^=='), 'false')
        self.assertEqual(_bat('"^=="=="^=="'), 'true')

        self.assertEqual(_bat('4 ^LE^Q s'), 'true')
        self.assertEqual(_bat('a ^L^eQ s'), 'true')
        self.assertEqual(_bat('sta LEQ st'), 'false')
        self.assertEqual(_bat('4 LEQ 2+3'), 'false')
        self.assertEqual(_bat('4 LeQ 2^+3'), 'false')
        self.assertEqual(_bat('09 lEq 5'), 'true')
        self.assertEqual(_bat('0x4 LEQ 5'), 'true')
        self.assertEqual(_bat('0X4 leq 005'), 'true')

    def test_extract_text_from_help(self):
        @emulate
        class bat:
            '''
            for /F "tokens=6" %%i in ('exit /? ^| findstr label') do @set cl=%%i
            %cl% :ABORT
            echo SKIPPED
            goto :EOF
            :ABORT
            exit 0
            '''
        bat.execute()
        self.assertEqual(bat.std.o.read(), '')
        self.assertEqual(bat.state.envar('cl'), 'CALL')

    def test_file_exists(self):
        @emulate
        class bat:
            '''
            @echo off
            if exist "ex"""""i"sts" echo hi
            '''
        bat.cfg.show_nops = True
        bat.state.create_file('exists')
        self.assertListEqual(list(bat.emulate_commands()), ['@echo off', 'echo hi'])
        bat.state.remove_file('exists')
        self.assertListEqual(list(bat.emulate_commands()), ['@echo off'])

    def test_syntax_in_variables(self):
        @emulate
        class bat:
            '''
            @echo off
            set O=^>
            set A=^=
            set C=^;
            echo foo%o%%o%%a%%c%%c%%a%==test.txt
            echo bar%o%%o%%c%%a%%c%%a%==test.txt
            '''
        bat.execute()
        self.assertEqual(bat.state.ingest_file('test.txt'), 'foo\r\nbar\r\n')

    def test_groups_are_commands(self):
        @emulate
        class bat:
            '''
            (
                echo hello
                echo harry
            ) | findstr h
            '''
        self.assertListEqual(list(bat.emulate_commands()), ['echo hello', 'echo harry', 'findstr h'])
        self.assertEqual(bat.std.o.getvalue(), 'hello\x20\r\nharry\x20\r\n')

    def test_labels_can_be_variables(self):
        @emulate
        class bat:
            '''
            @echo off
            set a=FOO
            set b=BAR
            set c=OUT
            if 1==1 (
                :BAZ
                echo [%a%-%b%]
                (
                    goto %c%
                    :AGAIN
                    echo [%a%-%b%]
                    goto :%b%
                )
            )

            :OUT
            set a=BAR
            set b=BAZ
            set c=BOM
            goto :AGAIN
            :BOM
            '''
        it = (cmd[5:] for cmd in bat.emulate_commands() if cmd.startswith('echo'))
        self.assertEqual(next(it), '[FOO-BAR]')
        self.assertEqual(next(it), '[BAR-BAZ]')
        self.assertEqual(next(it), '[BAR-BAZ]')
        with self.assertRaises(StopIteration):
            next(it)

    def test_set_with_spaces(self):
        @emulate
        class bat:
            '''
            set a=hello>&2 world>&2 how>&2 are>&2 you?
            echo %a%
            '''
        self.assertListEqual(list(bat.emulate()), ['echo hello world how are you?'])

    def test_variables_in_quoted_set(self):
        @emulate
        class bat:
            '''
            setlocal enabledelayedexpansion
            set _a=FOO>nul &set _b=BAR
            set "c=%_a%!_b!
            echo %c%
            '''
        self.assertListEqual(list(bat.emulate()), [
            'setlocal enabledelayedexpansion',
            'echo FOO BAR'])

    def test_delayed_expansion_simple_01(self):
        @emulate
        class bat:
            '''
            setlocal enabledelayedexpansion
            set "a=FOO" & set b=!a!BAR & echo %a%%b%!b!T
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'FOOBAR T')
        with self.assertRaises(StopIteration):
            next(it)

    def test_delayed_expansion_simple_02(self):
        @emulate
        class bat:
            '''
            setlocal enabledelayedexpansion
            set "a=FOO" & (set b=!a!BAR) & echo %a%%b%!b!T
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'FOOBART')
        with self.assertRaises(StopIteration):
            next(it)

    def test_arithmetic_set_writes_to_stdout(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a x=12, ans=~-662*~-1152 | findstr 11
            '''
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '760811\r\n')

    def test_arithmetic_set_reads_variable_values(self):
        @emulate
        class bat:
            '''
            @echo off
            set A=10
            set B=20
            set /a C=A+B
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('C'), '30')

    def test_arithmetic_set_integer_division(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a p=7/2
            set /a q=-7/2
            set /a m=7%%3
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('p'), '3')
        self.assertEqual(bat.state.envar('q'), '-3')
        self.assertEqual(bat.state.envar('m'), '1')

    def test_arithmetic_set_compound_subtraction(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a x=10
            set /a x-=3
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('x'), '7')

    def test_arithmetic_set_quoted_expression(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a "x=1<<8"
            set /a "y=5*(3+2)"
            set /a "a=1, b=2, c=a+b"
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('x'), '256')
        self.assertEqual(bat.state.envar('y'), '25')
        self.assertEqual(bat.state.envar('c'), '3')

    def test_arithmetic_set_strips_whitespace_around_name(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a "a = 1 + 2"
            set /a "b = a * 2"
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('a'), '3')
        self.assertEqual(bat.state.envar('b'), '6')

    def test_arithmetic_set_keyword_identifiers_are_variables(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a a=True
            set /a b=False
            set /a c=None+7
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('a'), '0')
        self.assertEqual(bat.state.envar('b'), '0')
        self.assertEqual(bat.state.envar('c'), '7')

    def test_arithmetic_set_no_stdout_when_direct(self):
        direct = BatchEmulator('set /a x=7/2')
        direct.execute()
        self.assertEqual(direct.std.o.getvalue(), '')
        self.assertEqual(direct.state.envar('x'), '3')

    def test_arithmetic_set_bare_expression(self):
        direct = BatchEmulator('set /a 7/2')
        direct.execute()
        self.assertEqual(direct.std.o.getvalue(), '')

    def test_arithmetic_set_divide_by_zero(self):
        bat = BatchEmulator('set /a x=1/0')
        bat.execute()
        self.assertEqual(bat.std.e.getvalue(), 'Divide by zero error.\r\n')

    def test_arithmetic_set_malformed_expression(self):
        for expr in ('x=*', 'x=', 'x=)', 'x=1+', 'x=(1', 'x=08'):
            bat = BatchEmulator(F'set /a {expr}')
            bat.execute()
            self.assertEqual(bat.std.e.getvalue(), 'Missing operand.\r\n')
            self.assertEqual(bat.state.ec, 1073750989)

    def test_arithmetic_set_prints_in_command_line_context(self):
        bat = BatchEmulator('cmd /c set /a 2+2')
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '4\r\n')

    def test_arithmetic_set_chained_self_reference(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a "a=1, a=a+5, a=a*2"
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('a'), '12')

    def test_arithmetic_set_power_operator_unsupported(self):
        bat = BatchEmulator('set /a "x=2**3"')
        bat.execute()
        self.assertEqual(bat.std.e.getvalue(), 'Missing operand.\r\n')
        self.assertEqual(bat.state.ec, 1073750989)

    def test_arithmetic_set_oversized_shift_is_bounded(self):
        bat = BatchEmulator('set /a "x=1<<99999999"')
        bat.execute()
        self.assertEqual(bat.state.envar('x'), '0')

    def test_arithmetic_set_negative_shift_count(self):
        @emulate
        class bat:
            '''
            @echo off
            set /a "a=1<<-1"
            set /a "b=256>>-1"
            set /a "c=-8>>-1"
            '''
        bat.execute()
        self.assertEqual(bat.state.envar('a'), '0')
        self.assertEqual(bat.state.envar('b'), '0')
        self.assertEqual(bat.state.envar('c'), '-1')

    def test_arithmetic_set_rejects_non_integer_constant(self):
        for expr in ('1j', '1e500'):
            bat = BatchEmulator(F'set /a x={expr}')
            bat.execute()
            self.assertEqual(bat.std.e.getvalue(), 'Missing operand.\r\n')
            self.assertEqual(bat.state.ec, 1073750989)

    def test_substring_negative_length(self):
        @emulate
        class bat:
            '''
            set v=ABCDE
            echo %v:~2,-1%
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo CD'])

    def test_substring_empty_offset(self):
        @emulate
        class bat:
            '''
            set v=ABCDE
            echo %v:~,3%
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo ABC'])

    def test_substitution_case_insensitive(self):
        @emulate
        class bat:
            '''
            set v=HelloWorld
            echo %v:hello=Hi%
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo HiWorld'])

    def test_substitution_star_prefix(self):
        @emulate
        class bat:
            '''
            set v=abcXYZdef
            echo %v:*XYZ=_%
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo _def'])

    def test_if_equality_is_string_comparison(self):
        def _bat(s: str):
            for e in BatchEmulator(F'if {s} (true) else (false)').emulate_commands(allow_junk=True):
                return e
        self.assertEqual(_bat('01==1'), 'false')
        self.assertEqual(_bat('1==1'), 'true')
        self.assertEqual(_bat('01 EQU 1'), 'true')

    def test_if_casefold_keeps_numeric_comparison(self):
        def _bat(s: str):
            for e in BatchEmulator(F'if {s} (true) else (false)').emulate_commands(allow_junk=True):
                return e
        self.assertEqual(_bat('/i 5 GTR 10'), 'false')
        self.assertEqual(_bat('/i 9 GEQ 9'), 'true')
        self.assertEqual(_bat('/i abc EQU ABC'), 'true')

    def test_type_outputs_file_contents(self):
        @emulate
        class bat:
            '''
            type secret.txt
            '''
        bat.state.create_file('secret.txt', 'TOPSECRET')
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'TOPSECRET')

    def test_pushd_changes_directory(self):
        @emulate
        class bat:
            '''
            pushd C:\\Windows
            echo %CD%
            popd
            echo %CD%
            '''
        cmds = [c.lower() for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo c:\\windows', 'echo c:\\'])

    def test_endlocal_restores_extensions(self):
        @emulate
        class bat:
            '''
            setlocal disableextensions
            endlocal
            '''
        bat.execute()
        self.assertTrue(bat.state.cmdextended)
        self.assertEqual(len(bat.state.cmdextended_stack), 1)

    def test_findstr_wildcard_match(self):
        @emulate
        class bat:
            '''
            findstr hello *.txt
            '''
        bat.state.create_file('a.txt', 'hello world\r\n')
        bat.state.create_file('b.log', 'hello there\r\n')
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.txt:hello world\r\n')

    def test_findstr_wildcard_is_not_recursive(self):
        state = BatchState()
        state.create_file('a.txt', 'hit here\r\n')
        state.create_file('sub\\b.txt', 'hit nested\r\n')
        bat = BatchEmulator('findstr hit *.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.txt:hit here\r\n')

    def test_findstr_wildcard_match_is_case_insensitive(self):
        state = BatchState()
        state.create_file('a.txt', 'hello world\r\n')
        bat = BatchEmulator('findstr hello *.TXT\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.txt:hello world\r\n')

    def test_findstr_wildcard_match_order_is_sorted(self):
        state = BatchState()
        for name in ('mid.txt', 'aaa.txt', 'zzz.txt'):
            state.create_file(name, 'hit\r\n')
        bat = BatchEmulator('findstr hit *.txt\n', state)
        bat.execute()
        self.assertEqual(
            bat.std.o.getvalue(), 'aaa.txt:hit\r\nmid.txt:hit\r\nzzz.txt:hit\r\n')

    def _findstr(self, args: str, text: str) -> str:
        state = BatchState()
        state.create_file('in.txt', text)
        bat = BatchEmulator(F'type in.txt|findstr {args}\n', state)
        bat.execute()
        return bat.std.o.getvalue()

    def test_findstr_regex_dialect(self):
        f = self._findstr
        self.assertEqual(f('"a+"', 'aaab\r\n'), '')
        self.assertEqual(f('"a+"', 'a+b\r\n'), 'a+b\r\n')
        self.assertEqual(f('"a(b"', 'a(b\r\n'), 'a(b\r\n')
        self.assertEqual(f('"a?b"', 'ab\r\n'), '')
        self.assertEqual(f('"a|b"', 'a\r\n'), '')
        self.assertEqual(f('"a.c"', 'aXc\r\n'), 'aXc\r\n')
        self.assertEqual(f('"a.c"', 'ac\r\n'), '')
        self.assertEqual(f('"ab*c"', 'ac\r\n'), 'ac\r\n')
        self.assertEqual(f('"*x"', 'x\r\n'), '')
        self.assertEqual(f('"*x"', '*x\r\n'), '*x\r\n')
        self.assertEqual(f('"^foo"', 'foox\r\n'), 'foox\r\n')
        self.assertEqual(f('"^foo"', 'xfoo\r\n'), '')
        self.assertEqual(f('"bar$"', 'xbar\r\n'), 'xbar\r\n')
        self.assertEqual(f('"a$b"', 'a$b\r\n'), 'a$b\r\n')
        self.assertEqual(f('"[0-9]"', 'a1b\r\n'), 'a1b\r\n')

    def test_findstr_flags(self):
        f = self._findstr
        self.assertEqual(f('/I FOO', 'fOoBar\r\n'), 'fOoBar\r\n')
        self.assertEqual(f('FOO', 'fOoBar\r\n'), '')
        self.assertEqual(f('/V "a b"', 'apple\r\nbbb\r\nzzz\r\n'), 'zzz\r\n')
        self.assertEqual(f('"foo bar"', 'foo bar baz\r\n'), 'foo bar baz\r\n')
        self.assertEqual(f('/L "a.c"', 'aXc\r\n'), '')
        self.assertEqual(f('/L "a.c"', 'a.c\r\n'), 'a.c\r\n')
        self.assertEqual(f('/X foo', 'foo\r\nfoobar\r\n'), 'foo\r\n')
        self.assertEqual(f('/B foo', 'foobar\r\nxfoo\r\n'), 'foobar\r\n')
        self.assertEqual(f('/E bar', 'foobar\r\nbarx\r\n'), 'foobar\r\n')
        self.assertEqual(f('/N rr', 'apple\r\nberry\r\n'), '2:berry\r\n')

    def test_findstr_to_regex_unit(self):
        from refinery.lib.scripts.bat.util import findstr_to_regex

        def matches(pattern: str, text: str) -> bool:
            return bool(re.search(findstr_to_regex(pattern), text))
        self.assertFalse(matches('a+', 'aaab'))
        self.assertTrue(matches('a+', 'a+b'))
        self.assertTrue(matches('a(b', 'a(b'))
        self.assertFalse(matches('a?b', 'ab'))
        self.assertTrue(matches('a.c', 'aXc'))
        self.assertFalse(matches('*x', 'x'))
        self.assertTrue(matches('^foo', 'foox'))
        self.assertFalse(matches('^foo', 'xfoo'))
        self.assertTrue(matches('a$b', 'a$b'))
        self.assertTrue(matches('\\<cat\\>', 'cat scatter'))

    def test_findstr_offset_and_prefix_order(self):
        state = BatchState()
        state.create_file('a.txt', 'x\r\nfoo\r\n')
        state.create_file('b.txt', 'foo\r\n')
        bat = BatchEmulator('findstr /N /O foo a.txt b.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.txt:2:3:foo\r\nb.txt:1:0:foo\r\n')

    def test_findstr_filename_only(self):
        state = BatchState()
        state.create_file('a.txt', 'foo\r\nfoo\r\n')
        state.create_file('b.txt', 'nope\r\n')
        bat = BatchEmulator('findstr /M foo a.txt b.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.txt\r\n')

    def _find(self, args: str, text: str) -> str:
        state = BatchState()
        state.create_file('in.txt', text)
        bat = BatchEmulator(F'type in.txt|find {args}\n', state)
        bat.execute()
        return bat.std.o.getvalue()

    def test_find_stdin(self):
        f = self._find
        self.assertEqual(f('"world"', 'hello world\r\nbye\r\n'), 'hello world\r\n')
        self.assertEqual(f('"xyz"', 'hello\r\n'), '')
        self.assertEqual(f('/N "b"', 'abc\r\nxyz\r\n'), '[1]abc\r\n')
        self.assertEqual(f('/V "a"', 'apple\r\nzzz\r\n'), 'zzz\r\n')
        self.assertEqual(f('/C "a"', 'apple\r\nban\r\nzzz\r\n'), '2\r\n')
        self.assertEqual(f('/I "APPLE"', 'apple\r\n'), 'apple\r\n')
        self.assertEqual(f('"a b"', 'a b c\r\naxb\r\n'), 'a b c\r\n')

    def test_find_file_banner_and_count(self):
        state = BatchState()
        state.create_file('doc.txt', 'hello world\r\nbye\r\n')
        bat = BatchEmulator('find "world" doc.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '\r\n---------- DOC.TXT\r\nhello world\r\n')
        state = BatchState()
        state.create_file('doc.txt', 'hello\r\nworld\r\nxx\r\n')
        bat = BatchEmulator('find /C "l" doc.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '\r\n---------- DOC.TXT: 2\r\n')

    def test_for_f_reads_matching_files(self):
        @emulate
        class bat:
            '''
            @echo off
            for /f %%i in (data.txt) do echo got %%i
            '''
        bat.state.create_file('data.txt', 'AAA\r\nBBB\r\n')
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo got AAA', 'echo got BBB'])

    def test_delayed_expansion_empty(self):
        @emulate
        class bat:
            '''
            @echo off
            setlocal enabledelayedexpansion
            echo a!!b
            '''
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo ab'])

    def test_for_l_decreasing(self):
        @emulate
        class bat:
            '''
            @echo off
            for /l %%i in (5,-1,1) do echo n%%i
            '''
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo n5', 'echo n4', 'echo n3', 'echo n2', 'echo n1'])

    def test_for_l_step_overshoots_stop(self):
        @emulate
        class bat:
            '''
            @echo off
            for /l %%i in (1,2,6) do echo n%%i
            '''
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo n1', 'echo n3', 'echo n5'])

    def test_for_l_positive_step_start_after_stop(self):
        @emulate
        class bat:
            '''
            @echo off
            for /l %%i in (5,1,1) do echo n%%i
            '''
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, [])

    def test_for_f_command_substitution_reads_set_a(self):
        @emulate
        class bat:
            '''
            @echo off
            for /f %%i in ('set /a 1+1') do echo got %%i
            '''
        cmds = [c for c in bat.emulate_commands() if c.startswith('echo')]
        self.assertEqual(cmds, ['echo got 2'])

    def test_for_l_infinite_loop_detected(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('for /l %i in (1,0,5) do echo %i\n', state)
        errors = [str(s) for s in bat.trace() if isinstance(s, Error)]
        self.assertEqual(errors, ['Infinite loop detected in FOR /L loop (1,0,5)'])

    def test_goto_infinite_loop_detected(self):
        bat = BatchEmulator(':LOOP\ngoto :LOOP\n')
        errors = [str(s) for s in bat.trace() if isinstance(s, Error)]
        self.assertEqual(errors, ['Infinite loop detected for label LOOP'])

    def test_odd_error_level_after_set_01(self):
        bat = BatchEmulator('set /a||echo %ERRORLEVEL%')
        bat.execute()
        self.assertEqual(bat.std.e.getvalue(), 'The syntax of the command is incorrect.\r\n')
        self.assertEqual(bat.std.o.getvalue(), '0\r\n')

    def test_odd_error_level_after_set_02(self):
        bat = BatchEmulator('set /a ||echo %ERRORLEVEL%')
        bat.execute()
        self.assertEqual(bat.std.e.getvalue(), 'Missing operand.\r\n')
        self.assertEqual(bat.std.o.getvalue(), '0\r\n')

    def test_delayed_expansion(self):
        @emulate
        class bat:
            '''
            @echo off
            setlocal enabledelayedexpansion
            goto :A
            :B
            echo B
            set "a=FOO" & set b=!a!BAR
            echo !a!
            goto :END
            endlocal
            :A
            echo A
            goto :B
            :END
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'A')
        self.assertEqual(next(it), 'B')
        self.assertEqual(next(it), 'FOO')
        with self.assertRaises(StopIteration):
            next(it)

    def test_else_without_block(self):
        @emulate
        class bat:
            '''
            @echo off
            if 3==4 (echo hi) else echo ho
            echo hi
            '''
        it = (cmd[5:] for cmd in bat.emulate_commands() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'ho')
        self.assertEqual(next(it), 'hi')
        with self.assertRaises(StopIteration):
            next(it)

    def test_regression_set_with_escapes(self):
        parser = BatchParser('set ^^"^BA^R=S"E"C^O^^^"N"D\n', BatchState())
        parsed = list(parser.parse(0))
        parsed = parsed[0]
        assert isinstance(parsed, AstSequence)
        assert isinstance(parsed.head, AstPipeline)
        command = SynCommand(parsed.head.parts[0])
        self.assertEqual(command.verb, 'set')
        self.assertEqual(len(command.args), 1)

    def test_set_line_continuation_01(self):
        @emulate
        class bat:
            '''
            set A=F^
            OO
            echo %A%
            '''
        it = bat.emulate()
        self.assertEqual(next(it), 'echo FOO')

    def test_set_line_continuation_02(self):
        @emulate
        class bat:
            '''
            set A=F^
            ^
            REM
            echo %A%
            '''
        bat.cfg.show_comments = True
        it = bat.emulate()
        self.assertEqual(next(it), 'REM')
        self.assertEqual(next(it), 'echo F')

    def test_set_has_weird_escaping_rules_01(self):
        @emulate
        class bat:
            '''
            set "BAR=SE"C^O^^^"N"D
            echo %BAR%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'SE"CO^"N')

    def test_set_with_prompt_output(self):
        @emulate
        class bat:
            '''
            set Railway=S
            set Signature=e
            set Bennett=T
            %Railway%%Signature%%Bennett% /p ="MZ" > boom.exe <nul
            '''
        bat.execute()
        self.assertEqual(bat.state.ingest_file('boom.exe'), 'MZ')

    def test_set_has_weird_escaping_rules_02(self):
        @emulate
        class bat:
            '''
            set ^^"BAR=SE"C^O^^^"N"D
            echo %^"BAR%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'SE"CO^"N"D')

    def test_set_has_weird_escaping_rules_03(self):
        @emulate
        class bat:
            '''
            set ^^"BAR=S"E"C^O^^^"N"D
            echo %^"BAR%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'S"E"CO^"N"D')

    def test_set_has_weird_escaping_rules_04(self):
        @emulate
        class bat:
            '''
            set BAR=SE"^^"COND
            echo %BAR%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'SE"^^"COND')

    def test_set_has_weird_escaping_rules_05(self):
        @emulate
        class bat:
            '''
            set BAR^==TEST
            echo %BAR=%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'TEST')

    def test_set_has_weird_escaping_rules_10(self):
        @emulate
        class bat:
            '''
            @echo off
            set ^"FOO=FIRST
            echo %FOO%
            set ^^"^BA^R=S"E"C^O^^^"N"D
            echo %^"^BA^R%
            set ^^^"BAZ=THIRD
            echo %^"BAZ%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'FIRST')
        self.assertEqual(next(it), 'S"E"CO^"N"D')
        self.assertEqual(next(it), 'THIRD')
        with self.assertRaises(StopIteration):
            next(it)

    def test_set_unquoted_double_caret_immediate_expansion(self):
        @emulate
        class bat:
            '''
            set x=a^^b
            echo %x%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'ab')
        self.assertEqual(bat.state.environment['X'], 'a^b')

    def test_set_unquoted_double_caret_delayed_expansion(self):
        @emulate
        class bat:
            '''
            setlocal enabledelayedexpansion
            set x=a^^b
            echo !x!
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'a^b')
        self.assertEqual(bat.state.environment['X'], 'a^b')

    def test_set_unquoted_double_caret_cmdline_delayed_expansion(self):
        state = BatchState(cmdline=True, delayexpand=True)
        bat = BatchEmulator('set x=a^^b&&echo !x!\n', state)
        commands = list(bat.emulate())
        self.assertEqual(commands, ['echo a^b'])
        self.assertEqual(state.environment['X'], 'a^b')

    def test_block_not_treated_as_block_after_goto(self):
        @emulate
        class bat:
            '''
            @ECHO OFF
            SET FOO=FOO
            SET BAR=BAR
            (
                :BLOCK
                SET BAR=BAROQUE
                ECHO FOO=%FOO%
                ECHO BAR=%BAR%
                GOTO :%FOO%
            )
            :FOO
            SET FOO=END
            SET BAR=BARILLA
            SET END=END
            GOTO :BLOCK
            :END
            '''
        it = (cmd[5:] for cmd in bat.emulate_commands() if cmd.startswith('ECHO'))
        self.assertEqual(next(it), 'FOO=FOO')
        self.assertEqual(next(it), 'BAR=BAR')
        self.assertEqual(next(it), 'FOO=END')
        self.assertEqual(next(it), 'BAR=BAROQUE')
        with self.assertRaises(StopIteration):
            next(it)

    def test_default_errorlevel_is_zero(self):
        @emulate
        class bat:
            '''
            ECHO %ERRORLEVEL%
            '''
        it = iter(bat.emulate())
        self.assertEqual(next(it), 'ECHO 0')
        with self.assertRaises(StopIteration):
            next(it)

    def test_variables_integers(self):
        @emulate
        class bat:
            '''
            @echo off
            set ALPHA=ABCDEFGHIJKLMNOPQRSTUVWXYZ
            echo %ALPHA:~0x10,010%
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'QRSTUVWX')
        with self.assertRaises(StopIteration):
            next(it)

    def test_variables_reset_at_colon(self):
        @emulate
        class bat:
            '''
            echo %x:LEAK%
            '''
        self.assertListEqual(list(bat.emulate()), ['echo LEAK'])

    def test_variables_unclosed(self):
        @emulate
        class bat:
            '''
            echo %FOO BAR
            '''
        self.assertListEqual(list(bat.emulate()), ['echo FOO BAR'])

    def test_percent_escaping(self):
        @emulate
        class bat:
            '''
            echo %%%FOO BAR
            '''
        self.assertListEqual(list(bat.emulate()), ['echo %FOO BAR'])

    def test_delayed_variable_resetting(self):
        @emulate
        class bat:
            '''
            @ setlocal EnableDelayedExpansion
            @ @ @ @ @@ set foo=bar
            @@@@@ echo !foo:oo=ar!!u:bong!
            '''
        self.assertListEqual(list(bat.emulate()), [
            '@setlocal EnableDelayedExpansion',
            '@echo barbong'])

    def test_leading_semicolons(self):
        @emulate
        class bat:
            '''
            @ echo,Test1
            =;echo Test2
            ;;echo...st3
            =@echo:Test4
            @;=,echo/Test5
            =echo#Test6
            =echo!Test7
            '''
        goal = [
            '@echo Test1',
            R'echo Test2',
            R'echo ..st3',
            '@echo Test4',
            R'echo Test5',
            R'echo#Test6',
            R'echo!Test7',
        ]
        test = list(bat.emulate_commands(allow_junk=True))
        self.assertListEqual(test, goal)

    def test_labels_within_line_continuations_work(self):
        @emulate
        class bat:
            '''
            @echo off
            set BOO=BOO
            goto :BAR
            :BOO
            set BOO=END
            echo FOO^
            :BAR
            echo %BOO%
            goto %BOO%
            :END
            '''
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'BOO')
        self.assertEqual(next(it), 'FOO:BAR')
        self.assertEqual(next(it), 'END')
        with self.assertRaises(StopIteration):
            next(it)

    def test_lines_extended_after_variable_expansion(self):
        @emulate
        class bat:
            '''
            echo A ^%FOO%
            echo B %%FOO%%
            echo A ^%FOO
            echo B %%FOO%%
            set FOO=TEST
            echo A ^%FOO%
            echo B %%FOO%%
            setlocal enabledelayedexpansion
            echo A^!BAR!
            echo B
            endlocal
            echo A^!BAR!
            echo B
            '''
        it = (cmd[5:] for cmd in bat.emulate_commands() if cmd.startswith('echo'))
        self.assertEqual(next(it), 'A echo B %FOO%')
        self.assertEqual(next(it), 'A FOO')
        self.assertEqual(next(it), 'B %FOO%')
        self.assertEqual(next(it), 'A TEST')
        self.assertEqual(next(it), 'B %FOO%')
        self.assertEqual(next(it), 'A')
        self.assertEqual(next(it), 'B')
        self.assertEqual(next(it), 'A!BAR!')
        self.assertEqual(next(it), 'B')
        with self.assertRaises(StopIteration):
            next(it)

    def test_call_errorlevels(self):
        @emulate
        class bat:
            '''
            SET VAR=UNCHANGED
            CALL :TEST
            ECHO %ERRORLEVEL%
            ECHO %VAR%
            IF ERRORLEVEL 10 ECHO FOO
            IF ERRORLEVEL 11 ECHO BAR
            IF ERRORLEVEL 12 ECHO BAZ
            GOTO :EOF
            :TEST
            SET VAR=CHANGED
            EXIT/B 0011
            '''
        self.assertListEqual([cmd for cmd in bat.emulate_commands() if cmd.startswith('ECHO')], [
            'ECHO 11',
            'ECHO CHANGED',
            'ECHO FOO',
            'ECHO BAR',
        ])

    def test_goto_vs_call_vs_eof_01(self):
        @emulate
        class bat:
            """
            goto EOF
            echo FOO
                :EOF
            echo BAR
            """
        self.assertListEqual(list(bat.emulate()), ['echo BAR'])

    def test_goto_vs_call_vs_eof_02(self):
        @emulate
        class bat:
            """
            goto :EOF
            echo FOO
            :EOF
            echo BAR
            """
        self.assertListEqual(list(bat.emulate()), [])

    def test_goto_vs_call_vs_eof_03(self):
        @emulate
        class bat:
            """
            call EOF
            echo FOO
            :EOF
            echo BAR
            """
        self.assertEqual(list(bat.emulate()), [
            'call EOF',
            'echo FOO',
            'echo BAR',
        ])

    def test_goto_vs_call_vs_eof_04(self):
        @emulate
        class bat:
            """
            call :EOF
            ecHo FOO
            :EOF
            echo BAR
            """
        self.assertListEqual(list(bat.emulate()), [
            'echo BAR',
            'ecHo FOO',
            'echo BAR',
        ])

    def test_goto_vs_call_vs_eof_05(self):
        @emulate
        class bat:
            """
            call :EOF
            echo FOO
            """
        with self.assertRaises(EmulatorException):
            for _ in bat.emulate():
                pass

    def test_else_ignored_without_grouping(self):
        @emulate
        class bat:
            '''
            if 1 == 1 echo (
                echo B
            ) else (
                echo C
            )
            '''
        it = (cmd[5:] for cmd in bat.emulate_commands() if cmd.startswith('echo'))
        self.assertEqual(next(it), '(')
        self.assertEqual(next(it), 'B')
        self.assertEqual(next(it), 'C')
        with self.assertRaises(StopIteration):
            next(it)

    def test_only_first_token_of_labels_counts(self):
        @emulate
        class bat:
            '''
            goto :FOO
            echo FIRST
            :FOO BAR
            echo FOO
            goto :EOF
            :FOO
            echo BAR
            '''
        self.assertEqual(list(bat.emulate()), ['echo FOO'])

    def test_block_expand_01(self):
        @emulate
        class bat:
            '''
            set A=FOO && (
                echo [%A%]
            )
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo []'])

    def test_block_expand_02(self):
        @emulate
        class bat:
            '''
            set A=BAR
            set A=FOO && (echo [%A%])
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo [BAR]'])

    def test_goto_01_label_escaped_without_respecting_quotes(self):
        @emulate
        class bat:
            '''
            goto "^^"baz" "BAR
            junk
            :    "^^^^"BAZ" "X
            echo BAR
            '''
        self.assertEqual(list(bat.emulate()), ['echo BAR'])

    def test_goto_02_label_escaped_without_respecting_quotes(self):
        @emulate
        class bat:
            '''
            goto BAZ"^^x
            junk
            :    BAZ"^^x
            echo BAR
            '''
        with (exc := self.assertRaises(InvalidLabel)):
            for _ in bat.emulate():
                pass
        self.assertEqual(exc.exception.label, 'BAZ"^^x')

    def test_goto_03_trailing_quote_ignored(self):
        @emulate
        class bat:
            '''
            goto ^^BAZ" "BAZ
            junk
            :    ^^BAZ^ BAZ
            echo BAR
            '''
        with (exc := self.assertRaises(InvalidLabel)):
            for _ in bat.emulate():
                pass
        self.assertEqual(exc.exception.label, '^BAZ"')

    def test_goto_04_trailing_caret_discarded(self):
        @emulate
        class bat:
            '''
            goto ^^BAZ^ BAZ
            junk
            :    ^^BAZ^ BAZ
            '''
        with (exc := self.assertRaises(InvalidLabel)):
            for _ in bat.emulate():
                pass
        self.assertEqual(exc.exception.label, '^BAZ')

    def test_goto_05_trailing_caret(self):
        @emulate
        class bat:
            '''
            goto BAZ^ FOO
            junk
            :    BAZ^ BAR
            echo BAR
            '''
        with (exc := self.assertRaises(InvalidLabel)):
            for _ in bat.emulate():
                pass
        self.assertEqual(exc.exception.label, 'BAZ')

    def test_goto_has_gap_after_verb(self):
        @emulate
        class bat:
            '''
            goto , , ,TEST,:TEST :FEST :REST
            echo SKIPPED
            goto :EOF
            :TEST
            echo EXECUTED
            '''
        self.assertListEqual(list(bat.emulate()), ['echo EXECUTED'])

    def test_goto_06_escaping_of_labels(self):
        @emulate
        class bat:
            '''
            goto ^^"B^AZ"
            junk
            :^^"B^^AZ"
            echo hi
            '''
        self.assertListEqual(list(bat.parser.lexer.labels), ['^"B^AZ"'])
        self.assertListEqual(list(bat.emulate()), ['echo hi'])

    def test_variable_in_quotes(self):
        @emulate
        class bat:
            '''
            set A=FOO
            set B="%A%"
            echo %B%
            '''
        self.assertListEqual(list(bat.emulate()), ['echo "FOO"'])

    def test_variable_set_with_at(self):
        @emulate
        class bat:
            '''
            @@set A=FOO
            echo %A%
            '''
        self.assertListEqual(list(bat.emulate()), ['echo FOO'])

    def test_if_knows_variables_in_sequence(self):
        self.assertListEqual(['echo success'], list(BatchEmulator(
            'set b=1 >nul 2>&1& if not defined b (echo trap) else (echo success)').emulate_commands()))

    def test_if_does_not_chain(self):
        for op in ('&', '&&'):
            self.assertEqual(list(BatchEmulator(
                F'           if 1==1 (echo x) else (echo y)  {op} echo z'
            ).emulate_commands()), [
                'echo x',
            ])
            self.assertEqual(list(BatchEmulator(
                F'          (if 1==1 (echo x) else (echo y)) {op} echo z'
            ).emulate_commands()), [
                'echo x',
                'echo z',
            ])
            self.assertEqual(list(BatchEmulator(
                F'echo a{op} if 1==2 (echo x) else (echo y) {op} echo z'
            ).emulate_commands()), [
                'echo a',
                'echo y',
                'echo z',
            ])

    def test_labels_can_be_silenced(self):
        @emulate
        class bat:
            '''
            @goto HI
            @echo HO
            @:HI
            @echo HI
            '''
        self.assertListEqual(list(bat.emulate()), ['@echo HI'])

    def test_variables_in_redirect_work(self):
        @emulate
        class bat:
            '''
            set filename=output.txt
            echo test>%filename%
            '''
        for _ in bat.emulate():
            pass
        self.assertEqual(bat.state.ingest_file('output.txt'), 'test\r\n')

    def test_separators_after_redirect(self):
        emu = BatchEmulator(';;>test.txt===echo hi\n')
        cmd = list(emu.emulate())
        self.assertListEqual(cmd, ['1>test.txt echo hi'])
        self.assertEqual(emu.state.ingest_file('test.txt'), 'hi\r\n')

    def test_separators_in_redirect(self):
        bat = BatchEmulator('echo/==;;>;; ="==",,  ')
        self.assertEqual(list(bat.emulate()), ['1>"==" echo ==;;'])
        self.assertEqual(bat.state.ingest_file('=='), '==;;\r\n')

    def test_variable_asterix_01(self):
        @emulate
        class bat:
            '''
            echo %*%
            echo %1 %2
            '''
        bat.state.command_line = "hum   ho"
        self.assertListEqual(
            list(bat.emulate()),
            ['echo hum   ho', 'echo hum ho']
        )

    def test_replace_in_delayed_expansion(self):
        @emulate
        class bat:
            '''
            (setlocal enableDelayedExpansion) &&  (set foo=REFINARY) && echo !foo:REF=B!
            '''
        self.assertListEqual(list(bat.emulate_commands()), [
            'setlocal enableDelayedExpansion',
            'echo BINARY'
        ])

    def test_expansion_directly_after_set(self):
        @emulate
        class bat:
            '''
            set jVElq=yxlpdqajizrusokhbmnwefgctv
            @%jVElq:~20,1%%jVElq:~23,1%%jVElq:~15,1%%jVElq:~13,1% %jVElq:~13,1%%jVElq:~21,1%%jVElq:~21,1%
            '''
        self.assertListEqual(list(bat.emulate()), ['@echo off'])

    def test_for_loop_01(self):
        @emulate
        class bat:
            '''
            for %%i in (foo,bar) do (
                echo %%i
            )
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo foo', 'echo bar'])

    def test_for_loop_02(self):
        @emulate
        class bat:
            '''
            for /f %%i in ("hello)") do echo %%i
            '''
        self.assertEqual(list(bat.emulate_commands()), ['echo hello)'])

    def test_regression_quoted_set_statements_not_separated(self):
        @emulate
        class bat:
            '''
            ;SE^T "BAR=BAR"
            ;SE^T "FOO=FOO"
            echo %FOO%
            '''
        self.assertListEqual(list(bat.emulate_commands()), ['echo FOO'])

    def test_cmd_c_preserves_text_after_last_quote(self):
        @emulate
        class bat:
            '''
            cmd /c "echo hello"^& echo world
            '''
        cmds = list(bat.emulate_commands())
        self.assertIn('echo hello', cmds)
        self.assertIn('echo world', cmds)

    def test_cmd_full_path_handler_lookup(self):
        bat = BatchEmulator('C:\\Windows\\System32\\cmd.exe /c echo hello\n')
        cmds = list(bat.emulate_commands())
        self.assertIn('echo hello', cmds)

    def test_cmdline_for_loop_basic(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('for %i in (foo,bar) do echo %i\n', state)
        self.assertEqual(list(bat.emulate_commands()), ['echo foo', 'echo bar'])

    def test_cmdline_for_loop_numeric(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('for /l %i in (1,1,3) do echo %i\n', state)
        self.assertEqual(list(bat.emulate_commands()), ['echo 1', 'echo 2', 'echo 3'])

    def test_cmdline_for_loop_file_parsing(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('for /f %i in ("hello") do echo %i\n', state)
        self.assertEqual(list(bat.emulate_commands()), ['echo hello'])

    def test_cmdline_env_vars_still_work(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('set FOO=BAR\necho %FOO%\n', state)
        self.assertEqual(list(bat.emulate()), ['echo BAR'])

    def test_cmdline_percent_escape(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('echo %%FOO%%\n', state)
        self.assertEqual(list(bat.emulate()), ['echo %FOO%'])

    def test_cmd_c_with_for_loop(self):
        @emulate
        class bat:
            '''
            cmd /c "for /l %%i in (1,1,2) do echo %%i"
            '''
        cmds = list(bat.emulate_commands())
        self.assertIn('echo 1', cmds)
        self.assertIn('echo 2', cmds)

    def test_cmdline_for_loop_digit_variable(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('for %4 in (a,b) do echo %4\n', state)
        self.assertEqual(list(bat.emulate_commands()), ['echo a', 'echo b'])

    def test_cmdline_digit_var_not_positional_arg(self):
        state = BatchState(cmdline=True)
        bat = BatchEmulator('echo %4\n', state)
        self.assertEqual(list(bat.emulate()), ['echo %4'])

    def test_batch_mode_positional_arg_still_works(self):
        state = BatchState()
        state.command_line = 'one two three four'
        bat = BatchEmulator('echo %4\n', state)
        self.assertEqual(list(bat.emulate()), ['echo four'])

    def test_cmdline_deobfuscation_with_delayed_expansion(self):
        state = BatchState(cmdline=True, delayexpand=True)
        bat = BatchEmulator(
            'set A=HELLO\n'
            'for %i in (0,1,2,3,4) do set R=!R!!A:~%i,1!\n'
            'echo !R!\n',
            state,
        )
        self.assertIn('echo HELLO', list(bat.emulate()))

    def test_cmd_c_digit_for_variable(self):
        @emulate
        class bat:
            '''
            cmd /V:ON /c "set A=XY&&for %%4 in (0,1) do set R=!R!!A:~%%4,1!&&if %%4 geq 1 echo !R!"
            '''
        cmds = list(bat.emulate_commands())
        self.assertIn('echo XY', cmds)

    def test_if_geq_with_expanded_for_variable(self):
        state = BatchState(cmdline=True, delayexpand=True)
        bat = BatchEmulator(
            'for %i in (9,83) do if %i geq 83 echo %i\n',
            state,
        )
        cmds = list(bat.emulate_commands())
        self.assertEqual(cmds, ['echo 83'])

    def test_delayed_expansion_substring_not_split_at_colon(self):
        state = BatchState(cmdline=True, delayexpand=True)
        bat = BatchEmulator(
            'set A=HELLO\n'
            'echo !A:~1,3!\n',
            state,
        )
        cmds = list(bat.emulate_commands())
        self.assertEqual(cmds, ['echo ELL'])

    def test_colon_still_splits_without_delayed_expansion(self):
        from refinery.lib.scripts.bat.model import Ctrl
        lexer = BatchLexer('goto :label\n', BatchState())
        tokens = list(lexer.tokens(0))
        self.assertIn(Ctrl.Label, tokens)


class TestBatchUtil(TestBase):

    def test_batchrange_length_zero_when_inc_zero(self):
        br = batchrange(0, 0, 10)
        self.assertEqual(len(br), 0)

    def test_batchrange_length_zero_when_inc_negative(self):
        br = batchrange(0, -1, 10)
        self.assertEqual(len(br), 0)

    def test_batchrange_length_zero_when_max_less_than_min(self):
        br = batchrange(10, 1, 5)
        self.assertEqual(len(br), 0)

    def test_batchrange_normal_iteration(self):
        br = batchrange(1, 2, 7)
        self.assertListEqual(list(br), ['1', '3', '5', '7'])

    def test_batchrange_single_element(self):
        br = batchrange(5, 1, 5)
        self.assertListEqual(list(br), ['5'])
        self.assertEqual(len(br), 1)

    def test_batchrange_length_normal(self):
        br = batchrange(0, 3, 10)
        self.assertEqual(len(br), 4)
        self.assertListEqual(list(br), ['0', '3', '6', '9'])

    def test_batchint_hex(self):
        self.assertEqual(batchint('0x1F'), 31)
        self.assertEqual(batchint('0X10'), 16)

    def test_batchint_octal(self):
        self.assertEqual(batchint('010'), 8)

    def test_batchint_negative(self):
        self.assertEqual(batchint('-5'), -5)
        self.assertEqual(batchint('-0x10'), -16)
        self.assertEqual(batchint('-010'), -8)

    def test_batchint_default_on_error(self):
        self.assertEqual(batchint('notanumber', 99), 99)

    def test_batchint_raises_without_default(self):
        with self.assertRaises(ValueError):
            batchint('notanumber')

    def test_u16_str_to_memoryview(self):
        result = u16('AB')
        self.assertIsInstance(result, memoryview)
        self.assertEqual(result.format, 'H')

    def test_u16_roundtrip(self):
        original = 'Hello'
        encoded = u16(original)
        decoded = u16(encoded)
        self.assertEqual(decoded, original)

    def test_unquote_removes_surrounding_quotes(self):
        self.assertEqual(unquote('"hello"'), 'hello')

    def test_unquote_nested_quotes(self):
        self.assertEqual(unquote('"he"llo"'), 'hello')

    def test_unquote_no_quotes(self):
        self.assertEqual(unquote('hello'), 'hello')

    def test_unquote_unclosed_quote(self):
        self.assertEqual(unquote('"hello'), 'hello')

    def test_uncaret_basic_escaping(self):
        trailing, result = uncaret('^a^b', ignore_quotes=True)
        self.assertFalse(trailing)
        self.assertEqual(result, 'ab')

    def test_uncaret_trailing_caret(self):
        trailing, result = uncaret('test^', ignore_quotes=True)
        self.assertTrue(trailing)
        self.assertEqual(result, 'test^')

    def test_uncaret_with_quotes(self):
        trailing, result = uncaret('^a"^b"^c', ignore_quotes=False)
        self.assertFalse(trailing)
        self.assertEqual(result, 'a"^b"c')
        trailing, result = uncaret('^&"^&"^|^')
        self.assertTrue(trailing)
        self.assertEqual(result, '&"^&"|^')

    def test_error_zero_bool_is_true(self):
        from refinery.lib.scripts.bat.state import ErrorZero
        ez = ErrorZero.Val
        self.assertTrue(bool(ez))

    def test_error_zero_str_is_zero(self):
        from refinery.lib.scripts.bat.state import ErrorZero
        ez = ErrorZero.Val
        self.assertEqual(str(ez), '0')

    def test_error_zero_int_value_is_zero(self):
        from refinery.lib.scripts.bat.state import ErrorZero
        ez = ErrorZero.Val
        self.assertEqual(int(ez), 0)

    def test_batchstate_errorlevel_default(self):
        from refinery.lib.scripts.bat.state import BatchState
        state = BatchState()
        self.assertEqual(state.envar('ERRORLEVEL'), '0')

    def test_batchrange_basic(self):
        r = batchrange(1, 1, 5)
        self.assertEqual(list(r), ['1', '2', '3', '4', '5'])

    def test_batchrange_step(self):
        r = batchrange(0, 2, 8)
        self.assertEqual(list(r), ['0', '2', '4', '6', '8'])

    def test_batchrange_empty(self):
        r = batchrange(10, 1, 5)
        self.assertEqual(list(r), [])
        self.assertEqual(len(r), 0)

    def test_batchrange_zero_step(self):
        # A step of 0 loops forever while start <= end, exactly like cmd.exe FOR /L; take a
        # bounded prefix so the test cannot hang. When start > end it yields nothing.
        r = batchrange(1, 0, 5)
        self.assertEqual(len(r), 0)
        ascending = iter(r)
        self.assertEqual([next(ascending) for _ in range(4)], ['1', '1', '1', '1'])
        self.assertEqual(list(batchrange(5, 0, 1)), [])

    def test_batchrange_descending(self):
        self.assertEqual(list(batchrange(5, -1, 1)), ['5', '4', '3', '2', '1'])
        self.assertEqual(len(batchrange(5, -1, 1)), 5)

    def test_batchrange_step_overshoots_stop(self):
        self.assertEqual(list(batchrange(1, 2, 6)), ['1', '3', '5'])
        self.assertEqual(list(batchrange(5, -2, 0)), ['5', '3', '1'])

    def test_batchrange_step_direction_mismatch(self):
        self.assertEqual(list(batchrange(5, 1, 1)), [])
        self.assertEqual(list(batchrange(1, -1, 5)), [])

    def test_batchrange_infinite_property(self):
        self.assertTrue(batchrange(1, 0, 5).infinite)
        self.assertTrue(batchrange(1, 0, 1).infinite)
        self.assertFalse(batchrange(5, 0, 1).infinite)
        self.assertFalse(batchrange(1, 1, 5).infinite)
        self.assertFalse(batchrange(5, -1, 1).infinite)

    def test_batchrange_negative_step(self):
        r = batchrange(1, -1, 5)
        self.assertEqual(len(r), 0)

    def test_batchint_decimal(self):
        self.assertEqual(batchint('42'), 42)

    def test_batchint_negative_hex(self):
        self.assertEqual(batchint('-0xFF'), -255)

    def test_batchint_invalid_with_default(self):
        self.assertEqual(batchint('notanumber', 0), 0)

    def test_batchint_invalid_raises(self):
        with self.assertRaises(ValueError):
            batchint('notanumber')

    def test_unquote_basic(self):
        self.assertEqual(unquote('"hello"'), 'hello')

    def test_unquote_partial(self):
        self.assertEqual(unquote('"hello'), 'hello')

    def test_uncaret_basic(self):
        trailing, result = uncaret('^&^|^<^>', ignore_quotes=True)
        self.assertFalse(trailing)
        self.assertEqual(result, '&|<>')

    def test_uncaret_trailing(self):
        trailing, result = uncaret('hello^', ignore_quotes=True)
        self.assertTrue(trailing)

    def test_u16_string_to_memoryview(self):
        result = u16('AB')
        self.assertIsInstance(result, memoryview)

    def test_u16_bytes_to_string(self):
        data = 'Hello'.encode('utf-16le')
        result = u16(data)
        self.assertEqual(result, 'Hello')

    def test_enquote_with_special_characters(self):
        self.assertIn('hello world', enquote('hello world'))
        self.assertIn('a&b', enquote('a&b'))
        self.assertIn('x<y', enquote('x<y'))

    def test_enquote_no_quoting_needed(self):
        self.assertEqual(enquote('simple'), 'simple')

    def test_enquote_preserves_token_value(self):
        for token in ('hello world', 'a&b', 'foo|bar', 'test^val', 'a<b>c'):
            result = enquote(token)
            self.assertIn(token.replace('"', '"""'), result)
            self.assertNotEqual(result, '"{token}"')

    def test_cmd_c_verb_with_special_chars_not_literal(self):
        bat = BatchEmulator('CMD /c C:\\foo\\bar.exe /a\n')
        cmds = list(bat.emulate_commands(allow_junk=True))
        for cmd in cmds:
            self.assertNotIn('{token}', cmd)


class TestBatchCmdSemantics(TestBase):
    """
    A ledger of Windows command interpreter behavior, measured against cmd.exe and findstr
    on Windows, checked against what the emulator does.

    Each test's docstring states what cmd.exe actually does, so a failure can be read without
    leaving this file. An entry marked `expectedFailure` is a defect the emulator still has.
    That marking is a ratchet in both directions: a fix makes the entry an unexpected success,
    which is reported as a failure until the marking is removed, and a regression makes an
    unmarked entry fail outright. Neither direction can pass silently.
    """

    def _run(self, code: str, state: BatchState | None = None):
        bat = BatchEmulator(F'{code}\n', state)
        bat.execute()
        return bat

    def _run_collecting(self, code: str, state: BatchState | None = None):
        """
        Runs the code once, returning the emulator and every command it emitted, so
        that commands and stdout are asserted against the same single execution.
        """
        bat = BatchEmulator(F'{code}\n', state)
        commands = [str(s) for s in bat.trace() if isinstance(s, SynCommand)]
        return bat, commands

    def _for_file(self, line: str) -> str:
        state = BatchState()
        state.create_file('cmds.txt', F'{line}\r\n')
        bat = BatchEmulator('for /f "delims=x" %%A in (cmds.txt) do %%A\n', state)
        bat.execute()
        return bat.std.o.getvalue()

    def test_for_f_value_operators_are_inert(self):
        """
        A command operator inside a FOR variable value is never re-detected: the value
        `echo one&echo two` given to `do echo [%%A]` is printed verbatim.
        """
        bat = self._run('for /f "delims=x" %%A in ("echo one&echo two") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[echo one&echo two]\r\n')

    def test_for_f_value_preserves_whitespace_runs(self):
        """
        Internal whitespace runs in a FOR variable value are preserved: the value `a  b`
        given to `do echo [%%A]` prints `[a  b]`, not `[a b]`.
        """
        bat = self._run('for /f "delims=x" %%A in ("a  b") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[a  b]\r\n')

    def test_set_quoted_junk_after_closing_quote(self):
        """
        In `set "X=Y"&rem junk`, everything after the closing quote is discarded and
        `X` is set to `Y`; the `&rem` tail never becomes a comment.
        """
        bat = self._run('set "X=Y"&rem junk')
        self.assertEqual(bat.state.envar('X'), 'Y')

    def test_for_f_tokens_range_missing_upper_runs_empty(self):
        """
        `for /f "tokens=1-2" %%A in ("one")` runs the body once with %%A=one and %%B
        empty; only a missing lowest requested token skips the body.
        """
        bat = self._run('for /f "tokens=1-2" %%A in ("one") do echo [%%A][%%B]')
        self.assertEqual(bat.std.o.getvalue(), '[one][]\r\n')

    def test_for_f_empty_delims_captures_line_verbatim(self):
        """
        `for /f "delims=" %%A` captures the whole line verbatim, including leading
        spaces: `("  x  y")` gives `[  x  y]`.
        """
        bat = self._run('for /f "delims=" %%A in ("  x  y") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[  x  y]\r\n')

    def test_for_f_tokens_one_with_empty_delims(self):
        """
        `tokens=1` with empty `delims=` still captures the whole line; the token count
        must not guard the delimiters.
        """
        bat = self._run('for /f "tokens=1 delims=" %%A in ("  x  y") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[  x  y]\r\n')

    def test_for_f_delims_trailing_space_still_splits(self):
        """
        `for /f "delims= "` splits on the space, unlike empty `delims=`: `("  x  y")`
        gives token `[x]`.
        """
        bat = BatchEmulator('for /f "delims= " %%A in ("  x  y") do echo [%%A]\n')
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '[x]\r\n')

    def test_for_f_default_delims_skip_leading_runs(self):
        """
        With default delimiters, leading delimiter runs are skipped before
        tokenization: `("  two  spaces")` gives token `[two]`, not an empty token.
        """
        bat = self._run('for /f %%A in ("  two  spaces") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[two]\r\n')

    def test_for_f_default_eol_is_semicolon(self):
        """
        The default `eol` character is `;` and the check fires after leading-delimiter
        skipping: both `;semi` and ` ;spaced` skip the body.
        """
        bat = self._run('\n'.join([
            'for /f %%A in (";semi") do echo [%%A]',
            'for /f %%A in (" ;spaced") do echo [%%A]',
        ]))
        self.assertEqual(bat.std.o.getvalue(), '')

    def test_for_f_empty_delims_still_skips_eol_lines(self):
        """
        Empty `delims=` keeps space-first lines but does not disable `eol`: `;semi`
        is still skipped while ` ;spaced` is captured.
        """
        bat = self._run('\n'.join([
            'for /f "delims=" %%A in (";semi") do echo [%%A]',
            'for /f "delims=" %%A in (" ;spaced") do echo [%%A]',
        ]))
        self.assertEqual(bat.std.o.getvalue(), '[ ;spaced]\r\n')

    def test_for_f_empty_eol_disables_comment_skip(self):
        """
        `eol=` with no value is legal and disables the comment check: `(";x")`
        captures `;x`.
        """
        bat = self._run('for /f "eol=" %%A in (";x") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[;x]\r\n')

    def test_for_f_delimiter_only_line_runs_no_body(self):
        """
        A line consisting only of delimiters runs no body iteration.
        """
        bat = self._run('for /f %%A in (" ") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '')

    def test_for_f_missing_lowest_token_runs_no_body(self):
        """
        `for /f "tokens=2" %%A in ("one")` runs no body iteration; the lowest
        requested token does not exist.
        """
        bat = self._run('for /f "tokens=2" %%A in ("one") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '')

    def test_for_f_tokens_asterisk_strips_leading_delimiters(self):
        """
        With `tokens=*`, leading delimiters are stripped and the whole remainder is
        captured: `("  x  y")` gives `[x  y]`.
        """
        bat = self._run('for /f "tokens=*" %%A in ("  x  y") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[x  y]\r\n')

    def test_for_f_tokens_asterisk_delimiter_only_line_runs_empty(self):
        """
        With `tokens=*`, a delimiter-only line runs one body iteration with an empty
        value, unlike the no-asterisk case.
        """
        bat = self._run('for /f "tokens=*" %%A in (" ") do echo [%%A]')
        self.assertEqual(bat.std.o.getvalue(), '[]\r\n')

    def test_for_f_supports_up_to_31_tokens(self):
        """
        `for /f "tokens=1-31"` is accepted by cmd.exe and runs the body.
        """
        bat = self._run('for /f "tokens=1-31" %%A in ("a b") do echo ok')
        self.assertEqual(bat.std.o.getvalue(), 'ok\r\n')

    def test_for_f_tokens_above_31_rejected(self):
        """
        `for /f "tokens=1-32"` is rejected by cmd.exe; the emulator reports it as an
        error instead of raising.
        """
        bat = BatchEmulator('for /f "tokens=1-32" %%A in ("a b") do echo ok\n')
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_for_f_options_with_delayed_variable_rejected(self):
        """
        `for /f "tokens=!t!"` cannot be resolved at parse time and is reported as an
        error instead of raising a ValueError.
        """
        bat = BatchEmulator(
            'for /f "tokens=!t!" %%A in ("one") do echo %%A\n', BatchState(delayexpand=True))
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_cd_d_switch_and_quoted_target(self):
        R"""
        `cd /d "c:\windows"` changes to `c:\windows`; the `/d` switch and the quotes
        are not part of the path.
        """
        bat = BatchEmulator(
            'cd /d "c:\\windows"\necho %~f0\n', BatchState(filename='x.bat'))
        bat.execute()
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\windows\\x.bat'])

    def test_cd_quoted_target_without_switch(self):
        R"""
        `cd "c:\program files"` unquotes the target.
        """
        bat = self._run('cd "c:\\program files"\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\program files'])

    def test_cd_attached_switch_form(self):
        R"""
        `cd /dc:\windows` is the `/d` switch attached to the target and works.
        """
        bat = self._run('cd /dc:\\windows\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\windows'])

    def test_cd_switch_after_target_keeps_cwd(self):
        R"""
        `/d` is only valid before the target: `cd c:\windows /d` fails and leaves the
        working directory unchanged.
        """
        bat = self._run('cd c:\\windows /d\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\'])

    def test_cd_dangling_switch_is_error(self):
        """
        `cd /d` with no target prints "The filename, directory name, or volume label
        syntax is incorrect." and sets errorlevel 1.
        """
        bat = self._run('cd /d')
        self.assertEqual(bat.state.ec, 1)
        self.assertEqual(
            bat.std.e.getvalue(),
            'The filename, directory name, or volume label syntax is incorrect.\r\n')

    def test_cd_without_arguments_prints_cwd(self):
        """
        `cd` with no argument prints the current directory instead of changing it.
        """
        bat = self._run('cd')
        self.assertEqual(bat.std.o.getvalue(), 'c:\\\r\n')

    def test_cd_other_drive_without_switch_keeps_cwd(self):
        """
        Without `/d`, a target on another drive changes nothing.
        """
        bat = self._run('cd x:\\\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\'])

    def test_cd_drive_relative_target_is_noop(self):
        """
        `cd z:foo` is a drive-relative target on another drive and changes nothing
        instead of crashing.
        """
        bat = self._run('cd z:foo\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\'])

    def test_pushd_unquotes_target(self):
        R"""
        `pushd "c:\windows"` unquotes the target.
        """
        bat = self._run('pushd "c:\\windows"\necho %CD%')
        self.assertEqual(
            [c for c in bat.emulate_commands() if c.startswith('echo')],
            ['echo c:\\windows'])

    def test_type_reads_quoted_path(self):
        """
        `type "a b.txt"` unquotes the path and reads the file.
        """
        state = BatchState()
        state.create_file('a b.txt', 'hello\r\n')
        bat = BatchEmulator('type "a b.txt"\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'hello\r\n')

    def test_del_removes_quoted_path(self):
        """
        `del "a b.txt"` unquotes the path and deletes the file.
        """
        state = BatchState()
        state.create_file('a b.txt', 'x')
        bat = BatchEmulator('del "a b.txt"\n', state)
        bat.execute()
        self.assertEqual(state.ingest_file('a b.txt'), None)

    def test_del_without_path_prints_syntax_error(self):
        """
        `del /q` with no path prints "The syntax of the command is incorrect." and
        sets errorlevel 1 instead of raising.
        """
        bat = self._run('del /q')
        self.assertEqual(bat.state.ec, 1)
        self.assertEqual(bat.std.e.getvalue(), 'The syntax of the command is incorrect.\r\n')

    def test_start_d_sets_child_cwd(self):
        R"""
        `start "" /d "c:\x" sub.bat` passes `c:\x` as the child's working directory;
        the `/d` value is unquoted and taken from the next non-space fragment.
        """
        state = BatchState()
        state.create_file('sub.bat', '@echo off\r\necho [%CD%]\r\n')
        bat = BatchEmulator('start "" /d "c:\\x" sub.bat\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), '[c:\\x]\r\n')

    def test_start_trailing_switch_without_value_does_not_raise(self):
        """
        `start "" /d` with no value after the switch is an error, not a crash.
        """
        bat = self._run('start "" /d')
        self.assertEqual(bat.state.ec, 1)

    def test_cmd_trailing_switch_without_value_does_not_raise(self):
        """
        `cmd /v` with no value after the switch is an error, not a crash.
        """
        bat = self._run('cmd /v')
        self.assertEqual(bat.state.ec, 1)

    def test_call_self_reference_is_bounded(self):
        """
        `call %~f0` recursing into itself is reported as an error instead of raising
        RecursionError.
        """
        bat = BatchEmulator('call %~f0\n')
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_goto_set_loop_is_bounded(self):
        """
        A `goto` loop that executes a SET between jumps is bounded by the statement
        budget and reported as an error instead of running forever.
        """
        bat = BatchEmulator(':LOOP\r\nset X=1\r\ngoto LOOP\r\n')
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_structural_nesting_is_bounded_instead_of_crashing(self):
        """
        Parentheses nested past the emulation's depth limit are reported as an error rather than
        exhausting the Python call stack.
        """
        state = BatchState(context=ExecutionContext(depth_limit=16))
        code = '(' * 64 + 'echo hi' + ')' * 64
        bat = BatchEmulator(F'{code}\n', state)
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertEqual(
            errors,
            ['The emulation exceeded its maximum nesting depth of 16 and was aborted.'])

    def test_nested_calls_share_one_depth_limit(self):
        """
        Nested CALLs draw on a single depth allowance shared across sub-shells, so a self-calling
        script is bounded rather than recursing until the Python stack is exhausted.
        """
        state = BatchState(context=ExecutionContext(depth_limit=8))
        state.create_file('r.bat', 'call r.bat\r\n')
        bat = BatchEmulator('call r.bat\n', state)
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_a_called_subscript_shares_its_callers_statement_budget(self):
        """
        A called sub-script draws statements from the same budget as its caller: a caller and
        callee that together exceed the budget are bounded even though neither exceeds it alone,
        so nested emulations cannot each spend a fresh budget.
        """
        state = BatchState(context=ExecutionContext(statement_budget=25))
        state.create_file('sub.bat', 'echo from_sub\r\n' * 15)
        parent = 'echo from_parent\r\n' * 15 + 'call sub.bat'
        bat = BatchEmulator(F'{parent}\n', state)
        errors = [s for s in bat.trace() if isinstance(s, Error)]
        self.assertNotEqual(errors, [])

    def test_a_bug_shaped_exception_from_a_handler_propagates(self):
        """
        A non-EmulatorException raised inside a command handler is a genuine emulator bug; it must
        propagate out of `trace()` rather than be downgraded to a benign error chunk that hides it.
        """
        def boom(self, cmd, std, *_):
            raise ValueError('simulated emulator bug')
        handlers = BatchEmulator._command.handlers
        original = handlers['ECHO']
        handlers['ECHO'] = boom
        try:
            with self.assertRaises(ValueError):
                list(BatchEmulator('echo hi\n').trace())
        finally:
            handlers['ECHO'] = original

    def test_a_stack_exhaustion_during_emulation_is_reported_not_crashed(self):
        """
        Stack exhaustion is a resource limit rather than an emulator bug, so a RecursionError
        raised while tracing is reported as an error chunk with errorlevel 1, never propagated
        out of `trace()` to crash the caller.
        """
        def boom(self, cmd, std, *_):
            raise RecursionError('simulated stack exhaustion')
        handlers = BatchEmulator._command.handlers
        original = handlers['ECHO']
        handlers['ECHO'] = boom
        try:
            bat = BatchEmulator('echo hi\n')
            errors = [s for s in bat.trace() if isinstance(s, Error)]
            self.assertNotEqual(errors, [])
            self.assertEqual(bat.state.ec, 1)
        finally:
            handlers['ECHO'] = original

    def test_if_errorlevel_with_a_nonnumeric_operand_reports_and_continues(self):
        """
        cmd.exe rejects a non-numeric IF ERRORLEVEL operand with `<token> was unexpected at this
        time.` on stderr, takes neither branch, leaves errorlevel unchanged, and runs the next
        statement; the operand is frequently a variable that expands to junk (`if errorlevel %n%`).
        """
        bat = self._run('if errorlevel abc echo INBRANCH\necho AFTER')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')
        self.assertEqual(bat.std.e.getvalue(), 'abc was unexpected at this time.\r\n')
        self.assertEqual(bat.state.ec, 0)

    def test_if_cmdextversion_with_a_nonnumeric_operand_reports_and_continues(self):
        """
        IF CMDEXTVERSION with a non-numeric operand fails the same way as IF ERRORLEVEL: cmd.exe
        writes `<token> was unexpected at this time.` and carries on to the next statement.
        """
        bat = self._run('if cmdextversion xyz echo INBRANCH\necho AFTER')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')
        self.assertEqual(bat.std.e.getvalue(), 'xyz was unexpected at this time.\r\n')

    def test_lexer_switch_parameter_colon_stays_attached(self):
        """
        A colon directly after a switch token belongs to that token: `findstr
        /c:hello in.txt` lexes `/c:hello` as one token.
        """
        lexer = BatchLexer('findstr /c:hello in.txt\n', BatchState())
        self.assertListEqual(list(lexer.tokens(0)), [
            'findstr', ' ', '/c:hello', ' ', 'in.txt', '\n'])

    def test_for_f_command_spec_delayed_expansion(self):
        """
        The whole FOR line, including the backquoted command, is subject to delayed
        expansion: `('echo !V!')` with `V=hello` must run the child command `echo
        hello`, not `echo !V!`.
        """
        bat, commands = self._run_collecting('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set V=hello',
            "for /f %%A in ('echo !V!') do echo [%%A]",
        ]))
        self.assertEqual(
            [c for c in commands if c.startswith('echo')],
            ['echo hello', 'echo [hello]'])
        self.assertEqual(bat.std.o.getvalue(), '[hello]\r\n')

    def test_for_f_command_spec_without_setlocal_is_literal(self):
        """
        Without `setlocal EnableDelayedExpansion`, `!V!` inside the backquoted
        command stays literal.
        """
        bat = self._run('\n'.join([
            'set V=hello',
            "for /f %%A in ('echo !V!') do echo [%%A]",
        ]))
        self.assertEqual(bat.std.o.getvalue(), '[!V!]\r\n')

    def test_for_f_command_spec_expands_at_parent_time(self):
        """
        The FOR spec is expanded when the line is read, before the child runs: with
        `X=parent` set, the spec `set X=child& echo !X!` must run the child command
        `echo parent`, not `echo !X!`.
        """
        bat, commands = self._run_collecting('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set X=parent',
            "for /f %%A in ('set X=child^& echo !X!') do echo [%%A]",
        ]))
        self.assertEqual(
            [c for c in commands if c.startswith('echo')],
            ['echo parent', 'echo [parent]'])
        self.assertEqual(bat.std.o.getvalue(), '[parent]\r\n')

    def test_for_f_literal_spec_delayed_expansion(self):
        """
        A quoted FOR /F literal is delayed-expanded before tokenization: with
        `X=a b`, `("!X!")` gives token `a`, not `a b`.
        """
        bat = self._run('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set "X=a b"',
            'for /f %%A in ("!X!") do echo T[%%A]',
        ]))
        self.assertEqual(bat.std.o.getvalue(), 'T[a]\r\n')

    def test_for_fileset_spec_delayed_expansion(self):
        """
        A file-set item is delayed-expanded: with `X=hi`, `(!X!)` iterates over
        `hi`.
        """
        bat = self._run('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set X=hi',
            'for %%A in (!X!) do echo F[%%A]',
        ]))
        self.assertEqual(bat.std.o.getvalue(), 'F[hi]\r\n')

    def test_outer_for_variable_in_command_spec(self):
        """
        A FOR variable of an outer loop is substituted inside an inner `for /f`
        command spec: `%%E` with value `one` must give the child command `echo inner
        one`, not `echo inner E`.
        """
        bat, commands = self._run_collecting(
            "for %%E in (one) do for /f %%F in ('echo inner %%E') do echo [%%F]")
        self.assertEqual(
            [c for c in commands if c.startswith('echo')],
            ['echo inner one', 'echo [inner]'])
        self.assertEqual(bat.std.o.getvalue(), '[inner]\r\n')

    def test_call_file_inherits_delayed_expansion(self):
        """
        A CALLed file runs in the same cmd process and inherits delayed expansion:
        a called file's `!X!` sees the caller's variable.
        """
        state = BatchState()
        state.create_file('sub.bat', '@echo off\r\nset "Y=!X!"\r\n')
        bat = BatchEmulator(
            'setlocal EnableDelayedExpansion\r\nset X=abc\r\ncall sub.bat\r\n', state)
        bat.execute()
        self.assertEqual(state.environment.get('Y'), 'abc')

    def test_for_f_command_child_preserves_batch_file(self):
        """
        The command child of a `for /f` loop does not overwrite the batch file in
        the virtual file system.
        """
        code = "for /f %%A in ('echo payload') do echo [%%A]\n"
        state = BatchState(filename='main.bat')
        bat = BatchEmulator(code, state)
        bat.execute()
        self.assertEqual(state.ingest_file('main.bat'), code)

    def test_cmd_c_child_creates_no_file(self):
        """
        A `cmd /c` child is a command string, not a batch file, and registers no
        phantom file in the virtual file system.
        """
        state = BatchState(filename='main.bat')
        bat = BatchEmulator('cmd /c echo hi\n', state)
        bat.execute()
        self.assertEqual(set(state.file_system), {state.resolve_path('main.bat')})

    def test_percent_f0_without_backing_file_is_empty(self):
        """
        With no backing file, `%~f0` expands to the empty string instead of
        crashing.
        """
        lexer = BatchLexer('echo [%~f0]\n', BatchState(filename=None))
        tokens = [t for t in lexer.tokens(0) if not t.isspace()]
        self.assertEqual(tokens, ['echo', '[]'])

    def test_do_for_variable_executes_command(self):
        """
        A FOR variable holding a whole command line is executed: `do %%A` with the
        value `echo hello` runs `echo hello`.
        """
        self.assertEqual(self._for_file('echo hello'), 'hello\r\n')

    def test_do_delayed_variable_executes_command(self):
        """
        A delayed variable holding a whole command line is executed the same way:
        `do !V!` with `V=echo a b` runs `echo a b`.
        """
        state = BatchState()
        state.create_file('cmds.txt', 'z\r\n')
        bat = BatchEmulator('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set "V=echo a b"',
            'for /f "delims=x" %%A in (cmds.txt) do !V!',
        ]) + '\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a b\r\n')

    def test_do_for_variable_operators_are_inert(self):
        """
        A FOR variable given to `do %%A` is split into verb and arguments at
        whitespace, but operators in the value stay inert: `echo one&echo two` runs
        as a single `echo` printing `one&echo two`.
        """
        self.assertEqual(self._for_file('echo one&echo two'), 'one&echo two\r\n')

    def test_do_for_value_caret_space_is_inert(self):
        """
        A caret-escaped space inside a FOR variable value does not split arguments:
        `echo a^ b` prints `a^ b`.
        """
        self.assertEqual(self._for_file('echo a^ b'), 'a^ b\r\n')

    def test_do_set_unquoted_value_keeps_spaces(self):
        """
        `do set X=%%A` with value `a b` sets `X` to `a b`: the SET argument is the
        whole tail and is not split at spaces.
        """
        state = BatchState()
        state.create_file('cmds.txt', 'a b\r\n')
        bat = BatchEmulator(
            'for /f "delims=x" %%A in (cmds.txt) do set X=%%A\n', state)
        bat.execute()
        self.assertEqual(bat.state.envar('X'), 'a b')

    def test_do_set_junk_after_quote(self):
        """
        `do %%A` with the value `set "TRY=ok"&rem marker` sets `TRY` to `ok`.
        """
        state = BatchState()
        state.create_file('cmds.txt', 'set "TRY=ok"&rem marker\r\n')
        bat = BatchEmulator(
            'for /f "delims=x" %%A in (cmds.txt) do %%A\n', state)
        bat.execute()
        self.assertEqual(bat.state.envar('TRY'), 'ok')

    def _findstr(self, args: str, text: str, files: dict[str, str] | None = None) -> BatchEmulator:
        state = BatchState()
        state.create_file('in.txt', text)
        for name, content in (files or {}).items():
            state.create_file(name, content)
        bat = BatchEmulator(F'findstr {args} in.txt\n', state)
        bat.execute()
        return bat

    def test_findstr_c_literal_by_default(self):
        """
        A `/c:` needle is a literal search string: `/c:"a.c"` matches the line
        `a.c` but not `abc`.
        """
        bat = self._findstr('/c:"a.c"', 'abc\r\na.c\r\n')
        self.assertEqual(bat.std.o.getvalue(), 'a.c\r\n')

    def test_findstr_r_makes_c_needle_regex(self):
        """
        `/R` turns a `/c:` needle into a regular expression.
        """
        bat = self._findstr('/R /c:"a.c"', 'abc\r\na.c\r\n')
        self.assertEqual(bat.std.o.getvalue(), 'abc\r\na.c\r\n')

    def test_findstr_r_after_c_needle_is_regex(self):
        """
        `/R` after the `/c:` needle still applies to it.
        """
        bat = self._findstr('/c:"a.c" /R', 'abc\r\na.c\r\n')
        self.assertEqual(bat.std.o.getvalue(), 'abc\r\na.c\r\n')

    def test_findstr_c_and_g_needles_have_separate_modes(self):
        """
        `/c:` needles are literal while `/g:` needles are regular expressions in
        the same invocation.
        """
        bat = self._findstr(
            '/g:g.txt /c:"a.c"', 'abc\r\na.c\r\n', {'g.txt': 'a.c\r\n'})
        self.assertEqual(bat.std.o.getvalue(), 'abc\r\na.c\r\n')

    def test_findstr_l_makes_g_needles_literal(self):
        """
        `/L` makes `/g:` needles literal.
        """
        bat = self._findstr(
            '/L /g:g.txt', 'abc\r\na.c\r\n', {'g.txt': 'a.c\r\n'})
        self.assertEqual(bat.std.o.getvalue(), 'a.c\r\n')

    def test_findstr_l_and_r_are_mutually_exclusive(self):
        """
        `findstr /L /R` is refused with errorlevel 2 and the message "Specify only
        /L or /R.".
        """
        bat = self._findstr('/L /R a.c', 'abc\r\n')
        self.assertEqual(bat.state.ec, 2)
        self.assertEqual(bat.std.e.getvalue(), 'Specify only /L or /R.\r\n')

    def test_findstr_g_with_quoted_path(self):
        """
        A quoted `/g:` path is unquoted before reading the file.
        """
        bat = self._findstr(
            '/g:"g.txt"', 'abc\r\na.c\r\n', {'g.txt': 'a.c\r\n'})
        self.assertEqual(bat.std.o.getvalue(), 'abc\r\na.c\r\n')

    def test_batchstate_does_not_reseed_global_rng(self):
        """
        Constructing a BatchState must not reseed the process-global random number
        generator.
        """
        before = random.getstate()
        BatchState()
        self.assertEqual(random.getstate(), before)

    def test_random_sequences_differ_across_clones(self):
        """
        Two states constructed from the same `now`, as every clone is, produce
        independent `%RANDOM%` sequences.
        """
        parent = BatchState()
        first = BatchState(now=parent.now)
        a = [first.envar('RANDOM') for _ in range(8)]
        second = BatchState(now=parent.now)
        b = [second.envar('RANDOM') for _ in range(8)]
        self.assertNotEqual(a, b)

    @unittest.expectedFailure
    def test_random_is_reproducible_under_a_pinned_now(self):
        """
        The `now` parameter exists so that an emulation is reproducible; %RANDOM% should honor it,
        so two states pinned to the same moment draw the same sequence. The RNG is currently seeded
        from system entropy rather than `now`, so the two sequences differ.
        """
        now = '2021-06-01T12:00:00'
        first_state = BatchState(now=now)
        first = [first_state.envar('RANDOM') for _ in range(8)]
        second_state = BatchState(now=now)
        second = [second_state.envar('RANDOM') for _ in range(8)]
        self.assertEqual(first, second)

    def test_random_reaches_its_documented_maximum(self):
        """
        cmd.exe %RANDOM% spans 0..32767 inclusive; this seed lands the draw on 32767,
        the value the exclusive upper bound of `randrange(0, 32767)` could never return.
        """
        state = BatchState()
        state._random = random.Random(12735)
        self.assertEqual(state.envar('RANDOM'), '32767')

    def test_set_reconstructed_from_a_for_variable_binds_an_unpadded_name(self):
        """
        A `set NAME=payload` line executed through a FOR variable binds NAME with no
        leading space, so cmd.exe expands a later %NAME% to `payload` and not to nothing.
        """
        state = BatchState()
        state.create_file('c.txt', 'set NAME=payload\r\n')
        bat = self._run('for /f "delims=x" %%A in (c.txt) do %%A\necho %NAME%', state)
        self.assertEqual(bat.std.o.getvalue(), 'payload\r\n')

    def test_bare_cmd_switch_does_not_abort_the_script(self):
        """
        cmd.exe does not abort the running script when a CMD invocation carries only a
        bare `/` where a switch is expected; a following `echo AFTER` still prints.
        """
        bat = self._run('cmd /\necho AFTER')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')
        self.assertEqual(bat.state.ec, 0)

    def test_cd_slashd_to_unresolvable_target_reports_and_continues(self):
        """
        `cd /d z:foo` names another drive's directory that cannot be resolved; cmd.exe
        reports the failure and continues, so both following echoes still print.
        """
        bat = self._run('cd /d z:foo\necho AFTER1\necho AFTER2')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER1\r\nAFTER2\r\n')

    def test_pushd_to_unresolvable_target_reports_and_continues(self):
        """
        `pushd z:foo` names another drive's directory that cannot be resolved; cmd.exe writes
        "The system cannot find the drive specified." to stderr, sets errorlevel 1, and continues.
        """
        bat = self._run('pushd z:foo\necho AFTER')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')
        self.assertEqual(bat.std.e.getvalue(), 'The system cannot find the drive specified.\r\n')
        self.assertEqual(bat.state.ec, 1)

    def test_failed_pushd_pushes_nothing_onto_the_directory_stack(self):
        R"""
        A failed `pushd` pushes nothing: after a successful `pushd c:\windows\system32`, a failed
        `pushd z:foo`, and one `popd`, cmd.exe is back at `c:\windows`, the directory that preceded
        the successful pushd, and not the one it changed to.
        """
        state = BatchState(cwd='C:\\Windows')
        bat = self._run('pushd c:\\windows\\system32\npushd z:foo\npopd', state)
        self.assertEqual(bat.state.cwd, 'c:\\windows')

    def test_start_with_unresolvable_working_directory_does_not_abort_the_parent(self):
        """
        `start "" /d z:foo child.bat` names a working directory that cannot be resolved; cmd.exe
        cannot launch the child there, but the parent script continues to the next command.
        """
        state = BatchState()
        state.create_file('child.bat', '@echo off\r\necho CHILD\r\n')
        bat = self._run('start "" /d z:foo child.bat\necho PARENT', state)
        self.assertEqual(bat.std.o.getvalue(), 'PARENT\r\n')

    def test_command_that_expands_to_empty_is_a_noop(self):
        """
        A command line that expands to nothing — here an undefined `!undef!` under
        delayed expansion — is a no-op in cmd.exe; a following `echo AFTER` still prints.
        """
        bat = self._run('setlocal enabledelayedexpansion\n!undef!\necho AFTER')
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')

    def test_a_command_failure_returned_by_a_handler_is_written_and_applied(self):
        """
        A handler that returns `CommandFailure(message, errorlevel)` has its message written to the
        error stream and its errorlevel applied by the single command dispatcher, and the following
        statement still runs. Removing the dispatcher arm that recognizes `CommandFailure` fails this.
        """
        def fail(self, cmd, std, *_):
            yield cmd
            return CommandFailure('boom', 7)
        handlers = BatchEmulator._command.handlers
        original = handlers['CD']
        handlers['CD'] = fail
        try:
            bat = self._run('cd whatever\necho AFTER')
            self.assertEqual(bat.std.e.getvalue(), 'boom\r\n')
            self.assertEqual(bat.state.ec, 7)
            self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')
        finally:
            handlers['CD'] = original

    def test_a_command_failure_message_follows_stderr_redirection(self):
        R"""
        `cd /d z:foo 2>e.txt` routes the failure message into the redirected error file and leaves
        the outer error stream empty, because the dispatcher writes it to the redirect-aware stream.
        """
        bat = self._run('cd /d z:foo 2>e.txt')
        self.assertEqual(
            bat.state.ingest_file('e.txt'),
            'The system cannot find the drive specified.\r\n')
        self.assertEqual(bat.std.e.getvalue(), '')
        self.assertEqual(bat.state.ec, 1)

    def test_a_command_failure_still_flushes_the_stdout_redirect_file(self):
        R"""
        `cd /d z:foo >o.txt` fails before writing output, yet the redirected stdout file is still
        created empty, because the dispatcher flushes redirect files even on a command failure.
        """
        bat = self._run('cd /d z:foo >o.txt')
        self.assertTrue(bat.state.exists_file('o.txt'))
        self.assertEqual(bat.state.ingest_file('o.txt'), '')
        self.assertEqual(bat.state.ec, 1)

    def test_a_command_failure_sets_errorlevel_before_the_sequence_tail(self):
        R"""
        A command failure sets errorlevel before `&&`/`||` are evaluated: `cd /d z:foo && echo A`
        prints nothing, `cd /d z:foo || echo B` prints B, and the errorlevel is 1.
        """
        self.assertEqual(self._run('cd /d z:foo && echo A').std.o.getvalue(), '')
        self.assertEqual(self._run('cd /d z:foo || echo B').std.o.getvalue(), 'B\r\n')
        self.assertEqual(self._run('cd /d z:foo').state.ec, 1)

    def test_cd_and_pushd_report_the_identical_drive_message(self):
        R"""
        CD and PUSHD to an unresolvable drive both emit exactly "The system cannot find the drive
        specified."; the message is defined once and shared, so the two cannot drift apart.
        """
        message = 'The system cannot find the drive specified.\r\n'
        self.assertEqual(self._run('cd /d z:foo').std.e.getvalue(), message)
        self.assertEqual(self._run('pushd z:foo').std.e.getvalue(), message)

    def test_arithmetic_set_divide_by_zero_sets_the_cmd_errorlevel(self):
        """
        A SET /A divide-by-zero sets errorlevel 1073750993 alongside its message; the errorlevel is
        the part that drives `&&`/`||` and was previously unpinned.
        """
        bat = self._run('set /a x=1/0')
        self.assertEqual(bat.std.e.getvalue(), 'Divide by zero error.\r\n')
        self.assertEqual(bat.state.ec, 1073750993)

    def test_cd_switch_after_target_reports_path_not_found(self):
        R"""
        `cd foo /x` places a switch after the target, which cmd.exe rejects with "The system cannot
        find the path specified." and errorlevel 1.
        """
        bat = self._run('cd foo /x')
        self.assertEqual(bat.std.e.getvalue(), 'The system cannot find the path specified.\r\n')
        self.assertEqual(bat.state.ec, 1)

    @unittest.expectedFailure
    def test_for_f_assigns_tokens_past_twenty_six(self):
        """
        FOR /F names tokens beyond 26 with the characters that follow Z in ASCII, so token
        27 is %%[. cmd.exe binds it: `tokens=1-27` over 27 words makes %%[ the 27th word.
        """
        state = BatchState()
        state.create_file('t.txt', (
            't1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 '
            't15 t16 t17 t18 t19 t20 t21 t22 t23 t24 t25 t26 t27\r\n'))
        bat = self._run('for /f "tokens=1-27 delims= " %%A in (t.txt) do echo [%%Z][%%[]', state)
        self.assertEqual(bat.std.o.getvalue(), '[t26][t27]\r\n')

    @unittest.expectedFailure
    def test_cd_slashd_switch_is_recognized_once(self):
        """
        cmd.exe recognizes /D only once: `cd /d /d c:\\windows` reads the second `/d` as
        part of a bogus path, fails, and leaves the current directory unchanged.
        """
        state = BatchState(cwd='C:\\start')
        original = state.cwd
        self._run('cd /d /d c:\\windows', state)
        self.assertEqual(state.cwd, original)

    @unittest.expectedFailure
    def test_foreign_drive_relative_path_resolves_to_absolute(self):
        """
        A drive-qualified relative path names a location on that drive's current directory,
        so `z:foo` resolved from a C: working directory is an absolute Z: path and never the
        literal relative `z:foo`.
        """
        state = BatchState(cwd='C:\\dir')
        self.assertTrue(ntpath.isabs(state.resolve_path('z:foo')))

    def test_bare_set_lists_variables_and_does_not_abort_the_run(self):
        """
        A bare `SET` is a display command in cmd.exe, not an error: it lists the environment and the
        following statement still runs. The emulator previously raised on it and dropped the rest.
        """
        bat = self._run('set\necho AFTER')
        self.assertIn('AFTER\r\n', bat.std.o.getvalue())

    def test_bare_set_lists_a_script_variable_excludes_errorlevel_and_keeps_it(self):
        """
        Bare `SET` lists a variable the script defined and hides the pseudo-variable `ERRORLEVEL`
        that cmd.exe never shows; the display reads the environment and deletes nothing.
        """
        bat = self._run('set FOO=bar\nset\necho [%FOO%]')
        out = bat.std.o.getvalue()
        self.assertIn('FOO=bar\r\n', out)
        self.assertFalse(any(line.startswith('ERRORLEVEL=') for line in out.split('\r\n')))
        self.assertIn('[bar]\r\n', out)

    def test_prefix_set_lists_first_token_matches_sorted(self):
        """
        `SET FOO` lists every variable whose name starts with `FOO`, sorted, leaving the error level
        untouched; `BAZ` does not match and is not listed.
        """
        bat = self._run('set FOO=1\nset FOOBAR=2\nset BAZ=3\nset FOO')
        self.assertEqual(bat.std.o.getvalue(), 'FOO=1\r\nFOOBAR=2\r\n')
        self.assertEqual(bat.state.ec, 0)
        self.assertEqual(bat.state.envar('BAZ', ''), '3')

    def test_multi_token_set_matches_first_token_and_does_not_delete(self):
        """
        `SET FOO extra` matches on the first token `FOO`, lists the match, and leaves `FOO` defined;
        it neither deletes the variable nor changes the error level.
        """
        bat = self._run('set FOO=1\nset FOO extra\necho [%FOO%]')
        out = bat.std.o.getvalue()
        self.assertIn('FOO=1\r\n', out)
        self.assertIn('[1]\r\n', out)
        self.assertEqual(bat.state.ec, 0)

    def test_multi_token_no_match_reports_the_full_argument(self):
        """
        A `SET` whose first token matches nothing reports the whole argument, spaces included:
        `SET NOSUCH tail` writes `Environment variable NOSUCH tail not defined` with error level 1.
        """
        bat = self._run('set NOSUCH tail\necho AFTER')
        self.assertEqual(bat.std.e.getvalue(), 'Environment variable NOSUCH tail not defined\r\n')
        self.assertEqual(bat.state.ec, 1)
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')

    def test_quoted_set_display_does_not_spuriously_fail(self):
        """
        `SET "FOO"` strips the quotes before matching, so a defined `FOO` is listed and the error
        level stays 0; without the strip the literal quote would match nothing and fail with exit 1.
        """
        bat = self._run('set FOO=1\nset "FOO"')
        self.assertEqual(bat.std.o.getvalue(), 'FOO=1\r\n')
        self.assertEqual(bat.std.e.getvalue(), '')
        self.assertEqual(bat.state.ec, 0)

    def test_no_match_set_reports_and_continues(self):
        """
        `SET NOSUCH` with no matching variable writes `Environment variable NOSUCH not defined` to
        the error stream with error level 1, and the following statement still runs.
        """
        bat = self._run('set NOSUCH\necho AFTER')
        self.assertEqual(bat.std.e.getvalue(), 'Environment variable NOSUCH not defined\r\n')
        self.assertEqual(bat.state.ec, 1)
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')

    def test_no_match_set_preserves_the_typed_case(self):
        """
        The no-match diagnostic echoes the argument exactly as typed: `SET NoSuch` reports
        `Environment variable NoSuch not defined`, mixed case preserved.
        """
        bat = self._run('set NoSuch')
        self.assertEqual(bat.std.e.getvalue(), 'Environment variable NoSuch not defined\r\n')

    def test_matching_set_display_does_not_reset_errorlevel(self):
        """
        A matching `SET` display returns nothing and leaves the error level alone: after a failed
        `cd /d z:foo` sets it to 1, `SET FOO` lists the match and the error level stays 1.
        """
        bat = self._run('set FOO=1\ncd /d z:foo\nset FOO')
        self.assertEqual(bat.std.o.getvalue(), 'FOO=1\r\n')
        self.assertEqual(bat.state.ec, 1)

    def test_nameless_set_slash_p_is_a_syntax_error_not_an_abort(self):
        """
        `SET /P` with no variable name is cmd.exe's `The syntax of the command is incorrect.` with
        error level 1; it must not read standard input, so the following statement still runs.
        """
        bat = self._run('set /P\necho AFTER')
        self.assertEqual(bat.std.e.getvalue(), 'The syntax of the command is incorrect.\r\n')
        self.assertEqual(bat.state.ec, 1)
        self.assertEqual(bat.std.o.getvalue(), 'AFTER\r\n')

    def test_set_assignment_and_delete_paths_are_unchanged(self):
        """
        The display routing leaves assignment and deletion intact: `SET X=Y` defines `X` as `Y`, and
        a later `SET X=` removes it.
        """
        assigned = self._run('set X=Y')
        self.assertEqual(assigned.state.envar('X', ''), 'Y')
        deleted = self._run('set X=Y\nset X=')
        self.assertEqual(deleted.state.envar('X', '<undef>'), '<undef>')

    def test_set_slash_p_binds_stdin_to_the_named_variable(self):
        """
        `SET /P NAME=prompt` reads a line of input into NAME and echoes the prompt. The emulator
        previously bound the value to a variable literally named `/P`, leaving NAME undefined.
        """
        state = BatchState()
        state.create_file('in.txt', 'HELLO\r\n')
        bat = self._run('set /p VAR=Enter: <in.txt\necho [%VAR%]', state)
        self.assertEqual(bat.state.envar('VAR', ''), 'HELLO')
        self.assertNotIn('/P', bat.state.environment)
        self.assertIn('[HELLO]\r\n', bat.std.o.getvalue())

    def test_prefix_set_matches_variable_names_case_insensitively(self):
        """
        cmd.exe matches the `SET` display prefix without regard to case, so `SET mixed` lists a
        variable named `MixedCase` and keeps the error level at 0 instead of reporting it undefined.
        """
        state = BatchState(environment={'MixedCase': 'v'})
        bat = self._run('set mixed', state)
        self.assertEqual(bat.std.o.getvalue(), 'MixedCase=v\r\n')
        self.assertEqual(bat.std.e.getvalue(), '')
        self.assertEqual(bat.state.ec, 0)

    def test_bare_set_sorts_variable_names_case_insensitively(self):
        """
        cmd.exe orders `SET` output ignoring case, so injected `zeb`, `Apple`, and `ant` list as
        `ant`, `Apple`, `zeb`, not the case-sensitive `Apple`, `ant`, `zeb`.
        """
        state = BatchState(environment={'zeb': '1', 'Apple': '2', 'ant': '3'})
        listing = self._run('set', state).std.o.getvalue().split('\r\n')
        injected = [line for line in listing if line in ('ant=3', 'Apple=2', 'zeb=1')]
        self.assertEqual(injected, ['ant=3', 'Apple=2', 'zeb=1'])

    @unittest.expectedFailure
    def test_user_assigned_errorlevel_is_listed_by_set(self):
        """
        A script-assigned `ERRORLEVEL` shadows the pseudo-variable and is a real variable, so
        cmd.exe lists it: `set ERRORLEVEL=marker` then `set ERRORLEVEL` prints `ERRORLEVEL=marker`.
        The emulator stores the pseudo-variable in the same env slot, so it hides the name outright.
        """
        bat = self._run('set ERRORLEVEL=marker\nset ERRORLEVEL')
        self.assertEqual(bat.std.o.getvalue(), 'ERRORLEVEL=marker\r\n')


class TestBatchDeobfuscationDisplay(TestBase):
    """
    How the emulator renders a script whose behavior depends on variables: the raw
    statement is kept, and the resolved form is added when substitution changed it.
    """

    def _run(self, code: str, state: BatchState | None = None):
        bat = BatchEmulator(F'{code}\n', state)
        bat.execute()
        return bat

    def test_if_with_delayed_variables_emits_expanded_pair(self):
        R"""
        An IF statement whose condition or body references delayed variables is emitted
        twice: once as written, then with every reference resolved.
        """
        bat = self._run('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set "X=c:\\windows"',
            'if exist !X! set "Z=!X!"',
        ]))
        self.assertEqual(list(bat.emulate()), [
            'setlocal EnableDelayedExpansion',
            'IF EXIST !X! set "Z=!X!"',
            R'IF EXIST c:\windows set "Z=c:\windows"',
        ])

    def test_if_without_substitution_emits_once(self):
        """
        An IF statement that variable substitution does not alter is emitted once.
        """
        bat = self._run('if 1 == 1 echo A')
        self.assertEqual(list(bat.emulate()), ['IF 1 == 1 echo A'])

    def test_if_expanded_pair_keeps_body_inline(self):
        """
        The expanded IF pair does not un-hide the body commands that the IF synthesis
        already shows inline.
        """
        bat = self._run('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set "X=one"',
            'if 1 == 1 echo !X!',
        ]))
        self.assertEqual(list(bat.emulate()), [
            'setlocal EnableDelayedExpansion',
            'IF 1 == 1 echo !X!',
            'IF 1 == 1 echo one',
        ])

    def test_extracted_set_appears_in_output(self):
        """
        A SET command executed from a FOR variable value is extracted payload: it
        appears in the deobfuscated output even though ordinary SET commands are
        hidden as junk.
        """
        state = BatchState()
        state.create_file('payload.txt', 'set "X=payload data"\r\n')
        bat = BatchEmulator('for /f "delims=" %%A in (payload.txt) do %%A\n', state)
        self.assertEqual(list(bat.emulate()), [
            'FOR /F "delims=" %A IN (payload.txt) DO %%A',
            'set "X=payload data"',
        ])
        self.assertEqual(bat.state.envar('X'), 'payload data')

    def test_extracted_delayed_command_appears_in_output(self):
        """
        A command executed from a delayed variable is extracted payload the same way
        a FOR variable value is.
        """
        state = BatchState()
        state.create_file('lines.txt', 'z\r\n')
        bat = BatchEmulator('\n'.join([
            'setlocal EnableDelayedExpansion',
            'set "V=echo payload"',
            'for /f "delims=x" %%A in (lines.txt) do !V!',
        ]) + '\n', state)
        self.assertEqual(list(bat.emulate()), [
            'setlocal EnableDelayedExpansion',
            'FOR /F "delims=x" %A IN (lines.txt) DO !V!',
            'echo payload',
        ])
        self.assertEqual(bat.std.o.getvalue(), 'payload\r\n')

    def test_ordinary_set_in_loop_stays_hidden(self):
        """
        A SET command whose verb is part of the script text stays hidden as junk even
        inside a loop whose values are substituted into its argument.
        """
        state = BatchState()
        state.create_file('payload.txt', 'a b\r\n')
        bat = BatchEmulator('for /f "delims=" %%A in (payload.txt) do set Y=%%A\n', state)
        self.assertEqual(list(bat.emulate()), [
            'FOR /F "delims=" %A IN (payload.txt) DO set Y=%A',
        ])
        self.assertEqual(bat.state.envar('Y'), 'a b')

    def test_findstr_c_literal_is_pinned(self):
        """
        A `/c:` needle is a literal search string and must keep working; this was the
        crash site of the original findstr PatternError report.
        """
        state = BatchState()
        state.create_file('x.txt', 'abc\r\na.c\r\n')
        bat = BatchEmulator('findstr /c:"a.c" x.txt\n', state)
        bat.execute()
        self.assertEqual(bat.std.o.getvalue(), 'a.c\r\n')
        self.assertEqual(bat.state.ec, 0)
