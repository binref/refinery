import re

from inspect import getdoc

from refinery.lib.scripts.bat import BatchEmulator, BatchLexer, BatchParser, BatchState
from refinery.lib.scripts.bat.emulator import Error
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
