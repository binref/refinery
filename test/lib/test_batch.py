from inspect import getdoc

from refinery.lib.batch import BatchEmulator, BatchLexer, BatchParser, BatchState
from refinery.lib.batch.synth import SynCommand
from refinery.lib.batch.model import AstGroup, AstPipeline, AstSequence, InvalidLabel, EmulatorException, Redirect, RedirectIO

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


class TestBatchEmulator(TestBase):

    def test_arithmetic_if(self):
        def _bat(s: str):
            for e in BatchEmulator(F'if {s} (true) else (false)').emulate():
                return e

        self.assertEqual(_bat('"^="==^='), 'false')
        self.assertEqual(_bat('^=^===^=^='), 'true')
        self.assertEqual(_bat('A ==    A'), 'true')
        self.assertEqual(_bat('"^=="==^^=='), 'false')
        self.assertEqual(_bat('"^=="=="^=="'), 'true')

        self.assertEqual(_bat('4 ^LE^Q s'), 'true')
        self.assertEqual(_bat('a ^L^EQ s'), 'true')
        self.assertEqual(_bat('sta LEQ st'), 'false')
        self.assertEqual(_bat('4 LEQ 2+3'), 'false')
        self.assertEqual(_bat('4 LEQ 2^+3'), 'false')
        self.assertEqual(_bat('09 LEQ 5'), 'true')
        self.assertEqual(_bat('0x4 LEQ 5'), 'true')
        self.assertEqual(_bat('0X4 LEQ 005'), 'true')

    def test_file_exists(self):
        @emulate
        class bat:
            '''
            @echo off
            if exist "ex"""""i"sts" echo hi
            '''
        bat.state.create_file('exists')
        self.assertListEqual(list(bat.emulate()), ['@echo off', 'echo hi'])
        bat.state.remove_file('exists')
        self.assertListEqual(list(bat.emulate()), ['@echo off'])

    def test_groups_are_commands(self):
        @emulate
        class bat:
            '''
            (
                echo hello
                echo harry
            ) | findstr h
            '''
        self.assertListEqual(list(bat.emulate()), ['echo hello', 'echo harry'])
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
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
        self.assertEqual(next(it), '[FOO-BAR]')
        self.assertEqual(next(it), '[BAR-BAZ]')
        self.assertEqual(next(it), '[BAR-BAZ]')
        with self.assertRaises(StopIteration):
            next(it)

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
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
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
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('ECHO'))
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
        self.assertListEqual(list(bat.emulate()), ['@echo barbong'])

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
        test = list(bat.emulate())
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
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
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
        self.assertListEqual(list(bat.emulate()), [
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
        it = (cmd[5:] for cmd in bat.emulate() if cmd.startswith('echo'))
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
        self.assertEqual(list(bat.emulate()), ['echo []'])

    def test_block_expand_02(self):
        @emulate
        class bat:
            '''
            set A=BAR
            set A=FOO && (echo [%A%])
            '''
        self.assertEqual(list(bat.emulate()), ['echo [BAR]'])

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
            'set b=1 >nul 2>&1& if not defined b (echo trap) else (echo success)').emulate()))

    def test_if_does_not_chain(self):
        for op in ('&', '&&'):
            self.assertEqual(list(BatchEmulator(
                F'           if 1==1 (echo x) else (echo y)  {op} echo z'
            ).emulate()), [
                'echo x',
            ])
            self.assertEqual(list(BatchEmulator(
                F'          (if 1==1 (echo x) else (echo y)) {op} echo z'
            ).emulate()), [
                'echo x',
                'echo z',
            ])
            self.assertEqual(list(BatchEmulator(
                F'echo a{op} if 1==2 (echo x) else (echo y) {op} echo z'
            ).emulate()), [
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
        self.assertListEqual(cmd, ['1>"test.txt" echo hi'])
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
        self.assertListEqual(
            list(bat.emulate(0, command_line="hum   ho")),
            ['echo hum   ho', 'echo hum ho']
        )

    def test_replace_in_delayed_expansion(self):
        @emulate
        class bat:
            '''
            setlocal enableDelayedExpansion &&  (set foo=REFINARY) && echo !foo:REF=B!
            '''
        self.assertListEqual(list(bat.emulate()), ['echo BINARY'])

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
        self.assertEqual(list(bat.emulate()), ['echo foo', 'echo bar'])

    def test_for_loop_02(self):
        @emulate
        class bat:
            '''
            for /f %%i in ("hello)") do echo %%i
            '''
        self.assertEqual(list(bat.emulate()), ['echo hello)'])

    def test_regression_quoted_set_statements_not_separated(self):
        @emulate
        class bat:
            '''
            ;SE^T "BAR=BAR"
            ;SE^T "FOO=FOO"
            echo %FOO%
            '''
        self.assertListEqual(list(bat.emulate(0)), ['echo FOO'])
