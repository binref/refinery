from inspect import getdoc

from refinery.lib.batch import BatchFileEmulator
from .. import TestBase


def emulate(cls):
    if code := getdoc(cls):
        return BatchFileEmulator(code)
    raise ValueError


class TestBatchEmulator(TestBase):

    def test_arithmetic_if(self):
        def _bat(s: str):
            for e in BatchFileEmulator(F'if {s} (true) else (false)').emulate():
                return e

        self.assertEqual(_bat('4 ^LE^Q s'), 'true')
        self.assertEqual(_bat('a ^L^EQ s'), 'true')
        self.assertEqual(_bat('sta LEQ st'), 'false')
        self.assertEqual(_bat('4 LEQ 2+3'), 'false')
        self.assertEqual(_bat('09 LEQ 5'), 'true')
        self.assertEqual(_bat('0x4 LEQ 5'), 'true')
        self.assertEqual(_bat('0X4 LEQ 005'), 'true')
        self.assertEqual(_bat('^=^===^=^='), 'true')
        self.assertEqual(_bat('"^="==^='), 'false')

    def test_file_exists(self):
        @emulate
        class bat:
            '''
            @echo off
            if exist "ex"""""i"sts" echo hi
            '''
        bat.create_file('exists')
        self.assertListEqual(list(bat.emulate()), ['@echo off', 'echo hi'])
        bat.reset()
        self.assertListEqual(list(bat.emulate()), ['@echo off'])

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

    def test_set_has_weird_escaping_rules(self):
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

    def test_batch_integers_in_variable_expansion(self):
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
