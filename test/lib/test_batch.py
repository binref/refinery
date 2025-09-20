from inspect import getdoc

from refinery.lib.batch import BatchFileEmulator
from .. import TestBase


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
        @getdoc
        class test:
            '''
            @echo off
            if exist "ex"""""i"sts" echo hi
            '''
        bat = BatchFileEmulator(test)
        bat.create_file('exists')
        self.assertListEqual(list(bat.emulate()), ['@echo off', 'echo hi'])
        bat.reset()
        self.assertListEqual(list(bat.emulate()), ['@echo off'])
