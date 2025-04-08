#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect

from .. import TestUnitBase
from . import errbuf, TESTBUFFER_BIN, TESTBUFFER_TXT


def bindoc(cls):
    return inspect.getdoc(cls).encode('utf8')


class TestPeek(TestUnitBase):

    def test_unicode_variable(self):
        with errbuf() as stderr:
            pipeline = self.load_pipeline('put u u:This!Is-A-Un1c0d3-String [| peek ]')
            pipeline()
            output = stderr.getvalue()
        self.assertIn('u:This!Is-A-Un1c0d3-String', output)

    def test_hex_peek(self):
        peek = self.load(width=8, lines=15, gray=True)
        with errbuf() as stderr:
            peek(bytes.fromhex(
                '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00'  # MZ..............
                'B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00'  # ........@.......
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
                '00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00'  # ................
                '0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68'  # ........!..L.!Th
                '69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'  # is.program.canno
                '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20'  # t.be.run.in.DOS.
                '6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'  # mode....$.......
            ))
            output = stderr.getvalue()

        self.assertIn('45.87% entropy', output)

        self.assertIn((
            '-------------------------------------\n'
            '00: 4D 5A 90 00 03 00 00 00  MZ......\n'
            '08: 04 00 00 00 FF FF 00 00  ........\n'
            '10: B8 00 00 00 00 00 00 00  ........\n'
            '18: 40 00 00 00 00 00 00 00  @.......\n'
            '20: 00 00 00 00 00 00 00 00  ........\n'
            '..:        2 repetitions\n'
            '38: 00 00 00 00 F8 00 00 00  ........\n'
            '40: 0E 1F BA 0E 00 B4 09 CD  ........\n'
            '48: 21 B8 01 4C CD 21 54 68  !..L.!Th\n'
            '50: 69 73 20 70 72 6F 67 72  is.progr\n'
            '58: 61 6D 20 63 61 6E 6E 6F  am.canno\n'
            '60: 74 20 62 65 20 72 75 6E  t.be.run\n'
            '68: 20 69 6E 20 44 4F 53 20  .in.DOS.\n'
            '70: 6D 6F 64 65 2E 0D 0D 0A  mode....\n'),
            output
        )

    def test_regression_all_output(self):
        data = b'Refining Binaries since 2019'
        peek = self.load(all=True, decode=True, gray=True)
        with errbuf() as stderr:
            peek(data)
            test = stderr.getvalue()
        self.assertIn(data.decode('ascii'), test)

    def test_binary_NB1(self):
        desired = inspect.cleandoc(
            """
            -----------------------------------------------------------------
            4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..............
            B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
            00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00  ................
            0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ........!..L.!Th
            69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F  is.program.canno
            74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20  t.be.run.in.DOS.
            6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00  mode....$.......
            65 39 D7 74 21 58 B9 27 21 58 B9 27 21 58 B9 27  e9.t!X.'!X.'!X.'
            28 20 2A 27 11 58 B9 27 35 33 BD 26 2B 58 B9 27  (.*'.X.'53.&+X.'
            -----------------------------------------------------------------
            """
        )
        peek = self.load(narrow=True, bare=True, width=16, gray=True)
        with errbuf() as stderr:
            peek(TESTBUFFER_BIN)
            out = stderr.getvalue().strip()
        self.assertEqual(out, desired)

    def test_binary_NB2(self):
        desired = inspect.cleandoc(
            """
            ----------------------------------------------------------------
            4D5A 9000 0300 0000 0400 0000 FFFF 0000  MZ .. .. .. .. .. .. ..
            B800 0000 0000 0000 4000 0000 0000 0000  .. .. .. .. @. .. .. ..
            0000 0000 0000 0000 0000 0000 0000 0000  .. .. .. .. .. .. .. ..
            0000 0000 0000 0000 0000 0000 F800 0000  .. .. .. .. .. .. .. ..
            0E1F BA0E 00B4 09CD 21B8 014C CD21 5468  .. .. .. .. !. .L .! Th
            6973 2070 726F 6772 616D 2063 616E 6E6F  is .p ro gr am .c an no
            7420 6265 2072 756E 2069 6E20 444F 5320  t. be .r un .i n. DO S.
            6D6F 6465 2E0D 0D0A 2400 0000 0000 0000  mo de .. .. $. .. .. ..
            6539 D774 2158 B927 2158 B927 2158 B927  e9 .t !X .' !X .' !X .'
            2820 2A27 1158 B927 3533 BD26 2B58 B927  (. *' .X .' 53 .& +X .'
            ----------------------------------------------------------------
            """
        )
        peek = self.load(bare=True, narrow=True, width=8, blocks=2, gray=True)
        with errbuf() as stderr:
            peek(TESTBUFFER_BIN)
            out = stderr.getvalue().strip()
        self.assertEqual(out, desired)

    def test_binary_B4(self):
        desired = inspect.cleandoc(
            """
            -------------------------------------------------------------
            000: 4D5A9000 03000000 04000000 FFFF0000  MZ.. .... .... ....
            004: B8000000 00000000 40000000 00000000  .... .... @... ....
            008: 00000000 00000000 00000000 00000000  .... .... .... ....
            00C: 00000000 00000000 00000000 F8000000  .... .... .... ....
            010: 0E1FBA0E 00B409CD 21B8014C CD215468  .... .... !..L .!Th
            014: 69732070 726F6772 616D2063 616E6E6F  is.p rogr am.c anno
            018: 74206265 2072756E 20696E20 444F5320  t.be .run .in. DOS.
            01C: 6D6F6465 2E0D0D0A 24000000 00000000  mode .... $... ....
            020: 6539D774 2158B927 2158B927 2158B927  e9.t !X.' !X.' !X.'
            024: 28202A27 1158B927 3533BD26 2B58B927  (.*' .X.' 53.& +X.'
            -------------------------------------------------------------
            """
        )
        peek = self.load(bare=True, narrow=False, width=4, blocks=4, gray=True)
        with errbuf() as stderr:
            peek(TESTBUFFER_BIN)
            out = stderr.getvalue().strip()
        self.assertEqual(out, desired)

    def test_printable_decoded(self):
        desired = inspect.cleandoc(
            """
            -----------------------------------------------------------------------[utf8]---
                Another one got caught today, it's all over the papers.  "Teenager
            Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tampering"...
                Damn kids.  They're all alike.
                But did you, in your three-piece psychology and 1950's technobrain,
            ever take a look behind the eyes of the hacker?  Did you ever wonder what
            made him tick, what forces shaped him, what may have molded him?
                I am a hacker, enter my world...
                Mine is a world that begins with school... I'm smarter than most of
            the other kids, this crap they teach us bores me...
                Damn underachiever.  They're all alike.
            --------------------------------------------------------------------------------
            """
        )
        peek = self.load(bare=True, decode=2, width=80, gray=True)
        with errbuf() as stderr:
            peek(TESTBUFFER_TXT)
            out = stderr.getvalue().strip()
        self.assertEqual(out, desired)

    def test_printable_escaped(self):
        desired = inspect.cleandoc(
            R"""
            ------------------------------------------------------------------------
                Another one got caught today, it's all over the papers.  "Teenager\n
            Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tamperi
            ng"...\n    Damn kids.  They're all alike.\n\n    But did you, in your t
            hree-piece psychology and 1950's technobrain,\never take a look behind t
            he eyes of the hacker?  Did you ever wonder what\nmade him tick, what fo
            rces shaped him, what may have molded him?\n    I am a hacker, enter my 
            world...\n    Mine is a world that begins with school... I'm smarter tha
            n most of\nthe other kids, this crap they teach us bores me...\n    Damn
             underachiever.  They're all alike.\n\n    I'm in junior high or high sc
            hool.  I've listened to teachers explain\nfor the fifteenth time how to 
            reduce a fraction.  I understand it.  "No, Ms.\nSmith, I didn't show my 
            work.  I did it in my head..."\n    Damn kid.  Probably copied it.  They
            're all alike.
            ------------------------------------------------------------------------
            """
        )
        peek = self.load(bare=True, escape=True, width=72, all=True, gray=True)
        with errbuf() as stderr:
            peek(TESTBUFFER_TXT)
            out = stderr.getvalue().strip()
        self.assertEqual(out, desired)

    def test_gzip_from_libmagic(self):
        data = self.download_sample('2bda560f264fb4eea5e180f32913197ec441ed8d6852a5cbdb6763de7bbf4ecf')
        peek = self.load(width=70, gray=True)
        with errbuf() as stderr:
            peek(data)
            out = stderr.getvalue().strip()
        self.assertIn('1F 8B 08 00 00 00 00 00 04 00', out)

    def test_encoding_metavars(self):
        pfmt = 'emit s: [| put test "s:{}" | peek -m ]'
        for value, requires_prefix in {
            'b64:b64:b64' : True,
            'accu:@msvc'  : True,
            'u[:!krz--dk' : False,
            'ftp://t.com' : False,
        }.items():
            with errbuf() as stderr:
                prefix = 's:' * requires_prefix
                self.load_pipeline(pfmt.format(value))()
                self.assertIn(F'test = {prefix}{value}', stderr.getvalue())
