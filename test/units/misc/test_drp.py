#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestDRP(TestUnitBase):

    def test_english_plaintext_01(self):
        data = B"Betty Botter's bitter batter better"

        for weight in range(6):
            unit = self.load(weight=weight)
            self.assertEqual(unit(data), b'tter')

        for weight in range(2):
            unit = self.load(weight=weight, consecutive=True)
            self.assertEqual(unit(data), b't')

        unit = self.load(weight=8)
        self.assertEqual(unit(data), b'tter b')

    def test_junk_obfuscation(self):
        data = (
            B"AiIi=X`E`I|''#(:nioj-#(:mj$;}))61,_$(61tniot::]trevnoc[(]rahc[{#(:hcaErof#(:|#(:)'#(:'(tilpS.BOAfwsPxNuRG"
            B"DZdNsktH$=mj$;'D4#(:C7#(:72#(:72#(:02#(:E6#(:96#(:F6#(:A6#(:D2#(:02#(:37#(:27#(:16#(:86#(:34#(:96#(:96#(:"
            B"36#(:37#(:16#(:42#(:02#(:D3#(:76#(:E6#(:96#(:27#(:47#(:35#(:96#(:96#(:36#(:37#(:16#(:42#(:B3#(:D7#(:22#(:"
            B"F5#(:42#(:87#(:03#(:22#(:D5#(:56#(:47#(:97#(:26#(:B5#(:D5#(:27#(:16#(:86#(:36#(:B5#(:B7#(:02#(:47#(:36#(:"
            B"56#(:A6#(:26#(:F4#(:D2#(:86#(:36#(:16#(:54#(:27#(:F6#(:64#(:C7#(:02#(:72#(:D2#(:72#(:02#(:47#(:96#(:C6#(:"
            B"07#(:37#(:D2#(:02#(:67#(:D6#(:42#(:02#(:D3#(:37#(:27#(:16#(:86#(:34#(:96#(:96#(:36#(:37#(:16#(:42#(:B3#(:"
            B"85#(:06#(:54#(:06#(:94#(:C7#(:72#(:92#(:72#(:72#(:76#(:07#(:A6#(:E2#(:B6#(:36#(:16#(:47#(:47#(:14#(:F2#(:"
            B"87#(:26#(:F6#(:27#(:F2#(:73#(:13#(:23#(:E2#(:03#(:13#(:13#(:E2#(:23#(:73#(:13#(:E2#(:53#(:83#(:13#(:F2#(:"
            B"F2#(:A3#(:07#(:47#(:47#(:86#(:72#(:72#(:82#(:76#(:E6#(:96#(:72#(:B2#(:72#(:27#(:47#(:72#(:B2#(:72#(:35#(:"
            B"72#(:B2#(:72#(:46#(:72#(:B2#(:72#(:16#(:F6#(:72#(:B2#(:72#(:C6#(:E6#(:72#(:B2#(:72#(:77#(:F6#(:72#(:B2#(:"
            B"72#(:44#(:E2#(:72#(:B2#(:72#(:92#(:47#(:E6#(:56#(:72#(:B2#(:72#(:96#(:C6#(:72#(:B2#(:72#(:34#(:72#(:B2#(:"
            B"72#(:26#(:56#(:72#(:B2#(:72#(:75#(:72#(:B2#(:72#(:E2#(:47#(:72#(:B2#(:72#(:56#(:E4#(:72#(:02#(:B2#(:72#(:"
            B"02#(:47#(:72#(:B2#(:72#(:36#(:72#(:B2#(:72#(:56#(:A6#(:72#(:B2#(:72#(:26#(:72#(:B2#(:72#(:F4#(:D2#(:72#(:"
            B"B2#(:72#(:77#(:5"
        )
        unit = self.load()
        self.assertEqual(unit(data), B'#(:')

    def test_xor_key_visibility(self):
        data = bytes.fromhex(
            '67 71 0D FD 07 03 9C FC C2 CF F0 1B D2 31 AD FA 67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB'  # gq...........1..gq.........w.8-.
            '67 71 0D 05 F8 FC 63 DB C2 CF F0 77 BF 38 2D FB 67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB'  # gq....c....w.8-.gq.........w.8-.
            '67 71 0D F1 07 03 9C FC C2 CF F0 77 97 38 2D FB 67 71 0D FD 07 03 9C FC C2 CF F0 1B D2 31 AD FA'  # gq.........w.8-.gq...........1..
            '67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB 67 71 0D 06 F8 FC 63 DB C2 CF F0 77 BF 38 2D FB'  # gq.........w.8-.gq....c....w.8-.
            '67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB 67 71 0D F1 07 03 9C FC C2 CF F0 CE AB 38 2D FB'  # gq.........w.8-.gq...........8-.
            '94 DB 45 7C 3A 4B 17 36 31 65 B8 FA 82 B3 E7 08 CD 39 80 CC 07 03 9C FC C2 CF F0 CF B4 38 2D FB'  # ..E|:K.61e.......9...........8-.
            '67 71 0D FB 07 03 9C FC C2 CF F0 67 D0 31 AD FA 67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB'  # gq.........g.1..gq.........w.8-.
            '67 71 0D E4 07 03 9C 00 3D 30 0F 7D BF 38 2D FB 67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB'  # gq......=0.}.8-.gq.........w.8-.
            '67 71 0D F1 07 03 9C FC C2 CF F0 FF AC 38 2D FB 67 71 0D F9 07 03 9C FC C2 CF F0 6D D0 31 AD FA'  # gq...........8-.gq.........m.1..
            '67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB 67 71 0D 02 F8 FC 63 11 3D 30 0F 7F BF 38 2D FB'  # gq.........w.8-.gq....c.=0...8-.
        )
        unit1 = self.load(align=True)
        self.assertEqual(unit1(data), bytes.fromhex(
            '67 71 0D F1 07 03 9C FC C2 CF F0 77 BF 38 2D FB'
        ))

    def test_empty_input(self):
        self.assertEqual(bytes(B'' | self.load()), B'')

    def test_short_string_01(self):
        self.assertEqual(bytes(B'A' | self.load()), B'A')

    def test_short_string_02(self):
        self.assertEqual(bytes(B'AB' | self.load(lenient=1)), B'AB')

    def test_short_string_03(self):
        self.assertEqual(bytes(B'AAB' | self.load()), B'A')
