#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestMetaPushPop(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [| push | snip :4 | pop oof | nop | ccp var:oof ]')
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_02(self):
        pl = L('emit "FOO BAR" [| push [| snip :4 | pop oof ] | nop | ccp var:oof ]')
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_03(self):
        pl = L('emit "FOO BAR" | push [[| snip :4 | pop oof ] | nop | ccp var:oof ]')
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_variable_in_modifier(self):
        pl = L('push [[| pop x ] | cca cca[cca[var:x]:Q]:T | rev ]]')
        self.assertEqual(pl(B'x'), B'xQTx')

    def test_variable_outside_modifier(self):
        pl = L('push [[| pop x ] | cca T | cca var:x | rev ]')
        self.assertEqual(pl(B'x'), B'xTx')

    def test_push_pop_in_frame(self):
        pl = L('rex . [| push [| pop copy ] | swap copy ]')
        self.assertEqual(pl(B'foobar'), B'foobar')

    def test_pop_discard(self):
        pl = L('emit A B C D E [| pop a b 2 | cca var:a | cca var:b ]')
        self.assertEqual(pl(), B'EAB')

    def test_nested_push_pop(self):
        pl = L('emit FOOBAR [| push [| snip 3: | push [| snip :1 | peek | pop a ]| cca var:a | pop b ]| ccp var:b ]')
        self.assertEqual(pl(), B'BARBFOOBAR')

    def test_multiple_pops(self):
        data = B'$a = "foo"; $b = "bar"; $c = "baz"; decode-decode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", $a, $b, $c)'
        pl = L('push [[| carve -dm5 string | pop foo bar baz ]| carve -sd string | cfmt {foo}-{bar}-{baz}-{} ]')
        result = pl(data)
        self.assertEqual(result,
            B'foo-bar-baz-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
