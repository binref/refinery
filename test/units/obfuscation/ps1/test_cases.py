#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestNameCases(TestUnitBase):

    def test_set_variable(self):
        self.assertEqual(
            self.load().process(b'SET-vaRIabLE'),
            b'Set-Variable'
        )

    def test_real_world(self):
        self.assertTrue(
            b'Set-Variable' in self.load().process(
                br'''&('set-varIAbLE') gHc7R6XtR8aE 16;.('SET-vaRIabLE') PkfYKFVSBTmn 27;.(.    ({2}{0}{1}-f'c','m','g')    ({4}{2}{3}{0}{5}{6}{7}{8}{6}{9}{1}{2}-f'-','l','e','t','s','v','a','r','i','b')) EUCsMplIyR03 43;&(&({0}{1}{2}-f'g','c','m')"seT-VARiaBLe") F8riv8rRCqrK((((&"get-vARiaBle" gHc7R6XtR8aE).('vaLUE')+29)-AS[chaR]).('tOsTrinG').iNVoke()+(((."GeT-VaRIAblE" PkfYKFVSBTmn).({4}{2}{0}{1}{3}-f'l','u','a','e','v')+74)-as[CHAR]).('tosTrInG').INVOke()+(((&"gEt-VarIabLe" EUCsMplIyR03)."VaLUE"+56)-as[cHAr]).({4}{2}{5}{4}{3}{1}{0}{6}-f'n','i','o','r','t','s','g').INvOke());PowERsHELL -NONiNtErac -nOLOgo -NOP -Windows HIDDEn -ExEC BYpasS (    .({7}{4}{9}{0}{2}{3}{1}{6}{3}{5}{8}{4}-f'-','r','v','a','e','b','i','g','l','t') F8riv8rRCqrK).({4}{3}{1}{0}{2}-f'u','l','e','a','v')    .({5}{2}{6}{5}{4}{0}{1}{3}-f'i','n','o','g','r','t','s').iNvokE()'''
            ),
        )
