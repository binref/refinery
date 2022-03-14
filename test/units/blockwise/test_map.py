#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestInstrumentationWithMap(TestUnitBase):

    def test_conflicting_arguments(self):
        with self.assertRaises(ValueError):
            self.load(
                'commandline index',
                index=b'keyword index',
                image=b'keyword image'
            )

    def test_missing_arguments(self):
        with self.assertRaises(ValueError):
            self.load(index=b'lonely argument')

    def test_map_only_keywords(self):
        mp = self.load(index=b'es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')

    def test_map_commandline_and_one_keyword(self):
        mp = self.load('es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')

    def test_map_duplicated_but_matching(self):
        mp = self.load('es', index=b'es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')

    def test_map_blocksize2(self):
        index = (
            B'OCRUIJUFWBUKTMREYLWXOXOETERXEPPIWKEGOWYFTJPXRMQUTPTVUIPRQHQXIWOJ'
            B'ESTLEKIDIGENYZICRIWCPSORITWETIECUQYBUATUTGYAWDUBTHQVOATKOKPZOVWW'
            B'QJTXYMTZOBRRQWOSQEEAIUEDRGOIYRQSOUPQQZTFOHRLOLEEPGQRTCRQQPRNIIRK'
            B'UJRWIVWMEJEMEOTTWHIQUXUCYWUVWPEXEWRCQGIXUOIMYIEHEQUSPJWOYGEVYUOT'
            B'YXIHIPWNUMYDPKOGUTYVOOQIUDQAUURTOYEFQKYYWQIBTNPYILURPFTBRAQNIKRS'
            B'QFOPRHQTQCQMTRPPWIYKYJEYPHWJELWSTAISPOWFIORBIAUPQYRFUZWYRDETROPD'
            B'QOWGYHOMEZYSOZUYTOPWRPEBYCTDIEWZIRPLWRTYIYWTUNYPRZRJWVEIERYOPERV'
            B'UEPUWUQQPTPAEUONIFYQPCTQUHYNQDOFODOQWLYERYIZUGQBYTTSUWQLWAULINTW'
        )
        data = (
            B'EAQEOSIXEOIXEMEJTTEOIXIXEJESPZESOHIQUVEMQGRIWCOXQWEXQGESWHUXEJQE'
            B'IUOSTXTFOBQWESPZESYBESUOEXESUBOXEETFWMQGIQEWUOTITFYWEMEMEWESYBUQ'
        )
        unit = self.load(index=index, image=range(0x100), blocksize=2)
        out = str(data | unit | self.ldu('u16'))
        self.assertEqual(out, (
            'IHGsfsedgfssd = Timer()\n'
            'For hjdHJGASDF = 1 to 7\n'
            'WScript.Sleep 10'
        ))
