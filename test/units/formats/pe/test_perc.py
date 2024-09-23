#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import lzma

from ... import TestUnitBase


class TestPEResourceExtractor(TestUnitBase):

    def test_multiple_languages(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;00d-H(dZGmX2@$7x(N1yXy4+lmRb9?|kO<vP*ab%hBk2*4duIK3@A#<HS^yNUr@QB3IS!I@6kjBA~v!H|gf@-hxx;'
            '@6YTZG|&M~wgKn!%I*wV!aq4G6uGTBJ+@aMEQoX?*gV)Bsas7D_9$5g+;6gQE17{rFhMS0h~+7&k-z_sHpQk}|5c-dR;&a;?%kdaiBY=@u)6}{)Vx0yof|Z#'
            '8MX3?R37D<UdE~o;qqM42lC4wY9JaF2J4<mkugblgS(&h0V|UqBOg}2-Qk5bE^^|2Sl-Rg9TKSem(4#NwibQ}O$?jEd4JDt(<hsAVjwH9=tQAg)s*k&sLV&7'
            'iH*gn41;t#ya!jz|C^lK0Z9!6HXK`6W#~!R=n$#f&KBT`ZZmWEdaXX@N5s%#K&tHKK(+2|Vu$yh@2^%Nn(HvNVzp&R$-GWct17mwaZl6!d9`bBbxXQeLorPi'
            'b%&fq4fgvFKCGtr42|3uaafysBdsyO`AM#|3C)jkdJPQD&wr~yz)m3bqHJtxbvG)t0s|y9RZ3>qib@v+FZ0Krl#Z=xm68#^4<2x-KA+fto^ofJ7JaZ0rMpcI'
            'qxW5rlkp%{CcH%E!A*j4ii3^XWCfOg%Ta0|KC=T?y28wG965@olvKa*!Am6*Zq&pwkmsQsx4#TITkeeOh<xK0(-K8`?3jw^2Yejbfo0uPaa1?joE=qH{l(Bu'
            '{!2*3&^G^4;CoYD0puPd1Cft_00000E-2b@59d+q00Gkk;0gc$a@d!7vBYQl0ssI200dcD'
        ))
        unit = self.load(list=True)
        result = data | unit | []
        result.sort(reverse=True)
        self.assertSequenceEqual(result, [B'STRING/7/7', B'STRING/7/1033'])

        self.assertSetEqual({c['lcid'] for c in result}, {b'German (Austria)', b'English (United States)'})

        unit = self.load('*1033')
        result = data | unit | bytearray
        result = result[12:44]
        self.assertEqual(result, 'Binary Refinery!'.encode('UTF-16LE'))

    def test_pretty_icon_extraction_01(self):
        data = self.download_sample('e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384')
        prefix = bytes.fromhex('00 00 01 00 01 00 20 20 10 00 01 00 04 00 E8 02 00 00 16 00 00 00')
        t1 = next(data | self.load('ICON', pretty=True))
        t2 = next(data | self.load('ICON', pretty=False))
        self.assertEqual(prefix + t2, t1)

    def test_pretty_icon_extraction_02(self):
        data = self.download_sample('d68f0ed81b6a19f566af1c00daae4a595533a743671dc9d23303b5b81cd90006')
        prefix = bytes.fromhex('00 00 01 00 01 00 10 10 00 00 01 00 20 00 68 04 00 00 16 00 00 00')
        t1 = next(data | self.load('ICON/1', pretty=True))
        t2 = next(data | self.load('ICON/1', pretty=False))
        self.assertEqual(prefix + t2, t1)

    def test_pretty_bitmap_extraction(self):
        data = self.download_sample('d68f0ed81b6a19f566af1c00daae4a595533a743671dc9d23303b5b81cd90006')
        prefix = bytes.fromhex('42 4D 2E 42 01 00 00 00 00 00 36 00 00 00')
        t1 = next(data | self.load('BITMAP/103', pretty=True))
        t2 = next(data | self.load('BITMAP/103', pretty=False))
        self.assertEqual(prefix + t2, t1)
