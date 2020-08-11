#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lzma
import base64

from ... import TestUnitBase


class TestJavaStrings(TestUnitBase):

    def test_unicode_strings(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~@^T23-JUKa)$~28$(3C<8TI6W6wvlf6<T4!N!BZsi#ukVZ>AI4iG5KiyR}^*gorX6y2>XI-*_ItE#J>Qo&(rq<uP'
            'C45JKGO$LqRS})vmFMJt)9Ai$4XiGEZL5&{<c-p(E1}zyjm?ssu7vl9m=#j|X3zF%xH6uwM>bn%8hhUd=`0IsAy>!UJJ|g!v<IcI<mU+U*v55_Jw;;kCJ-VV'
            'p!$b%aUNjC#;+&(BFr5|Lg3Yj-Z0v6#u2RGs_5&~>BE+SuXPp3L7gv0pq1JnPZoAQYmXd$Ul)9(qbNWum&8$x^e?SPwIlk(O8auD-R4}F-i)>iR(rDn3O)_?'
            'Sm`k)=Z~#01ceYtH#V@SGEd(txfU1}x7fhY!GsSL)kc#&8O31ZA}%JV(5rFk%aa?rZljnm8rd=;xj(>S=$=bgakC>8aA$0Q77ZFci0AX&JH+m)le+HaUYafM'
            ';3w*Boj}o&igmwbM%s6-dLW$}Aig}t=7`3w>#?#=XJT0?FKKaAJfTl53@T*NKP>+7KA#xn;EkL$0LRi{8nFY7T81&OQ>dR{h6!{fT1gu>`=W7vAJn}(kb5`n'
            'O6(Mb-wF&#v#-jD%{of~gAJpV0OV$4hn3vv1oTW5@c&2^@ixL2sP~<TBi>q7C@_ggu&ZlJcMxE?Ab(KS!=_p|eWtV?SD66+2-wuQAZgCCH|=7TmxddySi!%W'
            '4FQt(*S~R>lFvAupz2m(MGp}pkK;J`(!nD~My`r224L{yo}~Qc87R=odBm;|X!4Eglau?W@IZp@vztTFOQQZOPm~+xSuyp{ks!{R6umDZ1Aj@*e>ue5v0VDh'
            'pD&L#_2~b~)o>XXj}#ZVqRS5pZ2mO9`jiyn$!_Si1hf9;2qHmnf+dS84Mt6x2La+^vTv?tckRRE>AVOp>Kj<z42*#6jA@!T+&81aj`+DO+8f!ySE4cju-rR{'
            'RKOX5WgaBFEf>tkHhP~%*^Ib>61=O6`iyHJB~tLtFJajHp8x;=aXGLm+C``f00E)~iwOV#Et^O!vBYQl0ssI200dcD'
        ))
        unicode_strings = {
            'Бинарный НПЗ?',
            'バイナリ製油所？',
            '바이너리 정제?',
            '二元煉油廠？',
            'مصفاة ثنائية؟',
            'बाइनरी रिफाइनरी?',
            'Binäre Raffinerie?',
        }

        unicode_strings.add('B̘̥̦̣͇̩̱͎̱͑̿̇̅͂ì̢̬̲̪̯̼̠̉͂̾͋͢͢ṋ̷̡̯̰͖͎̲̋̄͌̒͊̍͑̽͛ą̶̮̗̱̗̥̜̙̞̋̑́̀͐̓͋́̇̆r̶̟͇̬̺̙̝̻̪̥̙̽͊͋̔̍̾̒̄y̗̞̠̬̭̖̼̠̣͐̆͂͗͗̀͞ R̻͍̭͚͍̭̤̜̽̿̄́͡é͕̝͚̻̙̤͌̊̇͆͆̆̊͠f̷̨͓̜̣̜͐͛̿̌̉̋̎͜͜ḯ͚̩͈̮̫́̃͂̀͞ǹ̢̫͔̞̝̝̯̼̊̍͗͗̽̽́̿͜͜ẻ̸͚̮̝͎͖̜̻̙̀̔̆̅̆̔̊͞r̸̢̢̻̣̠̈́̂͛̓͋̍̾̌̕͟y̥̖͖̦̼̱̼̜͍͛́́͊͆̐̍̚͠͞') # noqa

        unit = self.load()
        self.assertSetEqual(unicode_strings, {
            t.decode('utf8') for t in unit.process(data)})

    def test_unicode_supplementary(self):
        unit = self.load()
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~#^vvRwdWKa)$~28$(38#OdRHxeuijMLw>btNxXh;P<?yY+wO1PBB`M>Oo1f8sf2E2)P)r}XMmIr?A^{D+2YMD8Cs'
            '9&w0MFxg7;Otb#O!X%A37>l$=!|uUg5DiiDHzPR%p(-zbD^RT0xH;2hy!gvSa)w5_lPYWzwz|e53g!32;V&d`!2^txwAO9bcG(Nj)s^#YVGFyfLqpf5GGY~c'
            'XpUr~t_^$c24H9YKh#43d^am}4>A$CELfmzq7>H14(S}&4Rvt-cB6gk7JhYh9QbeM)_#uq=A$ZQ7X2paOQOen?gxiKd8`A3##t>Or|o9e5%H&yOkfGnoK|ln'
            '7#s62MWyjXYZ1&Hrb`W|8>=mpZY=Q4DogP4J0T<q@oM6x3LhrjNpZ+r0U3fi${e!7$(k^@8eg_S=j^iksdEJ3W!|V$;d4}mt4it@T7$np5fuMxFUOogoFX3f'
            'Q88r=mKEFa0rOPTM^C<Eg3oNBAPVr`i-T3Pm`cVeLSxeB(pid4o<8KF&5*{rZ8DM{U~f{jX?KjSdZ(akKNSNv*y+6aD!ptD|6ZQqB>(^b*{P94o{+z`00GVe'
            'fCc~nKpVqGvBYQl0ssI200dcD'
        ))
        self.assertIn(
            '𠜎𠜱𠝹𠱓𠱸𠲖𠳏𠳕𠴕𠵼𠵿𠸎𠸏𠹷𠺝𠺢𠻗𠻹𠻺𠼭𠼮𠽌𠾴𠾼𠿪𡁜𡁯𡁵𡁶𡁻𡃁𡃉𡇙𢃇𢞵𢫕𢭃𢯊𢱑𢱕𢳂𢴈𢵌𢵧𢺳𣲷𤓓𤶸𤷪𥄫𦉘𦟌𦧲𦧺𧨾𨅝𨈇𨋢𨳊𨳍𨳒𩶘',
            (t.decode('utf8') for t in unit.process(data))
        )
