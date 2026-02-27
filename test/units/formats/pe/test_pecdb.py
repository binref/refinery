import base64
import lzma

from ... import TestUnitBase


class TestPECdB(TestUnitBase):

    def test_simple_example(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;02!oPF(;dmX2@$7x(N1yXy4+lmRb9?|kO<vP*ab%hBk2*4duIK3@A#<HS^yNUr@QB3IS!'
            'I@6kjBA~v!H|gf@-hxx;@6YTZG|&M~wgKn!%I*wV!aqJxA!XjFsQ6)D0iou~C=M`*=jR!dWZAbvyt&MOfyb_u3+P2VQKM!Qx8(Ds'
            '`-^O}WwsH7XU$7cX3Y^7>xu)+{kSE+c~ePa(OU#%Q9nxlZA`s3;?;<kAxDLd1e7{JTVIAK(4<8W#$;Q%)gxG@HfliS?=Z<vhZ(~{'
            '2JUFw>aj|o0WjCsawiq88bg)-$!=op<W4VIl}=qUS?1sI+WMnff^>4=mJ7X8)rhagdA~=MIsT3nN)c|=cWZZ9xe>V+=&eA*&f6C#'
            'noZs)gJtt94V6cWAhg#$wmuHO>q*uah)~%+);89j8<Pu>jjv-0zek2y3&Y~;MyLwZ0~%EZCo6hR!hG%gLgg&1O6-3!Hy8oN0y9FR'
            'ByJN$u#e?rU{tK3Y9AM>gsi^ae1Lp%@+zEpEIBCP>{qy*jqHNtbRNgqq(>r2LyaFq)Ow%CwLl=F=$K3PI>kFxbA$@PUyE{EJ6JXV'
            'YSg~MP_*A3u(r|Mjx+^)rfcFB1N_olRV#SvUK0{-{HzOVUA@a16i<>jhl3-8PetoOj7TxkF|{_tWE7xuCcU&Bf)YYT>T|TmNSQWL'
            'pcKMZD%orB(8!H#r_sYlf#wSrz(AqAK|=nFIf}DNr>Yux=VSo}sV!HBN7#LUK7C=|Yrv@`_}CHrbN~PVz!+*;)c8#u00HU*pbG#1'
            '9lSKavBYQl0ssI200dcD'
        ))
        test = data | self.load() | bytes
        self.assertEqual(test[:0x126], data[:0x126])
        self.assertEqual(test[0x128:], data[0x128:])
        self.assertEqual(test[0x126:0x128], B'\0\0')
