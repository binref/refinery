import base64
import lzma

from ... import TestUnitBase


class TestPECdB(TestUnitBase):

    def test_simple_example(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;02!oOI-jc63%b{7x(N1yXy4+lmRb9?{m8r!)Q?OIU!U#wA;j)J2q={q#aT~Ed&!Qr$#T#'
            'wRwl?-gs){cd>pEfbc?VA%!eta(DRX16*KI%Yv}>+xI9?hmV}Y>2o5Kf*P_Rn{+0)KlUUx0f0*jLKdJ>{&C`>ot8@Vc6dfYF+Rvx'
            '1Q~mX=xGuhUaUn4kdZN%(Pq8b2i`?pKVBM2J_zTReyM$0NQ75)=nc{8-A?hv{bPKAttvo<S<l5lpEF3CFuLJJK;VDS#@&GcXhLT!'
            'No42WH@RhA-n{{5$7^{F9j2Cfirg{pXmY5CUXV46DH8HEShPMWBhAD=ibkH5I62HP8w9~fwLiV}?5k<u2XDz4t=w=u^Y*a>{o>Z#'
            '#L|hrfI`pqH9(~<{Eq*DX94BKDQA0W0=jSwj_BEOcogjpcht66?jZpt{XPt>;j|V`W4C;|uzV3rs90vr8SKzp|C61hfdJ6^RCZq5'
            'tRVyUbw?wLu+|wM_O0off5im}6JVo>PDOoZRUAnu=6~BAkbkKHBpW_>-qRL<;PaWqtPCCICNSs!8mr96s#XB8K4$Nft-z|4xq&q<'
            '(kINGGqDb%Le;gqmVAqe6r(9aj>CdXy=bet7byWOmx@$&Vm-@CYL$!{hx#SgR%LduL;yXo^ux3%G3=B?NyR8J#gh~+9$^OcPW-S9'
            'gcnuQ$!zD~ADFlKrCc61YV?=DbD9%MGT#hgeYi~!jYOO^>;o@R!RFBbd=U)O4u9>KyF{MOyl?;jxeqfk1Jmkk00HL&pbG#1!>_7*'
            'vBYQl0ssI200dcD'
        ))
        goal = lzma.decompress(base64.b85decode(
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
        test = data | self.load(unmap=True) | bytes
        self.assertEqual(test, goal)
