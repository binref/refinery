import base64
import lzma

import pytest

from .. import TestUnitBase
from .test_pcap import _PCAPNG_SAMPLE


class TestTCP(TestUnitBase):

    @pytest.mark.xdist_group(name='pcap')
    def test_flaron11_challenge7(self):
        goal = [bytes.fromhex(p) for p in [
            '0a 6c 55 90 73 da 49 75  4e 9a d9 84 6a 72 95 47'
            '45 e4 f2 92 12 13 ec cd  a4 b1 42 2e 2f dd 64 6f'
            'c7 e2 83 89 c7 c2 e5 1a  59 1e 01 47 e2 eb e7 ae'
            '26 40 22 da f8 c7 67 6a  1b 27 20 91 7b 82 99 9d'
            '42 cd 18 78 d3 1b c5 7b  6d b1 7b 97 05 c7 ff 24'
            '04 cb bf 13 cb db 8c 09  66 21 63 40 45 29 39 22',
            'a0 d2 eb a8 17 e3 8b 03  cd 06 32 27 bd 32 e3 53'
            '88 08 18 89 3a b0 23 78  d7 db 3c 71 c5 c7 25 c6'
            'bb a0 93 4b 5d 5e 2d 3c  a6 fa 89 ff bb 37 4c 31'
            '96 a3 5e af 2a 5e 0b 43  00 21 de 36 1a a5 8f 80'
            '15 98 1f fd 0d 98 24 b5  0a f2 3b 5c cf 16 fa 4e'
            '32 34 83 60 2d 07 54 53  4d 2e 7a 8a af 81 74 dc'
            'f2 72 d5 4c 31 86 0f',
            '3f bd 43 da 3e e3 25',
            '86 df d7',
            'c5 0c ea 1c 4a a0 64 c3  5a 7f 6e 3a b0 25 84 41'
            'ac 15 85 c3 62 56 de a8  3c ac 93 00 7a 0c 3a 29'
            '86 4f 8e 28 5f fa 79 c8  eb 43 97 6d 5b 58 7f 8f'
            '35 e6 99 54 71 16',
            'fc b1 d2 cd bb a9 79 c9  89 99 8c',
            '61 49 0b',
            'ce 39 da',
            '57 70 11 e0 d7 6e c8 eb  0b 82 59 33 1d ef 13 ee'
            '6d 86 72 3e ac 9f 04 28  92 4e e7 f8 41 1d 4c 70'
            '1b 4d 9e 2b 37 93 f6 11  7d d3 0d ac ba',
            '2c ae 60 0b 5f 32 ce a1  93 e0 de 63 d7 09 83 8b'
            'd6',
            'a7 fd 35',
            'ed f0 fc',
            '80 2b 15 18 6c 7a 1b 1a  47 5d af 94 ae 40 f6 bb'
            '81 af ce dc 4a fb 15 8a  51 28 c2 8c 91 cd 7a 88'
            '57 d1 2a 66 1a ca ec',
            'ae c8 d2 7a 7c f2 6a 17  27 36 85',
            '35 a4 4e',
            '2f 39 17',
            'ed 09 44 7d ed 79 72 19  c9 66 ef 3d d5 70 5a 3c'
            '32 bd b1 71 0a e3 b8 7f  e6 66 69 e0 b4 64 6f c4'
            '16 c3 99 c3 a4 fe 1e dc  0a 3e c5 82 7b 84 db 5a'
            '79 b8 16 34 e7 c3 af e5  28 a4 da 15 45 7b 63 78'
            '15 37 3d 4e dc ac 21 59  d0 56',
            'f5 98 1f 71 c7 ea 1b 5d  8b 1e 5f 06 fc 83 b1 de'
            'f3 8c 6f 4e 69 4e 37 06  41 2e ab f5 4e 3b 6f 4d'
            '19 e8 ef 46 b0 4e 39 9f  2c 8e ce 84 17 fa',
            '40 08 bc',
            '54 e4 1e',
            'f7 01 fe e7 4e 80 e8 df  b5 4b 48 7f 9b 2e 3a 27'
            '7f a2 89 cf 6c b8 df 98  6c dd 38 7e 34 2a c9 f5'
            '28 6d a1 1c a2 78 40 84',
            '5c a6 8d 13 94 be 2a 4d  3d 4d 7c 82 e5',
            '31 b6 da c6 2e f1 ad 8d  c1 f6 0b 79 26 5e d0 de'
            'aa 31 dd d2 d5 3a a9 fd  93 43 46 38 10 f3 e2 23'
            '24 06 36 6b 48 41 53 33  d4 b8 ac 33 6d 40 86 ef'
            'a0 f1 5e 6e 59',
            '0d 1e c0 6f 36',
        ]]
        pipeline = self.load_pipeline('pcap [| tcp ]')
        test = _PCAPNG_SAMPLE | pipeline | [bytes]
        self.assertEqual(test, goal)

    @pytest.mark.xdist_group(name='pcap')
    def test_stream_labels(self):
        pipeline = self.load_pipeline('pcap [| tcp ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(chunks[0]['src'], '192.168.56.101:49848')
        self.assertEqual(chunks[0]['dst'], '192.168.56.103:31337')
        self.assertEqual({chunk['stream'] for chunk in chunks}, {0})

    @pytest.mark.xdist_group(name='pcap')
    def test_per_packet_meta_not_inherited(self):
        pipeline = self.load_pipeline('pcap [| tcp ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        for chunk in chunks:
            self.assertNotIn('time', chunk.meta)
            self.assertNotIn('link', chunk.meta)

    @pytest.mark.xdist_group(name='pcap')
    def test_merge_produces_two_directions(self):
        pipeline = self.load_pipeline('pcap [| tcp -m ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 2)
        directions = {(chunk['src'], chunk['dst']) for chunk in chunks}
        self.assertEqual(directions, {
            ('192.168.56.101:49848', '192.168.56.103:31337'),
            ('192.168.56.103:31337', '192.168.56.101:49848'),
        })

    @pytest.mark.xdist_group(name='pcap')
    def test_client_only(self):
        pipeline = self.load_pipeline('pcap [| tcp -mc ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]['src'], '192.168.56.101:49848')

    @pytest.mark.xdist_group(name='pcap')
    def test_server_only(self):
        pipeline = self.load_pipeline('pcap [| tcp -ms ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]['src'], '192.168.56.103:31337')

    @pytest.mark.xdist_group(name='pcap')
    def test_client_server_direction_from_handshake(self):
        client = self.load_pipeline('pcap [| tcp -mc ]')
        server = self.load_pipeline('pcap [| tcp -ms ]')
        c = list(_TCP_VNC_SAMPLE | client)
        s = list(_TCP_VNC_SAMPLE | server)
        self.assertEqual(len(c), 1)
        self.assertEqual(len(s), 1)
        self.assertEqual((c[0]['src'], c[0]['dst']), (
            '192.168.122.89:52902',
            '192.168.122.1:5999',
        ))
        self.assertEqual((s[0]['src'], s[0]['dst']), (
            '192.168.122.1:5999',
            '192.168.122.89:52902',
        ))

    @pytest.mark.xdist_group(name='pcap')
    def test_client_server_direction_without_handshake(self):
        client = self.load_pipeline('pcap [| tcp -mc ]')
        server = self.load_pipeline('pcap [| tcp -ms ]')
        c = list(_TCP_GIT_SAMPLE | client)
        s = list(_TCP_GIT_SAMPLE | server)
        self.assertEqual(len(c), 1)
        self.assertEqual(len(s), 1)
        self.assertEqual((c[0]['src'], c[0]['dst']), (
            '10.0.2.15:49188',
            '147.75.58.133:9418',
        ))
        self.assertEqual((s[0]['src'], s[0]['dst']), (
            '147.75.58.133:9418',
            '10.0.2.15:49188',
        ))

    @pytest.mark.xdist_group(name='pcap')
    def test_get_request_summary(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = self.load_pipeline(R'pcap [| tcp | rex "^GET\s[^\s]+" | sep ]')
        result = str(data | pipeline)
        self.assertEqual(result, '\n'.join((
            'GET /286//update.txt',
            'GET /286/soft/163.exe',
            'GET /286/count/count.asp?mac=00-0E-0C-33-1C-80&ver=2007051922&user=00&md5=258a993832e5f435cc3a7ba4791bc3de&pc=BOBTWO',
            'GET /mh.exe',
            'GET /286/pop.asp?url=http://www.puma164.''com/pu/39685867.htm?2',
            'GET /favicon.ico',
            'GET /12.exe',
            'GET /286/pop.asp?url=http://59.34.197.''164:81/804635/adx352133.asp',
        )))


_TCP_VNC_SAMPLE = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;1VDXm|XyBFww|;i}(qf'
    'uOG~L1Q*|5W;TY$&5#F94_ydhg0nep@~do7%Fyt(L&zYipEk}C'
    'v>%-uZSD+_Mu}e6Dwa`jT>l7RIC=wT<gZj#<Ls3)Eox&Rx006{'
    'inMd@4~kSmVM)lA&bf#i?lWef|2ojiamK=j_2`B8W+8m^SwJo|'
    'i>Pf_x)N}OFNfrU8BBr8eQqN_!dQtpt%NKbJ7M$|&w%x+wwe@o'
    'm`!dK|5nFyv{O6{2ABSJJDV^d5AAlju0{2h>CiZrEXkHO6SRbs'
    'oQ#?>TL6-98-a_fo%Ode*HrgoC;9-Pt~Bb=jAN@%?e}#*%=NqY'
    '0uiunst@BOkQ4DJ;yqktS$M&HP7hQM#~T2dtC;*SuI_+>Im>M-'
    '`o^+N$8UzCpfl#3KJ#l7PX8$SEc_5K3t&c#IHHJknp=W!ai_?Z'
    'qL4@5w)8z!n{pV`a)(hOPu^d^ka4?9&C)uPQ{;n<E*M`N$<Nog'
    '8a4ptZlu{?A>ZG&uJJ~_FWkxk%#$xVA|1YQaaHEx@6j)HP5;Pk'
    '%9H~ztl&AB5tS(b#ww8AomM_o73mx#rfFZf5fz*ilbzp{MTBJD'
    'euXXeY^YCEQ@@P=ni)_pZ++q0o0WwL&O76DAwOzKamq6hb{VIO'
    '=GFTfy0Hh|oIAe$P)^aHJzKvK5ll$a(_t`+-g12d$t`Erz#3rv'
    'e%7+fHe~MUFT<Ljzz-UsYBEVIg3$mm66x3E9461Z0vx}vn;sU&'
    'gOC2+)}Jek<kGDOl(0H@rJ)4ByD8c$5ZIK1_a$7EoV}AB<A_0j'
    'c^Jv%>covMufq=WxEh62t{_FL=JYn7iv;&cnkh^xG|SB}R<5%<'
    'ezxaRaHp?Q;1f_#r64+$CVbpH!vrn`o9M<0RBQnG(L{32wVt@>'
    '$98G-9~sT9&oz_AXrZSw@-)1r$LHG*bpHm^RQXD#M`ZDuTlleE'
    'r|x{Vj3Y<$FH$^nAp-q``iXv4M`|_+HMFQt*~HFid9$w`ynAE?'
    'vOTE=kw1l-HeMS}6(}9c$@(hcx1jV2$G8g<0QRxFmM3!92sh~Q'
    'FgFBQ%oOH2Y0J0$kYQ~*R&cQ}@TQD<lAa}^PLq_*T^yP?qPc2C'
    'MYU<k%gIzhhL(YWX7qLVK()nA#a=*=Y0~O63k!Y*-^I_|5_z{f'
    'n6we3Z=B__C3W0oNvNpFFKT=<F{*K|3d9ilaY{)+h>t`WpvQeL'
    '_jTY8r%Lg?!3xl5O{YEH!>Q8Mm$u>PnYhd3&A=bGP9yT{Uq!^-'
    'VrV$p?(dv1mOQ1>_l_Cu?@_VBDY;{|KoofZNU~{KkcDUvDxN?%'
    'yIvLMmpf2kR^3xsfq`o@58iV^k2`XztYh3!Mx!B#j#aU1x6Mw}'
    '=h#V^sY4De;Ct?i#ez0%eFUqcYkpm{_JH8(N1W0hDp<OD-+)FS'
    '1-x&#55FCWkWN~oM@v99!UyiDA(9MI{6|mie4b@XT#Mqz$+~VL'
    '6Ii`hYIDr1f84$SNXeF3dm@=aKk_DENn>T}H51=lTlCMAtu|wy'
    '<i98+y>>;bB{@y}0(-)6F`UrH+erNzQ<KHF!*}V!UH&~%_T1xk'
    'xx?*Ka7T-u)3vM^!_p=lS!O3#(YFH)83XJTSlFOG)^}Ts0MG5X'
    '5rf&yoi2_{@cpFsL;J36C4G*Q@Y)7GO@)df<NGDhPUFvWRA*tu'
    'tw&L=352N8B4$ikOmDK@^SkW14{)ySfh_9x+5(Ek?0oHw1^Ck@'
    'yh5yX_rb*zv6YJq<Z$KWqMLUiG(R2o+}BQWx(fn>9ilqkjgfzO'
    'M)-xE`QJi!3DEU+xt+waGxSDyv!tl<?|9q8YBq{4s(kvUZ+5Tb'
    'u{I)zOHgzxlxUKbLsJU`#@>Fc_<uX*-r}U+&idL{xTgXRf5LgX'
    ')~VqsRQ(v}@Ealf+~My(QQ?b=jYgfoj4v-Jyy-`1V*mrxN~2hT'
    'UU!zBFP`uvc~~<Zqaf>quyJ&|=XF9*1#K%?fo5m!-=C9v{@m;Y'
    'xvv17zp@gBbw-S)vTrMnS0?uyHBl9k+CN^*yc05gMeZvF$k**L'
    '5E461IozwsP0vtmsUIV+odE66r%NLq%$*%)4aZPVx7X>6W!bE+'
    'bLN55>=`6L`HYC@zZEmsNg7@qF^-;|35Ai373aIuh%D*Fj1k{V'
    'W!@or+`lVG%Cd$}HxFq}F!}DTR`Fh`daY<a019r1eK)=jcoiRz'
    'Hw&Q$A6^}u55c%kiSBHumd9Dp_$JSwkICfH{U^_*YN7>KhWtTG'
    'JWnEPSQNy%D^Z&gM9`!UU|wqohlvzlqi!D&Djz^&-r@I}8Yu~T'
    'giJ3t>=!$vMp$23JaAdHtX|}Pd!kaO=>CSzAi?*QKis&QbL*25'
    '_Li5~sIy#@z;I2$Ul0)aQGPlvUfA1Zh@_yN>hPKlR~2jdY3(#<'
    'diI_X9X7~%Bj-T2c~qEMD;96gM$RQSsy3zCb}dp>5<;YvZJ7qa'
    'g$4h<tTwZvq<O65Z2^b<6tvKI*;a#L(84u)Sudk_Q1t^Po79OD'
    '4Q1(kOB0wHTRI5@o+q`fJM?~0ZTvre##cb+;~=Qg*;W3uTjsam'
    'H@~()4EnNt24029S#xEEUB%#A2YDM@+MAI`o<>zj+(#Hm3)I2M'
    'U&Pbt7_p5jaH?nU?*ilhok{Zzr4GRHCjrQ!N$!JOwMy8Y7J&du'
    'fOO_IMh)^<onnL=#@3H|q?~pJe!o!dHQ_07Jiv3&i||W|k_kp)'
    'BhOt&2JEqWV@6+smXzXswYRjybR8$RRC^rYm@2DXN&i!ASlfie'
    'Cm_?$rZ-NX_op~Qh$@cb{^ES6+)hefv<FTxOcc=tuvdos&_gRT'
    'a(!cVZNXv}Bd{^Me3s+uL=G^4*J84uf7?s*5+s^*7q05ag(3*E'
    'J-TF?;6Z~bfA8N?p~UdB6N^I3^A44KF|J4JHYj~as8s9k^cadN'
    'PsnZJrImvh0rq}2w7}^WspQ&0LnpVh=KR8kZ&sIp+9Ov?4h+5}'
    'sz)5AFThU!uH1zYo)mhNav8Dw2Wl>y%P1I7<`q?po-)B_>k7J<'
    '#E^1!55r$4;^eb|AHm2R6iWBCtg>2IG#GH*t|5Aga>5;RpET)r'
    'GZ1jT?aJGNr=aA#eJwEC46E32kJUZBH+D^b_rP<X%RjxaK^D?3'
    '{EH+~c3!_-Y_O~~4)N;=FB(b%1lZ=B`BGz@qqE52mU@`Voyowt'
    'cF8zx+5c}b`h>EEZjz=?-nPwyBI6+W@_~|&Q>VycEV8CW<>fJ#'
    '#PvkCTpd;0Js^a(3DbT*OQyk}vgm0UXXyZ_wyY0lirt&}qn7fB'
    '_V;dL4h&JJfs5dXDn%$2{nCCAae|GM-oufLtJwi$<&VMI++&<n'
    'So(n?F21vrywb~$E3lm{mV-a**9DUDOk~&WBRg6ml)c~~Ucn_^'
    'ZSP<oY%_+2g;%vJz{2o`NK=1XvTM>6zfm_zAnSD9x2}B>Kvb`l'
    'XXCrll)NmZeHxibu9&cdAk6JV@6$PZ)<5geX3<$idB9B%ez0D6'
    '>LsOlNpF8EY>FCvAOi4XXX-JhHn;6I=kUVRubAo(4Y0m~`(bUn'
    'j@5J|3{zZEgsFS20Fd}pxh;@#;AtxD18hpo)rOVzp$_v}z*vR*'
    'Mv_C-!-Q^iNW>L1->9c)l|fLtj{2|IF5X|kF&lcN+<9ZCNXg3C'
    'kZ{!29twNDP}x2!^^R1c79pTJ)5@Pl#0Dq(3HA6<YiYBkpT7@%'
    'I$9Wd&+MTk6jmr&t+)Ve`a1oFrpNOk@na+d1m5?r2Bs<tJ&Ke!'
    'B}KhNDkXmzY;4`B=)nWNET*^40FO`+)q4GsBXCQ%Aqm^KB7swz'
    '$N0+Q5Og0LFB1hp^f8+u&>kl8wu-ll3CbOV##pJT3X_Evk|EZ-'
    'bC_ZwchLOg-F7DYYp~|OqjL7u5e7slj?XXEcL&=K(SWDG2d!wa'
    'T;c&n%-}rPh9{F*S0+bLgwr*jNQk}Oy=Xj%`|hlRJO5n44E_hn'
    '07=tDv$5i7X5S{8zGqfHe3Drp+z01B5qceg2kLSt>PDti`9KP@'
    '=3zgo$)kdb*%$w3SETb2?B)WruY;vWV9Cw(_HvKhjfN%jf^99)'
    'ANI1`vI2>xUeM9kMg#`W$DR@(h%~*ac-;^dMR2WScJ!>*>WgL#'
    '7%TI4*GAW_I2O~kR*71&;#v-F5}<^!xBT7&sQB8buh33F8elW{'
    '*V8&(EEyN5sL>uaNZAPZL(WGVu6eN)Zn#UL*~hsS?o)5tmVG}_'
    'v>2nyI896Gm3cWy*HpV|K!*{(WbXtFE^T{i2C$cPc^QgBm4Yr*'
    '$Lv(g?n;qD4L7USkY(#5_6v5TUuXG(wfq73XKgy<o71CQq)Y5?'
    'aS><K;L!?$;5vYMoZFw{(6p+SkQ2O&a%$^+z<T^2y3mV0yo?I('
    '{D&E+stSLT2u_r3qK*9FO|O>oBzp91js>4mS$gs)8S1JSOVeT9'
    '_l-r4QMf!YZl-9&y#O$CXB(Fdno?=`;!91v9<a02z(yU6ob-Nr'
    'svupBnkv%&hjSHhk;&`yoA0#=bi(x|Ejppc27=qC5ek_(W3mjQ'
    '+FT&d7B(z^2@Uz3v~*)k=y%p*55XEw7g$W0jP*<WGWYnBLh{7O'
    'hV}kk9zb>?L5R)f?C5gV$Mg}X!Ndz<dF4&rWH@)RllEa4o#>*+'
    'DOU^;3CX3=ON*NBMhFlDP|9%jLXjKjdffZZzfXFZ1}aQll`$&}'
    'q^GP-LaHcN9~q7qP9ZhX)_L$2<NFRir~Q*EN@uaq(fJ|<VjCfB'
    '>y69HOkhD76=t`R3F~Nt8c|3b<>i;@n@rpT_fUFub_kqSNpbK$'
    '&Ej0|a1g0~s4TF+4slLdtK7Z`LE?{M>J(Tg245-ac8Z_6zTcE!'
    'kA)J>GIsy~<B^4H01&TJ00Fcep(FqR(MIhMvBYQl0ssI200dcD'
))

_TCP_GIT_SAMPLE = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~vSfPF(<MFww|;i}(qf'
    't&~fO^GJnK+#BAft07XpTUw#E%}N8v<v^LHMyA!P@YP~|Z3-&U'
    'j7VS~R?tQl+-<RZ!i7&LI=D>Jg-!ldD(C{BW9m$}gNWxFzDhBH'
    'Y9o%W*-Dh8#6tBmM0MB%;ZTT+;@k!LE-(f{nro)_;(^ArQ}n$U'
    '70J<hitj?VPo3m{;Z&a3wl<9x7vvtt#TCsL$-x$t%ffAN{r1e#'
    'oBq7TFYUc*7vX3}Vm@cV6U&(AEHe)Kuqh`>_$uRF8-qv)jshAY'
    '-7OK`V4xy1;oUj_UtSU%j;Ft%uF=w5sk>4~BhLWv=wgW(q@fNP'
    'nU$6sAr`r?@tZk45J>eK=gZR)a1M*o#SN$YQR7Z-NI(ku%Ry6Y'
    'D_rskxAEH(w9<~3Y*MLEce6P68z(o}adE>BgRw(RR1<K?kX}lm'
    '?vt~P^8f$<JfE3L))QNT00HU(#smNWU#4YRvBYQl0ssI200dcD'
))
