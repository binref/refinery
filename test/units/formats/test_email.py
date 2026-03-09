from .. import TestUnitBase

import base64
import lzma
import json


class TestEmailUnpacker(TestUnitBase):

    def test_ascii_01(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        unit = self.load(list=True)
        listing = [t.decode('latin1') for t in data | unit]
        for k in range(1, 4):
            self.assertIn(F'body.txt/{k}', listing)
            self.assertIn(F'body.rtf/{k}', listing)
        self.assertIn('attachments/request.zip', listing)

    def test_ascii_02(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        extract1 = self.load('body.txt/2')
        extract2 = self.load('*.zip')
        self.assertIn(B'If you are unsure LKQ IT Security advises deleting the email.', extract1(data))
        zipfile = extract2(data)
        self.assertEqual(zipfile[:2], B'PK')
        self.assertIn(B'require.05.21.doc', zipfile)
        self.assertEqual(len(zipfile), 77_848)

    def test_cdfv2_01(self):
        data = self.download_sample('f4d5353552501b7aa0f9bb400e0d0349487dc45cbe5ce82fe5e7de526d37f301')
        out = data | self.load() | {'path': ...}
        self.assertTrue(set(out) >= {
            'headers.txt',
            'headers.json',
            'body.txt',
            'attachments/request.zip',
        })
        self.assertIn(b'figures,12.18.2020.doc', out['attachments/request.zip'])

    def test_embedded_attachment_extraction(self):
        data = self.download_sample('8f567c5fe40e15394ccf158356e445ea6b9afcbab8a225ad1c6c697f95ce36b9')
        unit = self.load('*.htm')
        html = str(data | unit)
        self.assertIn('<label for="username" class="sr-only">Email address</label>', html)

    def test_ipm_contact(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;8*_$|6KrRGrk;#Fn3_|q=YI!3><bRg7T4u+=$92y3rW_MUtiF1viUOT)C4cCKT2##x@RB'
            'Z8_$SMwEHsGsxd>d7EU#NxVZRErV))CUvU#n<fhK+jP_SpO_IoqLYFT1&oxkmF`ozx*6ufMzkmZ*LNE%XsVtO?|dB-rtI9gwtBv0'
            '=3?O8XiJPUK0x-;va+qo%!VxnYXhrzuiH?bl&0wu#`C&j#`g>>$nS<mS(dA8_>0ASHkC9b<qvkAtRd9={@sg_=<5j9RmJBBQ^#yj'
            '!aA%(<1v5V7b+HO%Yo>roCJ9DXAK)V`|W&}?XP_~3*AHb*hq*g5WJ<GEm{1mS>N#Lm?9ho1bZVI6<vjeeA2AS2d&QP%vkO_mO$f_'
            'Er>nr&RD!X7m^eFl-j$sQ-G0UeqDzh_|S^RGTSL)k;!TVmOHj|u{OW0C{#>CB~ffCY~3h+4J%xqyCT2&e!StsV>1S0s^paDYTzfX'
            'mLw)Z!a2Bo+y>06SVb_3o*Yp;*aT_qIVRu!H#``|lsh&n39PShNbfe)zyeRN39Z2D<{zS6F%!!cBTX2+9T7c-r&DUe-2<*6;^}F?'
            'buX6IXg2lLQz-lJ2*6eFh7<1)+yD*um=>tCb~Vx(0xo{JYP>t7Ji(<j1%$*fxtJh(eX@tcqX?i8>l)!BD3PeIq?TTW?^U>~Cj_<4'
            '<&0Pi;Ul4-KwP_=O!yiK%RZxQC~<u!*0|XJ8=sc`DN3yPLtvGs*DAtCug)IoaK09C4Qm**^ggf@BE!;WFJc+#dNcq`4_U{szoPw5'
            'Hg(s=b=+RIQQ-)0R#`GRdrBezi(QuhmEudrff6+%dWU0cGG`GFb<V8i2yVmiR;tS*fppyoOD|v)PDi=CNn);>5+E^G(O+o#D?i9P'
            'Q(Cjet|gbv_$X7D*DF$+a1F;>)ruG8eG<><HEdsnm71|y8m+7}?ae^ZZOJRvDFlm!kVIYygF4$uy<v^DHvSog3No7%7r6geavSk}'
            'ZeIqh8KvIFFSD>Q?n?`I7?j?V5Lab~S(xV_2)1rCDoU03WgN_wv;D{-*273d(K0;v-2r3Q{_{WkzW0X)U{BWHat-+)Af|Fr(+*gP'
            'p#z?B0INzrjmErM5w?5z$pW~ZMR#7s`|D)!{|8S$Py4Vrno;@<L%*saaZQ@Ddd;(z)qQ&0lTR<RC*Nhj5<wF;?Iu}z^ZF>v8fMA6'
            '@MZWhWUM1QAVV}ABN+GQUL9{M%c(<iu98dkt?P^p8pBx~bA%3YahX%IN*z&N3D-A&Ou3dde8CK<4>wb81K39(Nub9^Y2SaoM~!W!'
            '{G7omtv80XG}K2$xzdds>+6C=S_Fnq5i0c@;v11BM`~8c6jgg5hn|Psji|Ap;OfPFrXw^tTUm)wT1oWiK?WtHigW#|FXdY?A^D{$'
            'x_7?;Mk3ols!EjMRPms)$8bCjkpo?X8=Z`QaZDqK=7I87UF@?HFt|+Mby+Hx_B)!%TCofQV?W28$m3+xil#;sApwF{osYiHTdx*c'
            'W+lp8^tH0?@D%4)4(90tUCQ$*fVw@pQ$d^YrXrrXAr{)XAjM#@P%mZ4?~)Ig_h6$RqYw{O)Pu#e+R)2la8{h$iTD^t7Rs5C2NFnQ'
            'Yq7Lh0qUi^|9&Jtq`R<(cXu#B#Bj-og;6VzDeL{Om1Ld}WFMo^EBmNamnv9PvWflK#}JsU<vQ#T-92lvPDoUqlmZJkAdCz8=<IcP'
            'LSfx2XU#a3h@e6!(S%0!Vxn_xkY@Yq#IlW%Iv*Eeurz%0<bCC6xKfKb`l*Ea@o0X1gpPrs;j#L(s6G#0DotBABH47Y9mB=<vK5oy'
            'KDyC9iC8CJCLXjo#*WJowMpK?d70U?SB~&H#|^^8Qh(VY^O@Wzr#Ocq81D+h&x)QBaZ;O|*&$Hee2g~_rk|W>LHhu8{w`=}-Vht#'
            'b){aqLVU4p`2Y>py3t3U=yH3R14;5~c~|2wgXqVY<pP9uAc)+45VCkGhqqCwR0<*ro$(&HL=PWL)g7V&xku?cOfl87Nc0zZdz*pw'
            'APNdX>W}{7w*YO$WOw6)drL*a7p^a{dW+%isRB9?uJH#-QF~Q#dVCIWsq$GV1xpqzfyWYl&OmuvJSs#lAf2f0vBgmhnQwr$X4RXs'
            '60Jcg4c067+#;334T3+=GS<)B?~>R>#3$zU^GsO;+tCP=YkO$~u@~&06?&VMq_%L>In&(!8rp{+$-?RJK6^ydC1pRoIoNkOXUBCz'
            'KLAWNVG2W&Sz#Qp(oWSGJ`^mlSG9C~<~|wdcFXNnkcRCW;>)^D@uG$~y{enRL~+$z*Poynv-)E*iRf?d3dE;tB&}CulRk19urZ5Y'
            'RO*8KkoL;5wciWXUJ&+VJOmgA4RU^Ci0q0*2nOXRm<!15g<&Wsy}-kGRXlOMQRl3MK67oY21?&#ZBO5RPvp-CGFWGf%_0_j0-X1K'
            'bXc!G^E)51(2kFF{+g4Icfd!)a#)UI!c<cn1rW3`ESbx7{7zuH!ileO30Q<4oqd>zoSc+};3#843tylWx;XD5e)QEgp++=hO#9{V'
            '-c^Ad-5C}Wf12uz<l0Gf-3+&g$5aO1a=KHf0yaW(1rhv?K{9mj3MdY+`EA-sLURh<lr&90)vS;1)C|(_=~ykoLT!j{7}|uq-#Q}#'
            'S(PsI8Fmx0jJ3ORG;uJr=XOrtzbTH$OZg{d4*3S;fXNYW(>3|ikBe*P(tIj&;gzw}bn>o7twfMMy*#}WRp!tbYtW>uK)&GgLBg;?'
            's;a_ZllmQI`H?bd=+<36tKwW*d&z2u#FzKaV45t~p31xMp)BQ>9j7q;36F60<o+xnsOiEWFh;Mrp!Xiy&uS@b>pG$U`*%8<$LSKn'
            'tI19{N=uY4F~@_M=1-sfgDmSOdq1(dyv#J<@-^_}pPn9Et$WixhO!>`Zy1^r!a{jAvO`)C@&C5I;WD}L%B{g`q^_)+MRw{vlx}<n'
            '`6=5Q@y#`;UQm*?SpWb4hOC$e5d_im00Em4fUp4o)sM)ZvBYQl0ssI200dcD'
        ))
        test = data | self.load('ipm.contact.json') | json.loads
        self.assertEqual(test, {
            'name': 'Harry Glitchfinger',
            'company': 'Binary Refineries Inc.',
            'title': 'Chief Decompiler',
            'phone': {
                'home': '+1 555-0100',
                'business': '+1 555-0199',
                'mobile': '+1 555-0142',
            }
        })

    def test_ipm_appointment(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;8*_&mt6p8Grk;#Fn3_|q=YI!3><bRg7T4u+=$9M(6={5cmf+g^TqY#I&_6*NJBr_2i*XG'
            '%@;G^T&7Q>Jo~Fszg5QN8SLx^N5TBYdxZimmO0nQ>r#{uB`sMoQHdQ^{8_Db#b=CfbMoDJ$<GZvkP`&V1@m``3U=;fxxY8TBvt$&'
            'eWPfI3j#geW;Be7Q;CL4tl!Drl-Fd12Qts<%hq3)m4O#`2QI)gso4N9-6APsYykoixi19Rz8f>1T{R;BG<g;OsU|#X%K~QjG>+X<'
            'F1&>^@EBz@^^(gq9Sk6UWd%!x6_%FEHo1_0HE^1ID|OCSK8c@T|7ZcZwmpv$D-u5+1CgPkg9caF`-4$pcaI6z8$ubr=@~EdCq5Mw'
            'K)kdT#m^xEVp;tV3V?A7<BQevfc;cDss%Tb5@aZEyeajxJtwqNMg2oyH&?bHxLtkt=sG_5q)$~0)<64+7J=Z1SbuXIY~hLm8037@'
            '0k~<jt>Ng!l>}&#WWjp*tAK|XpWZe+V3S$$WP;(5Hea8FvsixyJZ-9o+cUi2yh+UbTb5t7!yj19o#lLQR1Km2XBW+fNgnSFtlVV6'
            'uU1=Ufim|+HDASo-V53Rmk?@;LL7jobv3}*De_->MtAo+rB*1k33o`VGO~=XQfJ}bmNw-*w4ut7&pTl|8NlxsKiAp_A2(M>O;pJ%'
            '<Gm4=7u@1l_?XtP?Yvm2G`s0$!3Q16JPIMh$iU2mU7?|)T43#+0tl;ciX}6SbM67`F*J88(cgn#SUIHCwMBG<o=Lmpvg_zj9x&B;'
            'y>!1pnbBAxokyOEVX{4Jpr7ru_*16k*m5ExtmvX8rtE{kffM0Vgs`2yxShg8po!A+P&=izK;6j(f~WLB;k#6TLxF#mW^H{)2PY-3'
            'zA<j0de@_}Ow3ywdf;h^oWU52TP{Qssn@@*!4^j65&o&Pt^R{1PGz{%!M2)7f*UV?%BfWJ=8jaPdA7~xtjz8l7pggB6=#&7HKx*-'
            'VTqY~e?yFa<9vl#Ql51OoX`ZhfR&KR7^nb~t=@6eJrY%1TB>5*YWi2!O$(=t{q?G~OSIQrNK!qFUg9)qq5*o5>hkpgQU_W#%d&$G'
            '5ma%&mA;V2-R&(ejDsgXYLq%Ef^~pJZ-@D>EsLN<lWpce?di4LRe&)^fQQ#Wztn-aK)S1tn6hx+)FbO#tal4BPomGx#=Vc->su!m'
            'TvqZrUFP|oW4RBrT+C11eb|^ZnDcC4L5BiB#cSW9klUR)<HD8!H+Uil$9QwMHZF;mjC@`#u)H;S?iCkhS`9{D?=K>4G}$xkFWLr?'
            '+7S~{*#5a9>)-*-OjlWqShwwPudSVx!>+<mB+6#Y6*jR@(jMq@0%Fk5%(XrCN(bJU|Km=o2;N~lWjraW$&!2QE>m+d%B3so^X4?)'
            'f)jM8--C>a&qbHf1Pdh+UP~?tVFhw?oW1Dp!Q-5Lu0n75u(l;^ShXd%-}!#dVYc&gbv4n^aLD}8j+42bmS^&@Vuo8M2y@j%ZPhq5'
            'S1boseq`TGZ5VFBS$w<a>Sd7fRkM+Qn<1(Y08E%+k6X~*Flp**;3U2iI}eh3%NS8P@S>DBr}K!utX!lXX%h8QZb{f|VG@Hsg}ly3'
            'LyC5AquF<ycxjDz1B<)#+TH=?BO0V_l6EH-{39Je=e?@15f0UPy}_E=8qdeAwF&&@mA>|sYEZrH@rRThm-S1+J%2wKH$4#=`l%%N'
            'ZcS?-919+~>=U=;ddrYEs?ZAw3q?mAESfA+nMO^X(lE3xG8HtWmTNH4y3Xr{9?!QZ>k>FJOL?p!A@t_0!dnENGdxjBCC>Q(l(6s8'
            'PZRHa&C$E<qm6nUy<DDwMm_qg4rlMB+pT6TaojK;{PJd&M`fX|xb3htyRN-DpH32L9i{`d7w4d(>|J;?9RPH^RS?QLxC*~6R@2xB'
            '|F&L&%o}J?4AoxJ=crrZT81B+LO$rDCn$uhuvGoqr`Wm$u+61o?%5zR2A0)Ehv%l-YdEGRzf-x=iXqU@Fg5llL$V)h-TweEMQ+un'
            'WqiJ#o0H3}d;LF2tYvX6N*z+jl=Uz+$H9(H0P#VOU(HPf4~7$E)7FdTc@V^uI$h)XrD$|iubFreFjE(2q-^Z#iN=7OF~lJR86jpQ'
            '51ld1>YS061tcyw9esU5rsT79lp=?cNyl6|F73l^x8LR*S3IGN)=&gF7xYn!oDYauIH}~0HS5i&6T5+{FYFNC2IP>%lvN11l-g*y'
            '?GXZwp!})oE&%;rIOY`r4d=l#y#|@xC{tAd;ZY#4Bu%5`TJxt5MR7st!+DqKmL?uyKVzh(i?*=gHc}22RibXKxr2^cy&o_K5qWN*'
            '9F30XInIUx_>3b3pIMA~4%WR&06%;tR`7M&?w+G$PpWjLwK?`Iqs)WL3)1-%=nTCQRA{Pzq+E26O}!2QsiSLC1cMC29HoPC1!$%5'
            '!$Hq=tNqgGqEt7(DL|^7$aHzE={X>^H7Z>)K)DME`xqsP7dfDW|6yDd{-|B5V+ctu)7vnmL)l`6*Y8Ae#GUz(apVDzl3;@mYvVT9'
            'p~b6ju0-*Yd7XlFlTZCALg7^H)wlvohagE}9&T*Qb~5LEItPqOe$rYXD>V7Pem?K}%BJ-;PBadD*mCU8Bb>(UzN}LDy`V4Ec6sx;'
            'HdOF=N~QlVT6yM%|JJa0W|e%ll@QEpbUeehItdm6n;X~p+f*!}dQEML)Lj%CYvt#T2O-gmgYwvpLsz1WOr&qb6K^H?{B58-18{;T'
            '@d_u1^ZEbtN9E%YN;0d?I_(Uu-0evIN@lNfe9mq*R~T6^CHfY`8<Ej9p((}uCprR6M;PB`^-<GpRSxL}$5okIf;>XiM{<u5-8w&O'
            'casBCE(DK_fO@;`p03a;hK)XE5=gwm*ozpoS`5%auhuI0i76Dm(_-1R75S}Mf_}ymaS`fauM~QB_t^m=b!-|r$t?j2gw0|2y5@au'
            'U*p*JF@prsEh9;wF0%!*+9%P_KT+y<uGH^Y!)2!8BILBwC7A1Td*a9v9tI870>)N}R!ZARS#ydF370;K_4uxB+a+owZ2-KE=$u^;'
            '3mmJIU(umWJQAVc7{ER;RBQ5GVZ6QRO3Qw~N87+urzFD1K|nBMWtfKcH`LE4u?Vz1%VkP;!Jc4bX+Fj4Q&c9DCB8oIGhLP50vgnz'
            'e!|=hV#)LpvRM=V;Z53hO`pp+;>ia3Yw$R!cA~vA%{|Dev)ACfi-^T<A2QXGsfC8lm}F}qQD{B_>M6)jGFOWUGqw-uZv<BOd<QQ*'
            ')**%ft8~ak@$#&I<Sg0B1<SralS5P<5m`0VKS&_V5FlkbySE{OdI3R<->hzpxvixq2YM5?kli29_c@SHH?YL3b`LrIA;^}0R?L7E'
            'r2pzJmRa=y1P>P5)7$1zM<vngd^9q_b~mZRIDWbS(~H;I$`T-z++BTcnv`ws2&iO@7N&OEPHXpB0@AJ$Lb7kEIlltxr{}K|G2hMN'
            'V_lBuxlS1gV@}~E17H4-wlU?vw9)_oKRzV6g|6Z<00FZVfUp4op41n{vBYQl0ssI200dcD'
        ))
        test = data | self.load('ipm.appointment.json') | json.loads
        body = data | self.load('body.txt') | str
        self.assertEqual(body.rstrip(), 'Get ready for refinement.')
        self.assertEqual(test, {
            'start': '2025-06-15 10:00:00+00:00',
            'end': '2025-06-15 11:30:00+00:00',
            'location': 'Planet Gunsmoke',
        })
