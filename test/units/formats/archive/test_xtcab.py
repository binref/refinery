from ... import TestUnitBase

import base64

_KADATH_CAB_PARTS = [base64.b85decode(x) for x in [
    'O;bZg0000000;m800000Jpcdz000000|5a50RRF3`vU*~aA9(EGA?6bVgN*Gb88?n09XJ30096204gc~000000RI1eTL^C;0Bd1n'
    'VRUFNba-?CCFW4Npa%c|LraZXLAK<!k=*M&-GK+F|1a=YvivOh$x_>v>{){(s)#8NpaAlhN-G~?Hgkqq%prUepJXB;K~{CE{obtl'
    'cNGaBGb1A-6ZO;NyWbb@=9j;0zOG$9cYjOQly9l~&W&!JzWm~M_wL)*?$58?pYppOiaW1ge(~iOKTXB^ZVj`q-CtcAb6lqGYgblZ'
    'x{(X|k&CTZe|F{F$C$U;4Pm{XIy{aq9`D~=?eJVpZXG7P=Wg!a-KG%n*&1Txmy6pfmrPo63YV$FR>cjzb3G2$h4r=j3eR409DULr'
    '5ue99zUlhte#P6t-mY7!em!-!uuj-K#(KhH^AbJ&7;?-hxsiW!5m$7kzJ&3Dv%;o#9}+%+S$*`Uu7>#T%S-R7K0fCytu7=zx|C37'
    'w}zpsOMy{1Kwq*OyZZCy3YOyzi!bMm{<^q=qqlu;VWj!+(ptIKFoksKdcWR0%o}|SgInQ2JYdW8G1r>sm*{B!R+4=j-gCKQA-5vH'
    'JisL)I$W#dTYYPOhF|OI{nDje*6D_WbT#G$ZwxWaJr1`9Uu09ke@f10TOQtq0q&~f!ykww{F1lA9b#BlEFN7l&s~bE^$r*JeDbyX'
    '<Eq%Z?(E^h9WR$W;#~O9r8AtwkLv~}B^P1tHZSyuLW9G(I`M%p&p0?9818fLBG&%?4ufF%wBaCt$hHy)jt1pztnDN2(r?1%mfk}R'
    'D<j)N_-4D*9oKcunMm-+3!L8$;eT2Du)4GwHXXp`;)cK>3~-Gr4(Fv^u%zDnvUc0jtr-xWW$lu~CAl=*wOZZk0tm=x7w25pmv@&!'
    'B?M;=8<9SG3&-O#h&dOBv+JH$Ot=vcU;vV5<Z`z}CCY_w-FU{F@c#)wbV!w(2X4GxpYcap=?=Z}%2fZ>ch}@^X52X!9X$}0-f5S4'
    'tH+AS#GU{}#EPH&8{Wzrl6BvBxDSL|!3TpwNY?<jO?DRJoq){5_qWN@X?#(9V($PiS8RFWD?{D@zLenr(93K0cX!!Zz7I%hSPoBL'
    '0N<q={21(Vq6wG0t~lg56rB7HAWSE2h~;w{v8mD$c~ZAR_$qO+q<Oai3k#0!-rPRAn{m##)hiwiS0!&o4xgD(V1m5BqA*+;53b|g'
    'g_r`?#FTMcTO!w-E^mM%fLiI^v*UIb$M4sy+&phZ&N0Xo(u@KjrUm$a2WWdYOkDy|3iYHt!FNZgDAYLYU{Vnx&o&@`l@mLQ3|u*N'
    '#f8|YHDAT>=PomKZOKhIHF_1-)3DyVZ8dan$s>~{#%P{F3V@6vdG=8$()DmZ+#=sH=>Pi1f5YZ`aVhaQ#tdgeLdrOA-C=;25ig)m'
    'CyDutE$fmEOCa;Xx8xA7!fxb}2Va~cJyh{8c>)hHv2nnWP(-9|N?d@rKG+zi^N}!tzfc?y96|&r0?B*j6j;I!*Uaot3jGJM#dGrn'
    'NY^r|^zqavcJyR(J-6A9WVH|Qu+#goB{-k?*wy>N_BTL22ny<@yvxet88Q+f84G!bS`Q-|5~o1EkarKyH!3TH%-{g9L4dGYD~K44'
    '0#4gUg5k7R*@2}2^o}BBPDH>EbXF`kHjM6cPs-8*E`cK(t|x!<%x_ej2vSnoCq^?Ul1Pd0PS(03L*84(sUTC!<cHyA<$N%SWo$_A'
    'g0Q}-ZYbdl8<FI9Y7=pm5b0TzM^<w9tad-3;H+BUI|plCewv)PgFzYS_4Hy=!XiqVTo4qe>UNIMMW~8MWYQMcs5_Tzb-?nwl|W-T'
    'uu+Ml%4GE*Q-(9&SSn9@4p%c0m02YG;9oZi0kCGG1!BDp+6~V2%w+Cj^k-YnVpK35u{h;u=;-~#D1Ju8y^&PHSw}D}cQCC?ax{*l'
    'uG7qnzZ(YRUSa|ju|^fno6KTu!f8~A8X!@El1f3aBEO?WDfJby+@}ixSIMe!H!&{CRH`v17iti1*!VbEL~G@~fRn)k6EnwzikmG{'
    'hJeE&Pvb6l41QEO5JwP8T$IPNV8LBu36>qRIf2fB)Pnb$f`H`9P>aIkCEJ;MdKf!VR!H`W*;}&EgO{8bRM_PAVpA*!15^Xp!I!mu'
    '1X?_BeUR6u`3e0RO$;lCn<MbVPD5J?v%5&mLN}I5*hM61h5Yvh{*;GxGetI0J>Gu-`YXj=i_<qWr~3eZDq4R`omdTy+aM<k(e~gq'
    'iE_e{q`ms3?#yHv^++8Npo`bNxqyGM3Uj`_@c&6y^a-sN>`&DR<&2+%(k<Yfw7zg5Ms*@tX@U1lI)b>kso?Y$f{|j7hv8XJ%%MYm'
    'A~!+SC2GkmmUHVTPElaVaMTqf#CzMGSl^YLlVlA>7VZMr3VS=BDL*N<A*$J-P^HuW{{giUFYPGMVL@(&ZUb@T+}MMw=0t{Y<Bm7!'
    'aHT9({}ed=wm#!h&q}ZktKmrs50Y1;QWr`J7%-zag7e-Ul5XX}TbU3gBk}0vVq$13#(bxy`C9eeioRDWlO<5F(bCZLA<qk>Xckib'
    'kY^VsXb!&p73y>k4<)eZnQL+JW6P6{CtMEHui+gIzVmQ}>dB99vRO_tk~?o?',
    'O;bZg0000000;m800000P5=M^000000|5a50RRI4`vU<0aA9(EF)m|aVgN*Gb88?m0B~V)bTckvVPXJ8X>)5JGXQA-000310RSp0'
    '0000000960ep?7{AOLG&WMOn@E_8Tw0Pqb`9ghb90LE#f4;XF4JW%+mn)m+l>>A{hPRC#tzyD7tg|@yz11+klmo1)!_$=={9AY>S'
    '&;=lM%(tu^26~|9GCyx<T3A38Zsa=(s8<!P8x-JszC%&flLU7hwkQn6Owt=&f(EVP@*BvV|7tHJ#2`{T2j)1MFX%o{6V|(gzGuDJ'
    '5<3O>TrQ*dp|BDgAOqPXf<{z>PLKL8+p2l@tw}Y|1}V2J6P?i;O~B|Ru&@PUaL!w0eC-VIUxk{U_s(}yKiRb`8$_noK}DDi8&I(R'
    '^^gBDg}Ir=gYoF6(o5YUy0`ADUjgyF9<@A?ZgAolmTH7s+2&$NP-g4UCy;n@x2hf!9#WeCHy==f>06RP1nJ~vd9L^OoSFbcCq7m?'
    '_Pm|Xkv0C&zJY{R6`6DQ&MtjK_gjxPk8K~G&dB2|c?{<yvwMJmC)m#FD&DLX&~u~5|5rg^*^^1lPEa)iAO;q<e2bjZ+^+04VjJ1G'
    '9w|5~6;M|Lu+G5-+=pthT4g>pc&p~U=P-D>n$wl!p(Qu`NiLHAKM3vLQ2m+9nNQY)GOLNqPT~R)E$$Y1KKL+$)bFlDh08ChE+15L'
    's&AdJh6=6X-Y9lOj?aYuxw3HR){kqB(cUqKdamFA*7%UHzfr=!6~ZkOj)uvor*CDQLBcD$A~ac8t$`DT%zo~RBGmM8Tpv@DCw=zR'
    'fW3Afb?+=v{|O3AC<{j!<E#SSZhak9_ECO5DO$%XyIKpYF=X!r(|C;7Vq-4rC9GMudYD*0?%h^BxYTAEq2=-D-+>rWp$jTkuicOM'
    'yNZg`y?fCVv%R*&cn+(bJ0v|{!Iw9}l>-LYjT4BBL;{gtd`5sUmB%9C^CUyQA-=KK?;-l&@gJLpQ54{4tML!{g}!!jvi64dY1cnW'
    '*)1hB=nqc6v0mGAJM$p<I4u~%Mb#m@Yvpsu>`TeY(w;lDS%Ff14D+LR2akdrAr@)eVB@nE;WKzDoVrm?R0pt?)tacWsXPAf*PJh!'
    '3}%gFEMU2>1E(SO*wLvdz%MG-Z6<dH*gn(7oc2n|&)HSV{5G1Rr%|kYJ;0+4P+?BT0O?71jiEYDS2jhcYFdoEdhNc36y}U;Oa2!u'
    'EC~zFWaLlkd-it2hHA5QBV@~_`e&bxmcKc|nkrDLm`tssL|Jp9Wyu}1ku-{8>mAkFJ=a8Y(4G+1{I<af$_%t7{-kjFtY5YM0+k1D'
    '@Sb#hW>+JS&#ZAOf>iKr%2IusfbS|+LSYF%Z=6#?KwFYQuWT$UngP&9y8<&QI%!x__mpP;QJb-xtiN{O=co2D5;>f2Q>NW&qfM%m'
    'kS5m$Ba^j&BM&1lq85#?+pIOVXxlDak^;bzSm<repEq`OetZgmg(+4L1}d0nbJg^L&ESlUfB@^Qmg!#A^x=!Tgc8=xMeC3U0}wV8'
    '=<Oz>Gz<VOk3EH9rii{`=q1Sz^w(B<p1Sp>u+Q+Q&99UkOkt5`+eR+nqmd(;wS|E-ymhchjLYU4RcmCTQ@U<%9vcVDZ#<PX!WPei'
    'oD|o%7~`Q!NSvnZqq?tAu9wOE^M4ie50FDIKez&}KQs&8`pG4L3Mc<I=;p-IrFe8<^i#CZ-eJO1jKAYyzS{~LY$TEO5YJQJo)bb7'
    'z>;2p4dWRgYcI)N)@wGUV7?!ZZbcTMU41b<Z6%XUDs_;wI}0nkhSjVo<sFuj1R~3cdC0xb{E5;VD$`}Zcxh9GUHurIkN#dUc?y`O'
    'yGI7W==3PqA{Qf+sIE=JuG=o}Y+i^{EE)M+Rme>O2!nJ32_sO^7s|uf2B#*N;Pj0bOlgn9Lly4~yob&q{$;S%-J*q@tL(&cvMVF?'
    'bqs)p{JeH)yu!h|vN^|nY|go=2FigVQ>BIpr0L@^dEW((hS_T4Ijc29m@8!O%Bl3I>dh;`CgM;AA!2{tj(TR&)<ry1H7R4XRt-_M'
    'Vs|GxJC44fvbv+tj2hQA>&+Q9*p;5CCWo!A?Gr+t><?^;b{$NI;f<qhF@V6P;fjxqvncr-XD*IKkijl|v5_?Xx}zY~mB8$lt?H(a'
    'w?t2xf&-{Mc#VlAu{P_qxjXy6@JJL@m4l#LWJ^;`7F!EL!>&|f<0W1_?1KgYbqCmM_g6&crpZXCzk&M67SJu)g5Cv~i+7`T(cM0?'
    'gGX*Qs8Qat6)u!?*1?O^{9Q@E+P$Z=V7o4SN*<<&2*F!KIY9B8uIp`K&IV_C3MHD-VW7OXhgCjLEEmhdIldK9I2GMSn_PX^T79WF'
    'v1YJsw5JiJRXZbYY;i{o&}Autd+O9PDBGqSrP5wBjZ85AqHdNxQI$KGn~HaSq-hWwm4|(?nSTq{mNesW^l%##z(i@-L~E$!(S)!9'
    '1FB8?tN!$65v3;DDq_xxVAbRRfy_K0HDh?RPH>h|!-h)T*NFBIBG37wjTed^@+H|l6pyaU)QsAf&u1}~Lz{&DQH>S)dM|-o-O}d8'
    '$b9P%=sUH|*EUXIQK);CYaps9wbv@II7cYs)$VL?T-r=$v>yx1FzC~(+!00P',
    'O;bZg0000076bqQ00000Jpcdz000000|5a50RRC2`vU?1aA9(EF)m|aVgN*Gb88?m09XJ30096204gc~000000R8`dTL^C;0Bd1n'
    'VRUFNba-?C^DH)1wgW0Es+&Tb4a$#Fn{Mjfy>81*FQapd`RDC!lO40%G$E^I;_cFwc)zzLkO1Q#z5Ec68X3Ug)(~>?Z$o6ev=Xiq'
    'vZi5G|30}q3H777Rnvqv8EYjIS!p8ox6@aE9&qwdeq=238BnS5WD{L<m35*Tbnz$;RV7F;7C3upBS*<gbyd7VY?tM-RpTShK)`3<'
    'ecq0m>d$Q&wLgTFZPuXSWKgM%ce}aSV@AvEzG<I$v^%FB6a;s+8m_Z=3*0`m7i9sFb`9)oE`V6+F64!mlJ_TUy)}jp`_MIYe}fR^'
    'UGbCd;cOqh-_?cFex0ub=U}4ALT}ToAusnwDR>?T-6i+_oZK~2J$&!dR#8`$wcUW>SgmJbBNEcnU3G8wmHcwdZ3=|X5;tf>{ZZ3h'
    'AI_XyDAu5a9!q?a@-kgLls!8T;e(9Z?ybh|gJvuL{2%j5L{-?YzF~EKTvF}Z{VC6`Fga-L{4hzyfL`U$8D`G}z{kJwP>aGQN%P6('
    '_2yk6&-yVFdet|3s-))AO2&UmB;|eFF906z4z2#~0;hrYqdTrym{h-X7XqV|)o)Fxo?Xy<uC*vOQ`iU3+GInM==Y0S4oyYa)U$T0'
    'EX4kpfAfPWCQZAG+$$Ro-l{9to6)ZjKGF+pIQSckT`(WK$}_)+KQ%8PEZnsf7Y+aa-NfP(&8yyKzpl1D7^Kq^vy~=Om=8E8IzFS{'
    '<36+fe2DmfBXW~`-vV0RMvgxO6O1kBW3~=aZ95udKXJOIQ$J5Bthqf=;V!FYHpRt5_O_obv;ju5;I2y*8`-I|GCjKw-_At$;T?9&'
    ')-DU;{^HYqgUrhzpOGR~2&mX>Is;7I4#j7`wOFiH0~k*X(lnH9q;5ku&=uw{BxhbO?j5KJ;=|wjxQ;}o`bHB@?00O2YnK2c<t%T='
    '?;4nCqQQ-~l-Lfa1dRH5k?GQ%S0Si1O_;TZR6NelHvh8c85>cuseZsF*4(cf)J^DY=(P@GoB>8QwHq*5<jn6VGtu>j5|!Sld%<q{'
    '7O2YQ?deAkN4L#+{CJ3Ymhq!#>2Aptwbr3f$(SHf1Ly&L{{Dk1);g(Ot?>7C4vhTyPN?MJy8kS%Z9?g`;LE_QWJ*D=pL01q&5g#a'
    'v4DQLxc6ar+5ZB{sKm2eaQsYQ+AdzFeF82iKh*Z47UI-I5S8~)81x%2Zj?MnR8AKWy@BEQP1uefK4;1*lTTZw;uwY7*x<j-Vq<`R'
    'Bx^)l{|5',
]]


class TestCabExtractor(TestUnitBase):

    def test_x86_filter_regression(self):
        data = self.download_sample('55e0e9167fa3612135815ed01119a91281373c08c257efc8f7cc36bcc08734d2')
        test = data | self.load() [ self.ldu('sha256', text=True) ]| {str}
        self.assertSetEqual(test, {
            '4ed76fa68ef9e1a7705a849d47b3d9dcdf969e332bd5bcb68138579c288a16d3',
            'fd65d192f2425916585450e46c9cc1db7747d00d1614a8ef835940f06795e2b4',
            '29835e2b02d6cb017fe9fdb957c79b120be6c91b6b908eefc29cae7efe3ffbf9',
        })

    def test_cab_works_in_xt(self):
        data = self.download_sample('55e0e9167fa3612135815ed01119a91281373c08c257efc8f7cc36bcc08734d2')
        test = data | self.ldu('xt', 'kZuIfcn') | self.ldu('snip', ':8') | bytes
        self.assertEqual(test, bytes.fromhex('77 A2 09 53 D7 1B EA C6'))

    def test_multi_volume_cabs(self):
        chunks = list(_KADATH_CAB_PARTS)
        chunks.insert(3, self.generate_random_buffer(1024))
        chunks.insert(0, self.generate_random_buffer(1024))
        out = chunks | self.load(iff=2) | str
        out = out.strip()
        self.assertTrue(out.startswith(
            'The Dream-Quest of Unknown Kadath'))
        self.assertIn('Of these things was Carter warned by the priests Nasht and Kaman-Thah', out)
        self.assertIn('So Randolph Carter thanked the zoogs', out)
        self.assertTrue(out.endswith(
            'to see the slab rise slowly and deliberately.'))
