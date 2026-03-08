import base64
import json
import lzma

from .. import TestUnitBase


class TestDSStore(TestUnitBase):

    def _parse(self, data):
        unit = self.load()
        ds_s = data | unit | json.loads
        return ds_s['DSDB']

    def test_handles(self):
        unit = self.load()
        self.assertTrue(unit.handles(self.PLAYER))
        self.assertFalse(unit.handles(b'garbage'))

    def test_player_iloc(self):
        result = self._parse(self.PLAYER)
        self.assertEqual(result['.fseventsd']['Iloc'], {'x': 88, 'y': 31})
        self.assertEqual(result['dmgbg.png']['Iloc'], {'x': 256, 'y': 31})

    def test_player_bwsp_plist(self):
        result = self._parse(self.PLAYER)
        bwsp = result['.']['bwsp']
        self.assertIsInstance(bwsp, dict)
        self.assertIn('WindowBounds', bwsp)

    def test_player_icvp_alias_in_plist(self):
        result = self._parse(self.PLAYER)
        alias = result['.']['icvp']['backgroundImageAlias']
        self.assertIsInstance(alias, dict)
        self.assertEqual(alias['target'], 'dmgbg.png')
        self.assertEqual(alias['volume'], 'Player')
        self.assertEqual(alias['posix_path'], '/dmgbg.png')

    def test_player_pBB0_headerless(self):
        result = self._parse(self.PLAYER)
        pBB0 = result['.']['pBB0']
        self.assertIsInstance(pBB0, dict)
        self.assertIn('volume_name', pBB0)

    def test_notion_bookmark_parsed(self):
        result = self._parse(self.NOTION)
        pBBk = result['.']['pBBk']
        self.assertIsInstance(pBBk, dict)
        self.assertEqual(pBBk['path'], ['Volumes', 'dmg.MtpUWZ', '.background', 'backm.png'])

    def test_notion_pBB0_with_header(self):
        result = self._parse(self.NOTION)
        pBB0 = result['.']['pBB0']
        self.assertIsInstance(pBB0, dict)
        self.assertIn('volume_uuid', pBB0)

    def test_df_data_modd_date(self):
        result = self._parse(self.DF_DATA)
        entry = result['Forum Data & Analysis']
        self.assertTrue(entry['moDD'].startswith('2018-07-09'))
        self.assertTrue(entry['modD'].startswith('2018-07-09'))

    def test_df_data_bool_and_complex(self):
        result = self._parse(self.DF_DATA)
        entry = result['Forum Data & Analysis']
        self.assertIs(entry['dscl'], False)
        self.assertEqual(entry['lg1S'], 0)

    def test_df_data_lsvp_plist(self):
        result = self._parse(self.DF_DATA)
        lsvp = result['TA Emails']['lsvp']
        self.assertIsInstance(lsvp, dict)
        self.assertIn('columns', lsvp)
        self.assertIn('sortColumn', lsvp)

    def test_assets_iloc_with_index(self):
        result = self._parse(self.ASSETS)
        self.assertEqual(result['7Clicker.png']['Iloc'], {'x': 70, 'y': 40, 'index': 1})
        self.assertEqual(result['arrow_down.png']['Iloc'], {'x': 204, 'y': 40})

    def test_assets_unicode_string(self):
        result = self._parse(self.ASSETS)
        self.assertIn('AutoClicker/assets/', result['arrow_down.png']['ptbL'])
        self.assertEqual(result['arrow_down.png']['ptbN'], 'arrow_down.png')

    def test_payload_dilc(self):
        result = self._parse(self.PAYLOAD)
        dilc = result['Daniel-Black.otf']['dilc']
        self.assertIsInstance(dilc, dict)
        self.assertIn('x', dilc)
        self.assertIn('y', dilc)
        self.assertIn('screen_x', dilc)
        self.assertIn('screen_y', dilc)
        self.assertEqual(dilc['screen_x'], -39)
        self.assertEqual(dilc['screen_y'], -69)

    def test_dni_modd_blob(self):
        result = self._parse(self.DNI)
        self.assertTrue(result['Samples']['moDD'].startswith('2022-05-21'))

    def test_no_data_loss(self):
        result = self._parse(self.ASSETS)
        expected = {
            '7Clicker.png', 'arrow_down.png', 'arrow_up.png', 'BebasNeue.otf',
            'checkbox_checked.png', 'checkbox_unchecked.png',
            'power_button.png', 'power_button_on.png',
        }
        self.assertEqual(set(result.keys()), expected)

    PLAYER = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;3xwJL0td<Xa1<j8xF4<9XTL@e>`9giGW$uIsU}8*narZY5pLwzv5ee91S0ErE_CAUU06h'
        B'*O>(=iAlXQr!9{Om!8v~n#^f_=HEg#;K{Ebgn2eiAjUP@un_8AsQdh}krP=cWRh~Dl#aehH&sL(xEq(yx0Wko`2AS5K(IOMf<s=@'
        B'CU9MiE29DERnETp!o_E5XK^y6#Y27e#6vxlRSq4cH7J$Et?50e+$~~cC&~%MOl>NOHt>C8sUFFhHSv@w7AGo9O`94wRoa>De%*39'
        B'*S~zq3|^Pt&61>1+^w&7n_VEOpkdu~Z}cq5Em8F2N@hGx=S{1(T6OnY*6QjHP+eqgvd?s!T21&SalZVpu=g5gV8qbk!;Cu|B|6m@'
        B'R$$?g3FXFS#lni3#96{Zq}ZXBhHDcXLbzR#YQJ=JF5q%>g8|OOTO>TxJtcE5?3*6ajq{tB8S17JOR}qksFVTsTgUed7&3?+e|DNr'
        B'0-y9?!`B{Ro{?VZtR8qFh9aQlCRucGm|XJO!g6)2J{@L1Q4Ep2GaDARJ4Qv6%E{1!1NzrI#s*CdrzTH$4LbTbarTcav8OZ^6P<<K'
        B'7#lgKL|1f72qXd@CB%ajOSQqJWsMgI+v@~Z9*W}j2#b{v*Vw((dC$^<z1rjG)M8;KxdeyVi2riN2+fmP_#~i!drmlXFCze2A&&G0'
        B'ks&rsu|P?|RwN@W(_>s_iwJW8OxU!BV)j7-41Yqg)NFac<h->3s@L$vslwI5yc`N(Y6x<}_(s!lRczukihKPndfdp-MK})|;1ulR'
        B'ji|mSj%<mPpnG9+B-LPgCaxOadZg%KDHAj8rCbv3`1nViad~^q!W|*`5@rd2>D`bYmhGyaG<C(Rr&9?%c|U5+|Hhq+f5eRm7e_^7'
        B'f;PzMbRhLoep(OG7i}j_P^avyor94RoyhjLM=`7{)M1zl;-!#!wPsx-A9SDwpTt7K@rH*tpZfrHr5b^(S+jaQ9l%}VeVxfJ7yY<@'
        B'`L?AuT0fE>Ji|lwBtA)@<}P`;21E+KQ%cv=Shz{VClx7shao_^ybt7;vKc_Cl8wsjLYXh`uhvR^hz~1iXrx_+<NR1@^}A|T&N?-V'
        B'&1-C)XGn;sG4QKKsU}(QD&d<WrIoTpZc$h%Q%~zsI~%@ny6@hmJVy^w^)1ZYr_3QP`MUYJ5N|}joz#2-@bPDC<&Qs{EUts9P%?&2'
        B'GgB+c@nwrTY!7b44*SPqRxf-=*W_?k^Q2m!w;RSxh;He{&f`M64_a$qm|}d`99^4bjaJI@4a=`kADrg-;=8w^IwScYExmYvTC-z8'
        B'k=+D3W4Hi8^Jh|OjT=SxM{Z2_tkSs7Y-=Bef;POosJc?d>*n`Y=(WPc%nMVyWn5Ya1~2ET|2BvuWpp`2YBapk^k-QoiZbT~#qv^G'
        B'?H1+=!YO^1NOS#bU?Q5n41^UiY0j@sm^^Qhia|_O9A72oq1Tt!?pS}sQLVVVYqtD|PC@&?mQ=dh_o9Ipl%GR!_cb!9ziR&}kp(Q5'
        B'p3S5IYm3PT*sUJSp~+W?*bCEQOmuOH*_CeZhAWG`(D#tNU8?si_Zf<5+$>jnOR0(EE{9aVNe(!qP)*pG|I79|>p0EnDG$%61_!wN'
        B'WzsmNqGn_-aP9y?feP_X{^Vo}iBz!6LP7zaODSwRf}Pc)=UFG&AMmh!3(o<??VAb@yDGU~^-VcoZMMC@bJ!_$%Z%&IE_{qC2TF80'
        B'qO4EWu3GQYPK42E#zVVL*9nfsRpbLSE+1zO5>dC3>UgJRe8J{I<J5NP?#shRr=Uw-b;X3ubg&<Isp4@eTDNP{qeR3buGI4PF|TwG'
        B'3@>&%D|e=Bo6CJ*#Emp_o!cZuBuLeDmE)Nz+`yD9P6~gZ)HbovwtJP40ho0KqQN^4D%oBKz8h`f(+pI7I<=NzC<ud{isOyJ$g)bK'
        B';IDOX=GThUhP7_RxdR#j>APaSh}iy$%giiCV`_Z~3U#d5xx#%!PCt0qBz?ZmNYN-IM&+z(=<uViGu@nn^A|qxQf<!JYtlG7OfkV%'
        B'+Mp2%Vv|WI1T#Y+&lBmLaxxjGQRs!djd%(3jc6h(qEgTnl?USCh}c@{v-Xw->!|U(+P2Ve7y#6QUh}BUc95-%%uv%d**!+>f6NH~'
        B'%8R&?7pX7f;JqxO;;(3_;KPJHyCTv+RDT5$e7;)E^xSz@4T)`8nSJ}@iF)|lq!icIzdRMa&^_5<LJI1j!1(+U9u{5n`OUWpA!og|'
        B'>uvYV1E_}(2t`e;CI-ctYgD~WPoGu;ZbA2S6|!)cQG&Lw#`E{X!MDDWi809a$=nSQ$$2t%jWBr+9?h8lIWgiaY1Cs2a!9X1eXcMZ'
        B'>a0XwBQ3tBe!Jo|`Fxw9IQrgg?lL@O7i^zthGO5x=FE;kZP%~Ed7*uI^SLAd00000ZoYOlY8l`z00G?&girtgk!nKRvBYQl0ssI2'
        B'00dcD'
    ))

    DF_DATA = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;3xwG!(9LXXa1<j8xF4<9XTL@e>`9giGW$uIsU}8<FDB7=H`o7@V07`<VP)#C@wZAeE5Y3'
        B'TVfJ)c8uO?b=Q}=5WMxDwf^u$10PX!FuvGah(#U81@W(AOGS()CyUJbDDss==W^v^laD-+m935kkB|}h=q9gZvx}`3DrIF952CT^'
        B'Dg*XN`cx=cBP&nvGXOXw?!8+J$?LFfc>sINd?9D8@b_MS^WtUY+DLE=qO@PgL!DIw`tV{qP`0Yg`CO%mzg9Lo$1n*a-f=`Ky6u#A'
        B'+mV(O6<elzHV!MlJQG1~LqcKvWaX47&tE_9?Y3_;5S-f~z_~PRf1^#9+WFgh98B)0sMK<ISylT+112oNS_uFzoS=x%RA7+vwT27o'
        B'F3>pVyrhCpl+;|?3>sjS<Itu;!4L;lPOQHeHypT};*r|VM2CHEsLTHY{h?GFZN05LF&;*UTXtv+hak|>OioNokCqyMHCLRK{v{pz'
        B'E{u0X*q!16UNGwNK=%kE+{1#E{=a=(4zjd#=S8ak4?S0ep}7h!fA4f2IQfHMWoYlc_Y1XBu-TY6y^9YoK*G<!8JhsW_s+rE%~{*p'
        B'*}@vREa2mN@S^sgj0ZPH{qdoH<cHYEy&epSgDKhGc3(1vT4bd}c}dEEC*&Qj#_m|lO;GbokTu@BZa{TZ<D`x%0-*h(GKvv>ln{T?'
        B'4n;kQF%q`sCsm{9i|x-FmhOpOR>S3iX~p#{a({yc9{r1f+`64X7s#b4Sy_;4L}Mjzvds{9DuM0lBxrXS@(2Bp-D=!l`r_5h$Jgc#'
        B't<HZqfTN~O&XrjFvhV#m$KT)@{?Mqc^n>BtO=26(QWFl#G6AF)=%8YV4cL^)$3`^GPt>aM%XmGTzju^;UH}}Lu1lHQuVQ`k8cUH9'
        B'wvEnJ6`4>b_<~hSqv^=kW^H3d0nY1WMTN<F?onZeaR02Fg6-%U*3oAZhOY0l1j2@7VSa%*IC^mX13X^!(^F5tH=vl{Mh0v}lKu<e'
        B'KexK7Qdj2-VlNJDU{cG?kkJp~RWvQK-xDBD*##eOTQm`wwISw~7CyOt@6z0!xmTKIGv;>U{Z%R8J0A@y@n7@PZPZBWPgQK*nOQ?7'
        B'-n7@RiOu%783(qSVWo|L0q!nhv8HlrWx4t`72dTc2T^L=ZJ!_cbm}{5;N>`FD%d%pR_a9bC?>Yai;Xp~@E^^T0{5-Ym<B9Wc*b3L'
        B'_0cD6oJq^0-RWwj^=6B|BuL6%i-|0S6vo#7o`$&WFySx(M=YX=cqH}T0}=DPT$~jAaXLDoT^Fn+g{It}0oTn}o$PyhC`0nWQ;#VZ'
        B'T8^|gm#6_v*j*66Qle96iu{90eoF0xsve;5U+}OI@TPa=hzj0^?$k~=yjt3GU_+ws)tQmAa4l+reX$BeUPG`mj@!9LepiL;ap*v<'
        B'`PrX`Pgl<MluAvlA5hPJ080TKoJ>M<1yl90KYbv2>qO=hR~0)WgWP$lTfyfACxnS&?5SexL^oEFLkA5$6{dE~Ju>p{{uW*iMy7Qp'
        B'#WM>;qfrI2dsFp{WLhgxzMgaF%7;b;9Nb2=VG#ly4kKw3U<||l)c|H6G_ba?p#T5?zMUo5k+MbW00G|#girtgiWjOQvBYQl0ssI2'
        B'00dcD'
    ))

    ASSETS = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;2;A5uU!BDXa1<j8xF4<9Hh8x27*Tv5(EoDYd0anEhE1Z!Q8lm=n#p8vB1F*pWSkyYvxMv'
        B'QcFuM`ryK<xY9hs3~#>mD~*mdQugZfG0w-$nn8oGU4tXc#1QG2E_H<>*E6)Lf2ZsSDldGj&h#k!xm<F*UxNYS2v`b`dRzGK)q5K#'
        B'8cPs?(;Md;)A|;L<HsZQ$4*A>{vBdm(<{7Ybe^aYBSEU3ma3ECkshBOcnm`VXs$n0Q&fS68yYXh-ya_{VR5H9g?0YQC|@>Lx#~me'
        B'?1!F4Y&~{Cl5FDg-RJyW9-+MtL0AAuEL5WyQ#zms?Z}i9N!N)C@(hGRluse0(x)kyYy~gl;LVe*cj+}Cs=)wUVK98|((bUckp<T?'
        B'tZ8)o5$){~9G8mcY_giMgs`J`-s)55;J9M}dXxx`e|=ecGWmyl&G9XkGMG&+Ia#~Lwp?+R)P(H-SZ!-21=Dd_Nk5;vEtes*X=kWK'
        B'f$!*LWflk-=O2Y;Y3QcG7_qZDj_W&Fr+oOQnn#=;l@)MI<B=8Hpzz^F4?U(v824tW0uUmwlwuM%O~3#EWMl1txL=OE00GMbgg^iQ'
        B'*6e%jvBYQl0ssI200dcD'
    ))

    NOTION = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;3xwH$z1>dXa1<j8xF4<9XTL@e>`9giGW$uIsU}8<F6Z$`q5N&RzgN19z9>Bh()56?URJ#'
        B'l4gt5JxEGG%JSaDwbOZooi91Plnik0gNP!O7HN0!b-G<|rpR55rLcFK>b}DT%058uf#LD`d7ZR^*FF`HnhttS*s~H{Z6PC))$@ik'
        B';Jg6-x4=WUca@mI{_DG&aeT~I!MjWP^AlC)AJl8`1<kOcu<V!C9Azmzkuwf+m)<eKf<-FA3G|os%}~B6va?XJhzejZGZlV59+9}q'
        B'G~Q#vRC(hm@n?{9`VprS4C@TJTbr7tD1Q%tKxeF_jeEbX&}8xX5zs#hvaoEMdtQK?RQ|8RwgHMw&I=+Q{#st%4EX4d=sq`PP2dM!'
        B'-cyjm8H-d9jimr3jsUMJoY3F~P`1}KJ$6irm7^@|qxgKk&edS~kNXPA)uBs*;Md*k@5?~uGRaVO87Z@T1B0m<F=k&W4ijTI><&*k'
        B'HD#=A1@W}*>=Q@CZt4UmDOU-w7(1>Idj2<#`-0(cPvrUaz9a?KI+4k2gW8gIq<BzYM%pLjqb}M5ZV;H6Xrm;cIbCDRQRq(mz?#ZI'
        B'*OzKPy`BOpLH`ZmYRAcM42*nNlR$N>4A33==EhDdlRD~cA4YVS1to#WNt*LenKtIJN_CI}(YEvJh(yC2-BU+A5_`sBYoqSqf%s?I'
        B'rW2i5aRWykR5w`Y@n^DEevL<F+iL|0WTCn7dAfc-#8{D0)Nso&gq*Pkz~i?%YDXPGM$m7S<evVFBKa`v628^E<b#_;B1XZPaf-&8'
        B'FR{ftyT!BW0gA=Q*|&4Dw?mSGD|xQ_(OqvOCWA{AFR)_%<qvt8Vb)|l3V{t>hZK~Wfh%lC>O{M17_h@&Uz38bO+gb7)bTm-gHcS_'
        B'CCsNLNgb)&AclZ~@hKlZ#rfTLbCapg+=23MZ_zam85!jNgFf3rDZ`#cSJO#9|Lm^5AHH&RYVi%16o*oJ9r2dpPH-3ggF$i1#TQMS'
        B'Gl%!iD`$4f;;z?h5a$0cBUfRHFot>$y25_R_RsHir@OCa!9J3w6{4<xP~I72v_Ln*M1g4O&R}~V)1-|h$&?bDFo#;A_{^fatmX`m'
        B'_pU#nCEK~p-qGqP0bZ%i<9Zy-I5{bO!sfW*z^J_3lzlrAwuLFe>zAukARkv2=e7}Q8|tmMX8CB_*_<+F7mT3k_}l6R=%^H*oz3Y@'
        B'y-#^B0N~lXijO3ycA@MXc9$nVN>a?zz;K}>SHO@v?!*!GE5L{J_oa7%S0Iw$Nw8p2I5<Ao(B2`#HBwAmN%Ko&S$YkfhQ-OQ6kkGm'
        B'1zVfx24vpI$rV8wT5QDZ86mI_boet6LB}p1bQ0OmXy3067ZWS~ay-RBq*T2%c|X2&&|eX(H7F2hA%d*0?>}Dj@h4OCppp;vu7(K7'
        B'ka7`f#>tO&=N|Ux1cXg!J^hf<Nf@{<x_A1$Gri((tb|Bu3+XPOKon}vn$O}eiF|ZW^0LNN8G%|&Q|x7N*H=V7?-U^iL)M;y17%wh'
        B'W7%~Eg29iNz3y7P!ZlH<H|XzG5LRTyvdoQdq`vxZ%_Pq6RZ&F60=eqdk~AeK<ynkKBSzF;`i^_BUOI=QJBRLv8ntuZ5tUn%2G{6('
        B'>w|)J#j{oS<hNr&esfJwaEm}}IYolb3p-(J$ykZK)r~;GKKpdV49oDxWJTqxOe>zn9d%kc3nV8TISdlxQzaBsog^q$&9By}C}5RM'
        B'P1PceP43|g@b>N6r<A<=ka+9NbHq*ySh_xoiDGgo6w=SBV8Pn=gY9*)smfq81voL~77@&*vr5f(%j!$w>8_C5crpmy_z@bd<cZV1'
        B'a~a$~)@IGwf?%x0d#b?w^XbE2^Qc0H5(D#kX#7sM*frTem+E($1TONX`7=2fJ)e8I(mv1`8fNT!5zYv(0PLf(>n{}m00000B57;j'
        B'%Lh7%00HF-girtgAz+LAvBYQl0ssI200dcD'
    ))

    PAYLOAD = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;1~k|23-IEXa1<j8xF4<91sXR27*TmuidzpfgKawK2l}n$0oJVdQN(5lb7E0Hndi^C9D_+'
        B'$juHJQtcABPV%@=O34DpV*zFdbIM>v>J*v`EAl_-YLgyV4D24{{&orW0+%%}cR^6u(KOSb;7hAQBJa*jFjc~h67fnoUqOBVH!j7`'
        B'bx*3T-$sp%;8Q;TDJmy3tV;+h9wGJQg_eL-iy{K=j|(GGu%5Tk_$hir;uuPjQlrjCZRLzv{=SQ*`HeVxz6Tae$45ccjY6{#YRq8U'
        B'+F;}Lwu}p)|3`1tgrE7gE~IYgxB&X@D<Bw*@cx7gf&@sm2u&wG7t3{~G{Ch!TqgxU00000KsBTEqDkQ-00E)`gfIXAr1KH0vBYQl'
        B'0ssI200dcD'
    ))

    DNI = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa761SMbT8$j;1~k{++6?wXa1<j8xF4<91sXR27*Tm3ZGV^ZT5T+`T!nu%l$fUHFlkYYr3)Yrb;*mx71&u'
        B'X^#+_LSY|jX0<`jKl@T`Mb{T@^PqQmH?C+PbSNf$2Ha{!5wUhJ;0Le(M6eJ7mj4xFC%Axps6D@U*6fn0<J2t}m=@3$$eYYCmlnLQ'
        B'B{XOBxvwBG_IYKMW-n!LEPSGh*e&^gN!}#~z!AaKr;@dsT3(>YZ3SG-a2l`~5)Lpuy1uW9HAwzbyqa|<<P8UIrAc;i5uYbhT4NtE'
        B'%~YF9?||MPq%Qyf?Wo}g6o0$;00H;`gfIXA<)WlPvBYQl0ssI200dcD'
    ))
