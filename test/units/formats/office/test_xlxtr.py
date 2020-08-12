#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import lzma

from ... import TestUnitBase


class TestExcelExtractor(TestUnitBase):

    def test_regular_xlsx(self):
        data = self.TEST_XLSX
        unit = self.load()
        self.assertSetEqual(set(unit(data).decode(unit.codec).split('\n')), {'Binary', 'Refinery'})
        xl1 = self.load('A1', 'R33', squeeze=True)(data)
        xl2 = self.load('2#E10')(data)
        xl3 = self.load('Refinery#E10')(data)
        self.assertEqual(xl2, xl3)
        self.assertEqual(xl1, b'BinaryRefinery.')
        self.assertEqual(xl2, b'Binary Refinery.')

    TEST_XLSX = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3PvDAzc6{61-q2m(dT*lz$@h&uisO-M2S>G=qQEROhS?T`LVCl<0*Kr;j=qGZrTMa1_{74oZ0B;H_q6z{0fO2`#4p'
        'Z(%@Rrb2l^+DIK4qbHHF_tmNDpz&Y$NlI-C6c(59S<hkLEM^A)s!{gk@qKO#f!<CU&7G31h2%4o%gM*%hC-@#t>rmqA<7aPOjP!YEkx*jkYln_Gs2{7ZcSSp'
        'k%^+f{8_0fK#=AnGd4nKnS~b32=88*Gzk18vHibqY6IP;P8rsEd*hi%t(hYl<vzGV#mly+rRuPU?H$RjiOhkC&_Y^=3@n*lF-L-p{&*dA>A$-1cYhlULYXE~'
        '9lRf#_`OFa&uH^H|E#>F1+<slwderZG)kz>f=O+S%CnbmT=-*EXvyp=?C!#p@e|yqJFol$s>T6*DyGIxp^}#q4f#_*{FEDNWty4CtIr9?l}dTd2ZvRe4c(lw'
        'DABO4`<xHUA!rFO$CY0pMP$7Ch|~lYzBzW26csva+1m`if>ts<6(kc$R^2wfYI_u<Q|ve2LG39foqnwf%7wRQd2S-u4FHQJN@YT;52pT!6{VrFCidv$Fyf;}'
        'rH559u)j4P7JILO$#(5+ZYcGMZALFyO?bVadG%NCWt)~F^p=Pm29lCFbYt)Fedzu<1zSy|M+}&@hOGrpf$f_=Y#DSA@|#f687|=g$UxDWWJKOTp)mW6TzZ=^'
        'p2l)f#+eE2G<HArbYwZE!pb>bRES(cfK<g8_b)!Kft2?rXK}=vK3~G(CX^_QX)BQi&gU31F}4c4VcB7TrBk^r&0ca1okiuv1q4^388j~{y%RNKdMWD;q7$3l'
        '#C;mMydS27!Koh*Bsd(dJ8m~*nz#&cRltJuz`RD02l;!L145|lg~%t7)#pZ6bT%^@aB5v|Mx2gU?|0@qMh{gR9r!(5QDnF8uc&l@Th{F@viY>d61j#TIyb8X'
        '61@K*a|ghIpbVLNf7H)(W5>emQ41R#dw<#Af~ZpQO|)JqOd_Vj*kk+pzMMj@w+^G{FQH|dL4#ia(qX?XVK!~^yYHeq(&}Ngxfz31xqCY)rD*@_3Pyn>pc~Wn'
        'MYDkF4kdF2tAi&B|JQ~s4)B9`NTUl4qos<(L1M+~{2d!BjkqBUb0%v1*kgIrF+ptfh}s0W$bSkIfJEba^sYW_lhRuUo-$5(Fftuy6p{|&N2JPAGBvqFg`%Q)'
        '1cB<NMLt8qVvugS&hO*6_B9Kg?C_=TOZyGd>o8}DAXwo}7%+6|%=!Q&@h){<N`TgzUUJ67cJdcdXo;y#hyb@#8t&HY8P=kV)6}2jZhORE^Qab?zfQf7B_xQV'
        'RK!+xABFg{33KMQ{4`>l&=iyiPUfI)c<LSMZ$G<RZa2rC=p3JGN`2;6a?#<4(EV$(=VK)cnGq^2NNZgPm;XW_n&r%)Tv0l1<R+xEEgpr*wA|*#_J_;WjMhx*'
        '2_V1cq6SWKO|ImPFM#_s4uUlRF5$o<bxhE8EI!Cp;wWYl$Rwb5FtH|uR2(*WCRKe{RcePa){nOIYL{IHzSvbnG=TE4j4@A1=U$eDy?6P-nQ|;;P(T(jnSv=m'
        'A&Rh1<Lz=W1J+!8u%iw8-_zZAtJcr2%@WV=+r{F4QyRi-NYdmBUk!FaGe5&&sf5vL_S1fe>CT`VFqQJ@BYH?72AFt;%Y}5m9zy2-<(iY_-&tjDSa4w0OtaO1'
        '8tKtv_^&+^2ur(e<A~BD=}W({XC6cTLgOQNXL9dl25Uj~y?U_xM??>jmwHU+ICMbW#mHy;%;FmR7XxDT&|UA)JmOx6IY-%2Nzf6u%Ak^&L#DrA=cJ-qL+2V4'
        'QaEix%b9zxe1xNE5#G23ON{#;_>8Kk9uORLt@ysrPLTL;n@tE%n;XrSU|Lbfw)ow=_ou8?#%|lEmF1WDbL}FKuGMr+{x400xau(;+mVCbvi;c!7;xGT@yFdV'
        'O%KZ3Zd7>8k{6`<kvAq=;*cc=8so}&t<|n@0JZ0ilyz;t_j^nrUr_nSS-~|bLvwY%)Eezn(t5`=4(yJ3=C)R^NZ7aBvqw##zY<>uu=C59T>6kOvA{kgk@|v`'
        's>pkG(&hxNnj-cSvL;G~#$Ew`FZiF$IM+7ut?;osAW_o%bvrhoYq6nZm9@=HAw>h4Pp#i=u)I}zReJI81}J1NlhYYmCJI!K?zcp6@Y#8Z3MQwQRUxzknnlp5'
        'Rl_cFj`Wt<CU*@+s1`HvyHy~l=e_`sA<(R)nIRh{g7LFc>#eyLlRNK~<0x(GE1^FLwOTD6)j;!)u7?|Ed8uB8efa1bHZN)eQzTas@ce)BAOmvmldGs|(&vx<'
        '5<<8Fy}}2W=u;!65A`@sm;bxZvSJ7?a@dwF?Hm9qA<e_Li%pFt+<IhChQmdjO{g%kg(jDtI-dwJFT9Gy@;{Nj;_p=$7QGZ6J(<db_mP^Z0@hL`fMm~^emi-<'
        '#U}<C;1S7UX&q{)L&*;Bb4F4&hy!RF0|TGtm9!CB-zUI~7+XmC5f#gR?25`_79+(~-tv8S?S4f!r4*c$F!XRrO<4{vh^|w`l%t?0J>547bF1x6nFKL1FZME8'
        'x>xF18ESM1s;wm*-x&m$NDpw?@x=<tlcE)STJnr9{NuK;#i6_2MYCPl%4Zq^9*$^R372ua6jwv>oH^mR0ioqk%%)Awns;#lrjXkIhYB_Vt*Pr*oTgse6Uazr'
        'd)yUnaZ|Z`9?Q6aTHa2@m4`pd_?E;;Re)&<*otbim^DZ!V{~?+t%H;U2&V8O9CkMdW*tOzBErCD-E}{=Nl%~-`;W#E5$bMF8A-TOVDt09^K)tTG2cvWxLh%9'
        'cuC?O7rL(QbGlAASV!M6dTB)pfy|#N5k4(Mdd*7+Mb<Fc^fR3BfFeEzF^|<<jpBXBM&T8{-77eX)1)UjzwbB1E&LZ4khDM^66En##rJ{5FB;62)1u0P(WW!?'
        'lQ>ewk;iuv3T5ya!?u25bnj7}T|JgGJ#9v?s8&4#t^H+#psB8+5X2Nb(T)9WO*Vt|gLB|i#r-n1JMfe$j%Ph5SXMv_Tanlh$I>cVX}KMHqanK)`S{y}?Q*p%'
        'q?-9=^4NCH4UFSGW?!(CtBYJuyypt+p0$nV^cK}KotkY2nSQndYOQFUvFVS3FW3?x>5yfLCco*5cW<@V1M^*WZG|(A0JM*3=9Sna%;2QH>md}mDc9$Mt3&b<'
        '9G4eqoW1wvVYXkau#+Amms%7l0aoEO^`4|P4TnM0ZoXb_xoe`WfYVjGR)VLd+Q_@wE=eFJLr%5%w|=*hWf977@eZKekfJ3;&92d7q=M_xzybcYrXD3rWUx7T'
        'YtP}VErR+Qx_;gt-vsQ=`UR=~2p9|w1mvGLTHTzpFy}ehnsV!-@9w;Br-4Iy$oZ!4*Ll%|=GkY0?kD^ebMpDWalI!>y!qU=-PH<$+%SHQox|bdqM~E30Lu?y'
        'n3PZbZ?~4RkXMF4T;wYcr7pG)Y;}^m^8PA7N*9B(6278}V(4CuTj{g8cnHCBjFEVl$#zR(-FckDWBH2kXxgM8VN!zSNkFRsiLX1J0e7IR-ok22b<Fh{0Zygn'
        'a->J1Tx<^V>tdmaeJ-AACUvHtR6ZqlAQc@|nfUvSjY9l8N}O1iL6tlkQNk$0EBJwV(D`Rl=MKmb{EZ(M+d9%;77%vNLbvj%X;Q>8k8h<6zf-kMENA;DDq9?9'
        '-c<)(XUOK-37=JI@*2_!1<`E;#sXJ^h*;4qBLW;_Mqdg3;l@sO8%u?U%P9drSYd47l>^xT9m~sM>V(|XYphyEM=oa(c$R$_SoS+4>&;O_fr;olaT?C<i;vRU'
        '>Z8O<b2dxzIAJbmw!O!q;jOe}<&^u*MaLUU@LxD!+r5~a9H*A^$_=p#3ZXmDXf(Ty2c+E9sKficRn4c|8+AF4uuF9VhW4%}>6syvgejhm`t$tpvg6Jz^Mj8-'
        'eJGh$HQ4_nYI6{Gq5tdgPaPK)6ehDCQ26}`@0(w}Y^jsD<S<4|2sfQd4)8g&VMHyPnhehJDk?3y@tj=^?fTchQ<Z_k7Q{seld!f7y2Ywsq3-BjBL~RJ=5!>)'
        'HrxQ9A#UUcI9OGd_dxu$A@8Czd8m&#<QJ`NMc2=__EFY=>wz*j8D_g9qx!^5p-44yDeVK-*Gq+h`Egsr8Zykb6#8*Md3@|MQtCqirE)!j#`xE3#3A;CNhhW6'
        '@xeBsNwb7OLeXHM-mx$+KjZN~rhI!XRzXlWcBNb!0{QQkA>m)Ta~ke$Z)|_T1I7V2h|AKhLTNs87A1I@LGcUyR57K}(+;tyyC8y-FEcM0@?iXGNBemODlLlH'
        'Mr&W(;)1Rbej$uqHn(yDH1F0kV@~eFf?-tYTXATJy75xajc$TygYO-K*F4I#iR*jVbT#0Sdc1yVJ~!nF1^f>mIxj#WHstZO4$~XMjt_&5m)E?ylIEe-l>(D!'
        'Mw7{vPF6HG$F-4mG8(?dUrM(jcMhCc>w~{Ex93TcYS@D19c^KVJU^TjPDbY1#=Uo*b{(Gv7n|GEQI?et?&_b)@xjCL01(3wMnc**8<dg)VsKfN?;QKq*-WZ)'
        'q@;?J7@QA^o5@YrEzLRbqL85Xn}ts4#pD44_rq|5fCqw#p~C9+4;y)=Dp3c|*;ZXTMF8FuRosDAR|5(w(ZGuW>E%_fgyG!r7?lqe3%xP?6V05D$y(VTsvUOT'
        'RQ^YFF+kR~czqgECf1UH;jIk8r2hg10EZw_%qg1HJbY!EE)z8(=N8PB9wvri&LcM3CAHa~Zirs4h%N)MGC{rV+dfuhiX)QYc8+1rR=`2V+zGHRbmllDEAxHp'
        '5<BjB;1rT_p7x*Z(v-bV+>i}0tw8REAnOZTGG7W$nnx$)6{BQ+R|g58X;%wAPn`#jR3qZx53X`$$S}|bEg91k*?nTro+A~2&E&c8bAL%TiOH-=B0Dj={_BRs'
        'zN_c*A9%woCER;T-@U)QT6Y*KB@#oPZMMU^)_cLl=aG57!=?!dINhxjR`Ad2cib22ZA>g)GQ}!oy<&=n)X-%0d%FsL#aNFDW*P*JZ{;gPC=bY4!wS)S?l&6g'
        'P6jM($%?=15;a!OkD@n`fxgQD^$w&KfMrNsA$(M<5bG)@`poZAgOs7zR6<b(_4gthE?vWQx9oH$gktbx6#eVoF&Xe5SGj?`c4Ao`3W{RMIdubs0e`X_6hiFK'
        '>wynbkbfB+=3+_Q?eSa6QO0d~q7yubxNApHZEG1Hp||VtF*`Epn)YU>IO$zG_leh1K>qkB&wVr6gi`E{(q4nMnP9&;s(RCZ@vfO7zGg>mK5c_Y1Sg6{rCRjF'
        '>nlWlf=PT6<0yV|00WvnG1-5Un}Qq#53Bat2Q+!&tPTzivUE>N5ydL&9B19kAevrDy(wr<id^TwwLC1O<k;_iWc3Al{%JZBDtYK^2QRE%g{XBQK>RO)dC9ur'
        '@dAER%=sun5g7ZDw^S%4sIPS^s2JBddi`&zG>k9cE<1bsW}oa3e?YeDQ&KX<O;c9qMe=CF{Aa$9kInQ9TT5DSP>=GYt(Gg*5b{QCyON-vRaXXK>xC<i&$tt2'
        '8|53#7Dg@~Q`bM<Zrh)ti1;$!Az6zi<f(9>`#JA?QiV1cR(HH_v>Ov#2ANK_#yB+M?#;Nxp?jzw_nBF?R|2yAURu=_MNoe$F@vzOw_rP{es)Mih4nvYQqY%f'
        '>%2udb2Id;8z%n8M|N}@WUOK6lk%1+62-uL>X?x0^(=9Y%o;c`$8#a?kCmpiihl|Q+S^8)dNsvuEqmd)J<2`*U_(F9{q6Sj<v84blBU_=ikeoN_)5W<J!VAw'
        'Sv$Ibl}+*I)>Qi(5y*2+-JLaxaUo`dNhioHs31)Ge(_tp+tQA>$|Gm~rxc`xRrz3dgbl<pfRlVz)6nvzGF>2$pK9lNm6NZx+A;1hh!Y^wq`e~y=n}-<6<e4<'
        '`*ul_NDY@>-g1WZ7hMwR?&tw9dyu+yY)xfY(Dxz$RK4(dU`!)mqVpN&qWD~f^V+}I=fWT<KC$YC_833-rC&s|-&P@2ne_N3A*te>b=X=Eek@lN46s;fVDhJ3'
        '^0`2@#<^2lA)H$6PSfhS?T3)G^?2IsKn{*Dcx9GZ>V1;)^ERS%jQdawwN@DFWmV_f?Max{4e??;&;7K<!{h(WPyGD{+@L*u(wzmx;X?xF{eUiKds($%ES*Ym'
        '@~7q)`@30*YJ|TX!8tw+6+2AlC{V-75h&3sf|h$oyap$59-bkLE$lBVKy1<dt?%3gfzvf!xPmrvI?%b7BV-?+9fzF(^>Rh&lc!B=7&O#O89HJ}8FtKJ8;*`G'
        '#oG&ackie*nZ<;gf4|RfL;3yJAyqllmLUY|?+yJh`Mg~?S^7{RY=Fzu=lz$Qg`QXCXTenb*>MO)qZKpGp?w@Wfo$u4oGUgZBL8~f!=1#)#f($a&NhjkJ@-g*'
        '+|f`#ugApNgEbuU`g6DMU9FM%e5J^mP;<ieN^1hy#Qk2#I>7|+b#|2|XaIX$?zVFH1@WR&)QzgwuL-#U&fG=uM=T9yeNcpwB+pV^h(zB$ZU5<M5gGqvOeN#N'
        'yVgbJ5<P11H}3-iK3WH)3&P%7HtVj_bQtmFcv{$s2yL*)Ii>v+ikrq*68vX=BgM4X#SvNA<ltrz-GE}KFtMrB(_&Z~V@}q;HCn15$x(Pijd=!-;U6Z~PoF&^'
        '0bkjt88le{rYSw?&3;UjOaX^gf3jGo@-xA5b()&3rH;aQgcyLDn(s~vim6}iRS{UhiHDj6J>u2XPyEZpPa~5t#8t}Zs&SnD&E{>^&$saZ?Mq`u7T-2s^Y-Ng'
        '5)+D+M@{nPIEmmA7yZb?N<>N0X_d)2EVrU~e?CqMCxLH~R^AVFzT{4dEXfA5k3DvQzw3Hs$VEW)xg^+5DPt<^7U9(JiWKa~nq2hxULBb*a&Y))x)#rQM8Z`j'
        '5Mmpf+M1+Y+jwRI6l<q@v9rV32JHH@XZtkinW?VkC)c278{WH8UyCuUxSAM<df#~$a<VV$$*tKVxAvl{Ax%2MO(8?<9gzDAuo(}9Y#e<svKuK1bD~XdngQEg'
        'L7nRHl|{{+DiK><=XU8^(;|agSqoyRyOB8*W9)6x|2vRE#7gKSkO^)4rPK~0v0)}fs&ZswK%<HY$uk`?OTLu>pD>T&rdIcf)>1>~PWqh-w8JOS&+-VlyMsOK'
        '<$oB)VeHgqUh%v_4krv{i6I|6O&`lof_mK2O+00|a#}BwG(2&@xM;48<nSGP3J~DqIBzs?Qy5Q-@Kyh&!Fl6@HL+`8)!~4;G)Oa=ex1SlfM$5+Zs#1`37rEW'
        '!z>3k19J|3fFOu?xIDa~SwA9%l3cKzCXIk>O75p|Bg)~|2;&k|mVGr+)MWRWCz;vY*&2yR97bK*S$>Ualdz*yplSY%%`-Yj!e!v%y*ROG3UlCsxgRcY70fqQ'
        'I+EX+tv<@*&DUsq7bbCHUntXdFs5vDGP@MDqpto`ZT!$seb}vPzciItw_Z$+jnO(0Q5Ge{`CApXVtSioC!~KF;1mjl7zHO2z0YfqFLzph`avY-bbj?E;T^30'
        'M0>~Bqjf8;WegI*+rs3kK<7hqTBy|v&jIUCfY+C*1mZJJbyU4ZEF!~_=0L~)Q#G|Ii{z+<I;P6A(s1E(@9b>FumB7oBm>X(NL!?}$KeF2{j3Ul)B_f84h4M5'
        'r9)#GV2+28fa6fK6R4CHHh)K#0Fad@oZV4_Gua#}uAjxJ*>@g%+T|%ID!}k^BS2Je^`Ky*>aIoivXvF>-dgPgyt#In;bPorwRyWMLjuMWcW+c-9boYE)8iS>'
        'q!Em8IIPsA1Y|^Xc@jro(IP&#10y0;na@27uAd3Z1T<ga0jjkKx&+RWCtm!fw0>lEr)3m(rj-=U)Zw-<dl;K4GSxkTx(VhK(SI=UN7dA?Lv=#D>Qsd{nfTXm'
        'pxA`o(dC=F2E!ILT@*bC=AU*b$fz9Y`RM+&%tUiKh(1zr0b-tBkC^=#vjh`Aw~`^(Z}03wRH!x87TD<`J_|NamNx>q96dEcpLR`+0~*>P<hAWD^Q;hQo+5F<'
        'jkThMTR3~)t79?MN$7I(KMPx$mkUjhroGlDzyqi{sBeG_$w)uw3xyWMeG8?|PVNM@^!iEg8ZFVzg+!q|&_T%AV79u_NzR%3;O-V&1mRqcD2rPxeHk7RDVwj+'
        'TW~`L2g!$~bL55kst*mQ@YGUoVM@Q%(QGB!3x%5Ts?P*J5jLjM`8si3@#uU;K+U@o3R88*v$BeZFy>Z6<)6zkIfDg$P{F3Tl%R;1Iy!4f7pFwT{pda1v(L5Y'
        'UAt4vr3g<_cO7kXPR6q&HzDpZU9JzHml~E4e~KjPSIg1zc8JX3ffWqT3X9rhxdhiZcI14+hrSC3geN)~9kc)SH6NaPEv7|+!C8lhOJHLhpn<#SnL<zbQ`F1d'
        'F7z+X3NUnd;Cc@zZzz1@J)*=%vm5Kr|KqESpnKN`SrPmK$ZOI60Z#t#%ak|7wNPLIs_$bSRqYTpZCMnKd^q}R>)k?yVOgo)24Y*7v8)rsT^@GGq}6!!?oE!^'
        'd+U-g60>iG7RE;8d~$5Nais62-MIq@rRX&o)QtxeW#N_%7vMGGro#IN7SIar0k*UrI@bNMf~JE^W&+Qnet4Kt7e#+qzFUEV{w~l8@%_@&J<W=gc7p!^u7cs7'
        '000006<H{x300yM00F%;#7F=D8E*!*vBYQl0ssI200dcD'
    ))
