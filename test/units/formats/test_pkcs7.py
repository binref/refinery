#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import json
import lzma

from .. import TestUnitBase


class TestTarFileExtractor(TestUnitBase):

    def test_parsing_of_nested_signature(self):
        unit = self.load()
        result = unit(self.SIGNATURE1)
        result = json.loads(result)
        self.assertEqual(result['content']['signer_infos'][0]['unsigned_attrs'][1]['type'], 'microsoft_nested_signature')
        self.assertTrue(all(isinstance(item, dict) for item in result['content']['certificates']),
            'failed parsing at least one certificate')

    SIGNATURE1 = lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;5WAvF<k%{AcE^E=O>Sa;=U-fb<qk}DiB}`2VL~3W}sd*dR+R0{)~K^oc2*Lvmqciwus=;'
        B'sm$4Y-e_2Ow%TCECA2H@kVb$F_fq>39qg?kh@!XeN!LYVz`|`5m4QH}oamB5Ty=B+G;#9wtuyzEk=wq~jdMXm;q9B>@72FHwsMEA'
        B'6WT*VZ)RCyWNIjC7B1Xf=G;Xxb0hM|JEp7F0+xL6(X4Me(VX-5CVYl@#-ikv5oG0Ndw;U;J5b>21;ot(t*}Y<df7Q0`Hf=8yL}`O'
        B'a7QgCcQTOIwqON#FnM6%8!`nol}$3DTQHQMoO33HgT>INy~OX?F{L#BAzp*}i@DsIgXu;kbQSb#4vZy@Sxr@Z**A>-zZa}Dsz-qP'
        B'(d|tVlJm^skVX_-5GwQ-fKKInSMeIz2i<SrvAi;!yLzrLb7#$UvB8W(6m2~ielYng-7lB;EYOR{(QW`a%wW1STsU1K^l`{uEg(O@'
        B'2JN5y2z<QM9EP*hNe5pJhuL$ReLXOI0>&RcABry364IzX6;9V}x>r%{?QLokOSO{80H<Oj6waw!Yx?9uJ5{?3o}x!$oCFczjnTMF'
        B'*jo$KpC70pZ|Vdjej-CY-36hLP2NT`yTP0-j<ni#Fa?r?^H96?N&pJiB4({q0y<<&6){8R@eE<#CWvjzsLvsmc$xEzFZXM7;dLC4'
        B'%*QT53%+rnSu%9=yNAW~ScJ9#_8kcgxyLXYq$xftN%=^o>&q%Vx5EbbiB5#Xr2TeaN6ywgA&hG~l43aKVdM{1=)=zq`KEK7Nr}8V'
        B'(=-oW&axZlBR_$-pGh3YmQx7-|HO*tb1++f4pvU)RTa5Bb>dFR2PbWe2B?D^-imfDp9vADW&2_O34MflZG)j&Vt^kozuJ<K`A6Hh'
        B'p-h$b^vFe%zf}~cTd{<TSLGEN)j)%9#@{E87V2io$KM%EH&C<+Up<{@g03_$HcG<r^El&2*C!XUd(SD=U+m58ihj|r#IPM?ig+Yi'
        B'>7FGW%5w>f<?|z*3gS(^EyfqUx^0(eN&2U%A&!F-m!i0<LuW|bx~?n9t<zuF9U?OuEQ<xzA2*<@Thh^JE7<SLPvEEP$7qzZ8S8Xd'
        B'eghai?4EuR{G>nYWSBn=toLe#i47&w4r_cs9<b`H%034{p&iI%3_gfC0t-Q)%d#ZwZ^-)0ag5Fs{%vS_BseGi)rJtvf2mbKb>LHz'
        B'D6w|{$mDxh?1!oBFKl}hm1Y%Et~UZ<1=}E-%S7dGT&4%wjb!)Px1F}LcxNh}L$+&7Ps>-8sMNBC*DdnjjuXaOl~nNHffij!7t@S('
        B';|s>$|6L!Q@G^$GknBCxXB5o#vlE(V#R;uL0cu3AOF7cmQle8&N(C*?U51mI%8#i3&h3a7SKSF=m<;v;P3|{#TnWc^;cw<<A^YP@'
        B's)c9AS44;i4?n_@2r%L5&`GjM=VJy?A6;Jbz(<|ZtU))i5;{D15(l6PCgQTt`5y_lc)mS(uQXqdK8dRKc*YBg(!GS@QC5F=e@N+-'
        B'O(VU92_f{C^U)eXC!pU%<oBJ*?`jA}NgC$u^f~?o&quhr#EhpCk;R)mDOe4>HZQ6$F|_JXdR_DjpaGGzb>kN3h#!MgAxL+uU*KeT'
        B'a^<P}Z)GohCbso|!aw+)EDWjphcsHt`P1d-<byYZ^LTYZ5f<K}LwGj&5zZ#N465cb`f;W>Y2E4QwNc%x3{W_-<d6vuqwB!hC5hdm'
        B'5Mdenj3qU-Kfok!RplmD(SS2o19=2W0Yi^Gl)g{;7uw1pGFyzS{?C8zV&g>tA{uXE@!qE!d*tTHp^h0As_16gW@KL0oA&_hS|X+d'
        B'GG}TK{({4xnYVhEfJ_DF4BAlQbA8N}e5E*|W-Ey+(TOp3SJ|E0V9ePD@Xwiu%5$z3oMD*^Ht6K4^H0M{Aj@3FwNsEcMS;sgf1o3m'
        B'YTU$NgD4*$RDe&?>=Q>5Md;Xi<TY4tpA21qDq*#>;r$W4|1CJt33F5_h5>`Ca##|JfH{8`fKdG~5q*V_=;DBy9A6yP)s>|ij$p0('
        B'tMP!1%%%Nn7#!|}0-ZNPf!3}8P&Stahf7hd0%zPl+eF4!t0Zw$(o1o&BE9(wBb(P78~bwLeIL)t*VeZy;o^jZpjp$hoGyqedKnii'
        B'z%r#biLtRUH3Q+nnSQ>&LnGRAg*q`>7FIga#S~QcQRRm74I3~{Y9<>tySgG_AAItyeZt^$_F?87=PV~wT+)7LOizWk3Kf59+l+d!'
        B'k}5js(HS%p`cDwxx%f41EYocu$QA5jNfOrx?oOux)|G-x{)I=}$THY?y|1csMU8TQJfkeXo_Bt4E*~O--a|_{-wm7Vr+HPXgBDT='
        B'?#@p=fT%e5_u|ka-Q2J-N>!nxtKBnni|2@&i!UULfO?5Qf8-Oo(nUq|S}u99WB(7ibXdNI0-dL!*Bc`H`{`a#PUwjYq`iAU<uR;J'
        B'_^$EJq!x9VUbbLw7ALnI>@6tY+qx53McMr)>L0H78=wpUrd4Er8tYD^&Fmdi_aLuA_~{R;=}HBlaXMyupKMnXmUQC5`3sa*`|yRP'
        B';6<F!|C3+#8-F0SWo<XmH8TotHN;;Kz=a1AplM$H;oJ+d(|fVauOU~Y;}Vjt;$QZWc%To)$KLOi*`>Z%^G;z7UvMuSP_6$NsAodz'
        B'O^#I@$?v8~sh4(BO~TvD--lxASzQf!P3W&}U^gm}n1}$Y`)>akApHJuXB_MRuhS5XovTsXb5i5yd7p-G*Q`t0QB?OX)dIWjLs>Ej'
        B'#4+91_ZR5H=w!8qgU5~u&bf6Av5Qg+)#<%%I8Hw?*`TT>)E#Fk3`Ty(;NZ!BSiy?v9Ztph8qgUGpUT>gH66eubQH<K@Pee)37=49'
        B'f>fz?SoZ(Z#39gDt4%19NV?iFg1Rl?qvIkcj7tYi!{Gc9D&;A8&*TyQ7Sz^4fc5}c&k^sTMG?(&MBvN0<7_37)@0Y}s?LCFUc`h-'
        B'>HelwcqYY8&0le*cabTZUq}W$bL$o3leZ9Kf37Hoq=3~*Xigrz&nRAu54KY!N`n2h`L-Qiv7UH^0ML^6qG2<RQ+^n^Uz@M$bgU#_'
        B'W+5tuFnwkw{!)&Q`@`k|os7v{v&&I2-K8WBghjB4^Tz$Io3;g?e(d3If#@(|KPyz_HH!EU-yhQ1+VVjPPY5wRPVOw>-S$#2^8Fwr'
        B'o;)}M{%_*AgJ60Wx!!t|x+_RcFX}iD0zKh9Zs`J(d`VTWc08YRs+Q(u?_aD@@x;%I0q{Kd{8^8UlQ7q=9q>DM`%lVIGP-ppAvZ&U'
        B'E4#&ax^F+*!1Ih5#yXwepC>Vz8tqe$@M^r6r>(8YQ*Uj&<w+7me}N=#eZ{)&MNV>iXP3f%=jZ>qm`H3DkARQ2-~t7siuEG%Pf`u4'
        B'kG&Y}x9l3k|6LO-0OPM{f*c4qCb!XF#&b($0<kiK<MS^``nHm6%(ZVu$T>5iWWLA{$&S8Y3h+1FUR7JbjZLVoW!&dm)GcK7z-WCt'
        B';suY|Yi3Oi;bZZ<r*5xvcd_!Wdd&z3u)enpVS|#ut~jyaaV!j-58<C8Zn#w!L^*YFx}Xk!(waL;x^be=v-C=(`~%b$YrSQ~a`pKo'
        B'5^gX1!k<WFm!Pkc4%17jaE~Gd9`={<*zg<q{_Tz(<H9T6ci?e6J|t9BH)meiOu6atQ-NoCUYc@Ru~}N=rt!*Zi^E)$Nm_Yr1HL;T'
        B'3)dfDapI+6<&lI1Q!t*swe>c4<q6K%Bz|oa!i{ivCNtXf?yUL4vJr|01x6Yc(o<1RMN&*<y(9wo&t$#Nxn`|7tl>hAk;GVhZaX{g'
        B'd`-lreljN?i&`Fha*sgsq#haPOz?~>Q)bhG{h?lIh5`7@Q*6lKOxp5tiv>xps&yq2h=Em}4udH-J?)%H6N0?U-s(e3WAk+bU8QKh'
        B'b8UbakU4}?*`E4_`4qU(y#Y3Jji-ue<w=AO0B1Y2gZyPTPXnB|EcUP&<57hVGIO;8PE12tC91fIWWzv;VaFB-)DFXGwzUy;iuxOn'
        B'idDik8}Q5w381BmEU~7F?X6`KQ?>0HrO70D5M-2;VdZXzWxJoZ@X<N0C_k4a9qc>&oOPyXR*5tP(<K!|I?@<d$&u2~aT)0ipa210'
        B'3QWWF@{kebp5XN_hs4b6^wYwZx2IWf{cNZPuWcW(zvy8t#Sv85z<$0<s-QW7ib&PA%h;^CqLp`k9kgCMb_TBeo#M>HB4ks_kfo_g'
        B'O(DnBR0;8{<JN91cMNZ(Rr(kY*yT1wfAfJ7!feqY*gZftUG5x$`kYB9Cd|dafkge=RE~ekI}j{9kIQACD#T9pfmbZl6Em3>h%bfd'
        B'Xp#*V#qo5^g$8mpwXaO~+{8_b?u)sMNw*<l8`}gW<H!uhR|(l<Hy)uhql?JDMKWvRA??OFmE8nI>y0jvuqh*g1h89#i~Nik))^~2'
        B'l*I6NR12emsg{ASIZ(MW6u+gFU&9t6EYCH!atIZqDmM?ici36XXY_`o--w(EmYfHj_<OR?6l=ymUd5^U${oG*V4x_~CWWq=%=L10'
        B'BoX+#S<-uv(JH4>SI+`HzHi3DibXOl34k{hrBf<E+DfY#7tI*(4Lpgm4EXL_7n3<;Z8SuV>zfFenguROp}<|I;!#IV4ne`D&Z9M)'
        B'KsY5k_ixq2uoS4Juy9hKI+Bw|c;%=tNqZ_%pb2ghybu$y4=;hYajD(2>pvi0ZsImW*|1Hjhn(Jx@NBjBbZMC5d(v4JM5(aJ;>`L~'
        B'PWv7Lh<iFnkT-{RGDP~Z*0NviM*Zb?G%Nnv@hin39>a5fPJO3S1ckCdW`?w-mne)cb|ssDcw4&2fYo(ZO=TFp)D29PC9|X9oXmla'
        B'dRPRlWQ2<3)OufYFKepi{XCWYS$YN3tJ3GJXUGu4!jQl{F~!N(#CMvF@XtNItb8iAbbzA-%2MR7JTMlA8|y^+mgE7Xp3@lprQz#b'
        B'3$)YSK4GQOwuGhcIo_ZDI*QQ7;>+iWHhc(4#+l>MyPCl1Dj@ABI0txu%0>3pmX%4IF%vLzhVYP0V6Xk(kGb#%-i)!jTZqO`8vH0j'
        B'V%!K|j8%lX9(oU9PH0-`6eR)!yvv$wUy#LjuNcR#HB~+G*dKD_8dhk`1qfzlF^E16--0?y&-{xp@yJX2$<t1aawxZSDqqC9gXZ1u'
        B'42jIWr~KyHm@B9in(8=m{AwjY{k8T<BAvO&2&kZ5h(`<^qB-#C<<vdWPWpaS^fWD^J9xg{fe;z=dd;LPu5m{W1{zf?Do=Eo$TZ|x'
        B'+}P2I=WpF65oZ(kRgau7>bM;p4!bB^><MOtrGV&BP-cPz!SsG+`^lw4<J@*TqghA}=ab$^&_A`qm?N1s5N0m?i-feLv7NgffVJx3'
        B'@GW3i=dgrl*leb&;!&nz{iddgOCOA+gW>NOGwsYWj?|f7rG>n|Bsv<G4xFGvB9Z=8Fj0jzJY!Q}gFQYZP-g^Swe`_Tq-wk5l-TPq'
        B'a@s0*3=&aha~uawy5*tKTp3gtpEA>C<Dq;RJICcFJQCodRh3%aw<h3^0c*|Q5c8!X{M-Bmd$8jdX?0U?KdHGHO*?NelENP#%1l%#'
        B'Ar=r6*IKdtJ)m&eVwz1o*{wa?3`tWplj#%C_e<QOYrfuS$zRb%XTi~TrKyf0;x$k&;=V?{H)^H9qC{CpY<*O}PhTLB%Df)xdfZKT'
        B'+1b|byQ615zshFVSwOt%_pIkE4=a{u6m)4igSo0Tj-AGw=dt$C#`f4$A-Xwys&@G6+VBs;!W@#B#IYF>!V$??oVkKi0&6gpp0T<P'
        B'N7!BEk+l&}sJStMVC;eolojDtvkOe#+JbW(qc=1Imy%Fk!N_=_JRv45LB4usCHMW1ErxK3S=GtQ;9Ug!>6iKttc}OzH;N1ubKkFO'
        B'ScrV$Kdv)hQ7Ce3Q}OhCSNs*Qf9e{s)}tcyE{{^9VEUi4zllq!BXY}&LrrO?zd=>hfSF??qWF3JS-vXOl=)>QIsoi@WbdIKH0A!<'
        B'q+Or#dk{Ll&Y~`cM{d+KozO`t@tT7iZr2IC4v4-p*8t`b`26$$?<+r2hv-iR+)=UahY=Yg`npgY19&F@TC;qcO01jr0|{=Tk1%-I'
        B'JCLE?Y{(^|B-t3YxROQhYZSw911@9tcZ|l6QQ`!Rtz8Rp?`D=T(gF<NI|T)3w@`#qy0f-2R@j)}a@EJEo3|zPz&UAsc-brPDHsge'
        B'-8m?L6;?Z13y1<3Hl=;yCZng5&}ZJcVIJ{K?D1f!*x@C~Na8ch<EBn=<P__eWRFrb)uECz$|}SPZjonm3>8W^6`M@2uwgF8`<F7('
        B'i28`+R7p^q!lKhKH@O~YT2$+CWkGBX)K#su<sq2I9~y~$8G5uJw28{l(3t|xe_r+1oQ*m9#|i_Lo*#=zk}h|b0BwjY`Qul{6@4Kh'
        B'Cj+PBKc{ump9&}jkR_4*hSO@>l&FdF8AVxcNW@r~oc{}pZ+Q>E@x8P$tbBLv6KCyi;b&po)9BX%alTVIa0Jw)VTt1>4JpqHeVr6O'
        B'-H=j@xcc=<1QbF8Xg(3zh(Md_6_l7?F&U*Jn329`iTW~ybc(qpZUiz1VK`+o->06c4V2#AgV3odhuUh1{)t>jOS`n9flf>bEg4Bk'
        B'Yg7e+4vF~12>a2`^uyV{A|ysSlvE8{ypA3s!CM}ee{jnFi<toi+R9h>X4KjTHAXy@CF5m$z`pt3z?unaP0iyQkNkWuy9HQURbp@e'
        B'00000X{(o|3!|$d00GS?xNiUe8du*0vBYQl0ssI200dcD'
    ))