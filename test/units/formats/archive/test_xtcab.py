from ... import TestUnitBase

import base64
import pytest

# Multi-method CAB from libmspack (https://github.com/kyz/libmspack) containing
# one file each for MSZIP, LZX, and Quantum compression.
_MSZIP_LZX_QTM_CAB = base64.b85decode(
    'O;bZg00000djS9d00000JOBUy000000|5g70{{R300000h5!Hn0RRC2$p8QV0RRIMLjeE)0RSQrIRF3v00000003+vx>+CqZF72Qa4vLsbO5^m0000000031Y$Cc@AOLK7crJ8!bO1X50000000062Y$Cc@AOLZ6Z7y_pbO1Jal8HM2IRHaT^Gs8y%r8|)PRvs%N=-~rD9Oky)&Y{K3ckTno&gFesmb}d1x2aF#rZ`FnZ*j_`9;~8dFhH=0O<w@B60w`09$~7jQ|j`3jhEB03rYYRSrYIQu02Gi*rHn2wss9rkA`&sDFPTEC2ui05Adr0C*rVjg4Sm6Mnxy5C8xG0001n2#O&u<8#rz@0XpIn$ZC{*c7w8CRtZMCK&`_rsL#~-yzy|(DgY}+6s=Bxd68PE$mA$06PHI25Ae+NAN5vI*%-?yF9rw0gKpJOM3yjZ*5U-I>To|OX~tQL)K<i%ARt}FaQ7'
)

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

_QUANTUM_CAB = base64.b85decode(
    'O;bZg00000Avpj500000EC2ui000000|5a50RR91BUb<bNB{r;0RVCp0Du4h00000008SAKu#b4V{dJ3VQyqDV{dH$;pZds(KrBr)5{F{doGQA+DZykMdNum'
    'u4`L^M$lG{uH$HeE_<oIF6Py&zj4WJ_LjnDg|tee?->)g?={hY5-TOb17%sUQDXp$wFgFJXGvVGgfE2_r>)~mh2c@`tdHlmbfGOHjfpai(|{=}e9%NP%PBpg'
    'F6(+}1Ya>>nbE6FGn^9-ZpmD<S|BGFSLO`q;4)*M-#@*1+ZCn;NlTT_B)ix<thkUA&`-_$EUX@m_x(r%0HmZk0-yDlkN`ftq-hB)${;#c_*`Nk+JR|{WI0Ct'
    'IiYlfP%~g%_A#%m5SDee<4aGfl4~DQkX>P=+NrC<zE0>e?-|e*#~=`d!<%8v;c0JM7Sw1Gdyfl%FXcxGXfgI*JJ@N^VD6uC&7(68kxW@){!AXkc*cc&*ZlR<'
    'cM&$_X)&YW=a8GF27M_6zQhJ8cx6`>9jiGl^3#aX8uZZ07jr0>pjh`_CeX5O^rUeQmc+OyBhBr!^<A~baRHLRnX?%2Qs`GT2Cv3FH5V(V^w!P{;54U7a=Ugu'
    '=9d1k2&BtyoF025pm)~9Q~*OsFEnI})Wlrd2DmnHeN)icqd4cQf)GA_5l0cea@JiMlSv8ySjCt_QjnLZ+sT)w4bd8cMBwHf3Ha`+-Nmlwf$seAsa^}y1ewOk'
    'J0rWgTGbn>Y@{`c1irNKZv6}Zk$OjM_ksABw}G{?+%55_bQtUk^i3nqJA2zPq@nMk*3cYn2jq|gRWQH%p7|lJ4I63Jv6!V+zTBQW(;C@8A_FN;>_l{r{`-vV'
    'ySth-G9!@Pf#q-YvozlVZK8Y$;G+jh6M3>o7=~X6=C{(VoM&A23e6xGPG#`$8T<`5SkbxUbaVB=M+A`}G_Oel%van1n;)!!mm#0uw8RzkQ1plgQp+<Tuh?Y_'
    'WN#eWc!jO{B_4QC8bdE?2Sj{WN#Q-+JqzDor3}Hzy?Ctz?;Mnq_J$t8B}B5Dc%NL$56r2X>*3;MqlP?58x|na=j#$QZjS#aj06&Iecz?=8JZcf9zlsm&tf0$'
    'o%iNw4WnzP-9rv!aHix5^@)Rn2FwADc6z~7T@NZufC@TvO-C$-_CEe7WIcs3Ij`ne9qA<%qJx>YuT@_u2mRU!NM!;K{9$seuN%{O;PyFqR79H<Uio8~*xI!y'
    'SMWZqVm=^$sA=SY&5m*~pAH9}N1CIi5%KXrV^f0c%fgIqyn1IxtMW`l0>wu3@GN!Qj*Ovp8ggnG&Ia^Je)!Q)8z`?XZv897c{Ktiz}AF)=nxAmQmBfiHPL@x'
    'x@e|Bv7lshB(o%p`30(}&@C6J%ytpJ1Zg}I`x<T9kJa?n6eFXh0pqHe_X2R??gPKVIdUKcvph}1W(l+y1yP+bkEEgE-sKAfjmV<r$Zxw@NRSH4)s{2x8<TTw'
    'snbha&>b$ow%?3)`dKA#in{Vx9ZE8Dj<U(n0AR^XCscyAX47U5L*bITMi?=iE1L^}mwS!PNMNnp!**UZ$zH^L!R*v2_()>;!Fs+Zkvk-g!>|2?v12@IF>^01'
    'Z@i2-VuIP-I}ZTMWw9_X&eO~?mF3crLEFx-3NUC<JEY%rFal?k#<Q%!70?_w4gkhI4@%}Z4A?Ga!w7w;r-zCui1PT(3Qmy=ed+PCwo#lB4#cg+fU@b5Pccm%'
    'J!lbIbk_F0;7ibG7UaRgS<v)WAmsh89}nTCZ*C;ljzxtDQ_pqZ*}n`@s_Jgb*=}Zd1xj15j7-0|cY;y^u)?Hbt(#(0Nam>TgzvPQ^}0FT58PXRf@|6MT|0Iv'
    '=$Ecu2=&rgHSQ)S>5pkru4Rd}O}fVes7r^_^Jp52B@ZlMk$H8x!~4(3ZeCp=ZRE%$6(tIJDgAAgaAnkKBb(X1M4z1J`AvF=JP<-V^_H=;`Dc~S!4(-d#NA$p'
    '?FMJ)x87x=>&#bm6oowRDnxz}LjJIX!OUd)f!>fUm%ZlHS8Vx{#(P6T&jM@RbPWEo7x<h^cI2t;l-2N47ApT#XhYf~!!dYHi5L(L==LsVs}_J0DVArE<)68)'
    's2Nu$N1Q~97B>GgE4{E$^D@g<yC#9$fsw>BkI{HvjLZ_y>_}NxxKUq{*wM6A(d)g+>8#jqg4lR$$Z}k5un)lxJopSf^XL0EF*o)PBj!F02WQ0ED-^q&jT%Pv'
    '0VMH}e_xYPzfujCaA&8r2dGNq6gO4d>lRQ?bnPn4oDPyeY-K<i24`v)V{@uHewFmE&Se8o+Et_FtF~d11U$<YU<OH2!y2mn;O2>>Pg}}z+O{_vzerd~N!NHw'
    ';%2#;OHEAB5{-of3OLAPGZSv1r61@yygf2scT!C*f$a1Ci9H<~LM+R^pL#^yc{6psrA?NA`G^=+d&krF0Lzczw$V&pQTLkzNR^A?LM_}}Py8mhkPF<*=bPww'
    '(oc*tPeMuMC*j&duWWgirlKlm`?hkjddA=5iV>gQe&c<8C3k3_#*3~A-T;}yF&YubAi6BO;~g63rg)%C#->39dgQS3=ObxWvYt0E(!=p!ZRlLwi7!>b*;BRI'
    '8(t($R*KG|v1`U|Xmw6SEin*EJ2Q8-1GJ6xXVbyU51zz&g`Q_#Mg@q8TS7pbXsg*fJvaygWiIHlISBKmC{b@_1pwQFeWW`-Xf2PO+k}GKrOJp;h-n?Rc+=~b'
    '8WsnQrYfP`vaC{bb>?hMVa3mxgMJ(JJ3W&)9h!&7aO!`S`MDlqC6%X?=}kZx<yOb0gFCOXmsX2f0}O$kaL-ykW9d<IaIYiAx|UdVX3|ai#vH)DFdghPLIDF|'
    'EG1CdI(i!c-aD_xn6OMygg=0cLlrc_+wBOugSB2lZ@7t{fUsoIh0Z7D8=1|B<6C_AvON9NQA#o|U?6=E6CjB}JO)C&`&!%6?V5>aL>@k&5V7OaDpK4Uexd<!'
    'e%EtS3$gIL<?K_9#fk@t5|})|hD|Qc^LqqLbCD(XU=7YO+}7f^TxQb+%KKEC#>;l90^{WeDl&@wS9fwyPP=(gA@#<1TRgx{n|XmO;v<k%C;;rXsThB|-jI7('
    'tjEaPAXh(4*o<!Qy?X(c<=0#=b$xJ!3>6HB7WHSk4{frrcG&p@F-kP%5z(@0uJU-;Y%yNl>|Z?edL2`-vuilyKF+~x=p39t!`rM{3FveF9g<Wbg=u5362H<m'
    '35d_?N?qAwF%E>QTJKDsQ@L;IM*6sIiYzqtsVp!L#dr!{4Wp^);>e|vPNli040t@`O-&d=7J+$9swGSln@hMs&8!Ft3PWvzu=)DcMa6)v8I|Fl2$q#N0R{+5'
    'GM0BNAYq(C0LKSqG9-#53Of&<!yDp6HS3TH%_~bk$oeZKSC3Xtr&miG>=t~*JzEw)vu_nhw~K_`7p@EXe=k8o*ciXS{!ex}K9#D`j{HI$)P_oWUsUrEf87+P'
    '|2hnRzYBYqk004_3XvV}T=G+n6PsYG2fkD`NIe)wN_4QPi^-F7wY%03bXV4+WVZ#TN7t)qA>X+G(HNYLW2exT3fZ8)1~)G5RA&}@PFj?nD75-G7fVDKO2i8`'
    '?~CCuG|B44XFbQx>Bg?`i})ui?6hieorj)RlP&fp`^kP!<j-N5dfXV&zxJRx3@E}5j@40;U5lbYM2&voQJuhUvA_key+7pIcCOvJ3^WIF&_*tN_c&&?B6YH<'
    'q7xr_zFPx|3~0IS((0%@Y<Uw}R%Nxc6kQxOa<wl5r!vei$N)-0&L1Lq6*XJN|DC9OVbMrwZ`QpPajXQdM<1^3qajjQDW%JveX2L1yp)?gh9})I=k+VG3EN&5'
    '`r}G8f-z33_@Pg_;|x)u(BDaW{xy9?SQKftiLC~fv8~x=OJwINS^TzUq&2TIHI&?cP1;!y!pu6!;Ee4P&ssNakUu7THj9B9u%HS7h)xGY>|m`2u)?JW;msv{'
    'mi<T#EU`;yH(Yx`y2XxiZ3{6l%N+d|xKW=~$U%o8+*+S6peI9H5DuVH6x~afpa<+hG%4-@j9S?*^_#cF@{0qb0gkkvBP#sO{$cbci?_ZLQX_v+U=pTVD$`h>'
    '2~_uE=*?u^s1bLED%u?3THD0J`vVpLa2O0*a~SORH#mFSn^%VRKo|PdxQ!jv=X|7(^V+1a@N$N>r$F!3aNFAG3@#W!?>ZaGOPvGvK7SErtRsHYSEIcYDIC*6'
    'mCzN(c4W7=0Iq+amkff!oB5jn0da=bUP>&{)0a`u3!>9u)!t42Wdl{K>eK1d7%lQLc5~tr@V`di>WO%P?IyIcYFaE5^xXTKk`|D`4j2qpkGZ{ny5}sJ;<&$D'
    '(pY&)*2J*C2c#=7*kifB=jf)Vo67d1l7fnB{>JT#GYVc1NSlUk#Vg^p?@g2!O!^O78feW21K%1rKM25H0ZQT~_ansBnSB+H7P$rS*<Gvlz8Jis&Jj4nHHeYS'
    '<v)7*A(?_9kjZnDTsKUyvS7^f`exq$P7}m`FB(H}UT<9InOe%<&tt2e2r|E68FPel!{rgRXn?3yIH9x&rc3e3V(FrF80aSE9HUzC`Gq8i@?4s1n;UpBOV=fu'
    'tLg_gMH9wCjEZqgD{+95x2nn(h7O~}IS-TLInlQXRv>Q+yyB<fZhu^digvOy`M+CMweS(JT|$nGN<(ut)^w%OKPtfR%hyosZrHs9A=kGsmKO-e-rZy3G2?>;'
    '_y1GX5>7kBLkNK|593<_KC_uBs1oJlogN<-u|;+24mN*<-ZbsL-HeS7r*J2M61SHE4vVcd>`{Li96ohB`YQ9O^-wijJ@yd?c$iWV*6B+z68s(;Z{sB*2YP`q'
    'c`$6Gt$7WNCA*%?N@%5C&7EPoB$N3+pL>lfW6co<0Y)0UxCefgm{$p&LUhwks?|Pow!pQ%h>gXXP~!!Z2J2tBda5qm+v3P@yJ~LGI6==#R5w_43C(_>AAN%$'
    '!dQfTaa%|;`5vNp5e>kwe6<g-zk0ssyf}Wpl>7ofO@8nL%8hMO7bsMqgL2^i0*p+Vcjw%{uWFE`8d;yUpu}p<BwkbIlDh%*1B)1ZHEaU3^v%d-^p~Xo790Az'
    '?oXFD*OIdf3V`OH$v@p}H`H=}XOG<mrCe$Ozh}&yY08Y>@3g!YGgjJZ;3;D-WH|b#BdW%gdHF}u42lmOVgDtj2T0R9!LCuk|Ksj+?fpd1AC2jgDBc;e;jTtA'
    '`@H9)Segzt|0*%5a!0kkSgMj7)&jf}xPaz)D>;NDj~Yp#-p__#3=mDI-q8SI;$?iuHrf~WT~ewFYt)?le_`|a$FiHT=2YxgA0d?(DwrkgUxTDJyc73^nIt0x'
    '+cS!Z8<{Qe6dc%fi$74qgw?MzQ|243@uOg4N6@O+JOtA5P9hFMU1^x!T1G9>vDT-907+NZ&76I$mki9B_3}GKFgADM0+|g!hk2+&$qP_F?qI?p2V`=a!5-e<'
    'e*LKVx8|bxBifA{q~`Vq6YhD%^8fHc^gVU29HPad&_pl^<atF_$`vb|7Cq$^YCWPQ+cKkCan;hBuCeQkbp$IP^QsMVsj)cFd#Wi>=V`;~GTU|Mj=MWBUG5!S'
    'Xh!!8JH^VU-p#C_4fU5q41;5`n<B@Yl-%tuIGU=}x@k_xp|eKP;=q=~zfluy;+5~Fyzvsgfgv)Ct;so`fAMb5sQE2%LhL5hMsEiD8GD&^m1d-Z69Be5S<M%O'
    'x)(xUN&#&Z;Ml&h7wZR2^Km`ZuU3F;nSNyiu}+T<MOaN5*LoD@MqFEPu7%EL%0JxzzjN_2qJy0^-tXvn^^abT9KhIhbGXq#k~D~auX35=qp6S1XtZ6HH|S@c'
    ';E+5BdDyAAjq1NOsN;u?lb!$6WsQBhJQdUADXkt0tiQ8*{^7<u?yI4`Kho^m!Ghx9vOV2tbAU;fbVyl59Sy^GPfLnGC$L$CaFE83OvY+AyZX|4EaoRdck6=9'
    '?7UpFgaAw8lt*5ku8(Yk4<R5G%{jl4N{cR}3|REH#9><M|K?Jl`Ycg>b#4oW(#+b}F>RkAq(qjMQw?U#-wIM30vXt5wBxwk2R$k0*xH<DW*{Sy<-vSe+~kOT'
    '7HoC3NVO2Kkd;-8?xtD=S;j5<4O@BjVjgnP_iS^3o`Kb>N0-bX@wQLKG7?_{`07T|G2-EZP{G7LfqR;AitlKNa9?rDznVtpu7L1s_NK^QM*U0y?MN0foI=fR'
    'cOk+DU4Xs}p5SDlXvbJ#@#Yf=%HrF1@=@4aQ>K5uw)-9XVxl;v%zoB8+Ca0u3@t7Gf%xmdQ8?=`1C`nuO<tA!GXLF4Upk+(b^k#pAK9R{SIyt)+tzPly3F~M'
    'mG|J*>YT*Aef1h#p>}}rQ(ADAn;+w(BT5*~fXt)`ObH(;JH=NL&~O@fsiqe=K*dT5%{jhIx(clmwTu{nQ>koXC`K?KRA*EJBDGI0K@b7k#>ff|2iDk*QWe*0'
    'nBuH$V49IFSI7@RV8mYVd$h(}XqMfI@*e_QfmOVPlt)a01igQiFNo$)4@NFA9yRZj@u&Z`IB?FEN~1bxZ?Nv++)@#N*6Jn$QtZvj0w+kz30MAP1jaq2uARJ('
    'KJYIe&_`zoNM0mmHw4{13xnU!;s~ZO&PEgRQj9L{?jP(PkxDvG4DkBUkQKuO?a%fABiXyM5<<rZ5?5r-DHS0uMiufFu6l$SN5+4ZFI)D5Ya}j#kjpX)$lsHM'
    'DmHTnAfc-#>Iv}HAX51_C-JA8B#?E!9TxpPdOogO-i9QiOKG`0TLD>of<@V+1V#bef5`sxnqHsdxJ3bS4P@Gzs%MKd&}FgHhxV?}ETRScz6T}9YNs#kbw_>!'
    '7&H{0$h#t`Hu?Yqw`3TM*Nt)dv+Vv3Ih4y>DB9XAQ#(pglu;6=F!W#>)J~xnExGenT`6~K$k#k;lfn%iKwRPkVicB|o?mH9p&0v0KmDIy`S*a45n`3tFd%$_'
    'Og5=~hQ`}m7`$S^>3nn13uHdy8WVb#Dv*>JiIx)mDN%stuK#{`|8+#(n%AbL6{?(zXU?DZOXVFK9wS|*UG8@s;~Hr%x0*HN8B_PDf$jpeX|7>5MS>*OrjITK'
    'K!Uzp3an1XXUsQrdaL%y<VEop&0V>&ePsJ7KiD4(mXvcxW%A}gJ-=DycHK&V5h~Y$Y``*Fp*HQDw0hcY9ibFNQ#F!9Doi4lFosy=%2SkH-!}G7#c+UN!+KBW'
    'JoWO~k+1SANRoNaur%2M{Uwy*EDd&QqLl|`Ow<L0#i-w=AJcZ8c(i5mXQ+8*9I?dONWH-_E-v5G?4)WVp5>iKi;JTESMZ^2(}s3`l8?^bX9~)__e0TKVCN@)'
    '2`rV2*^bFeBQ8-k)$i@`8Y5G6dR!3Si^1yNrvECfG`aprpLAJWg|9Mlo^J-ojOQNXh28<_YtJI4fCZ4H_HvNAbSY{=px`ULXda)?0<MdNV(|!7PMqtY<i|eu'
    '-@u>KVgn;&67`n~0X`JAE1&$_c5QVi>aW?mFZ)_<cOzSoi>=@k=<<GvfjN_FQ65CxhC+$2qb(d@dL`Py6wz!%pO0M1<MhJ=I%GML<Ca(-|0|cgStkLN^P!Y%'
    '8Xd<GZu*YfRIbRe3o0HMH+(*mcVy?>wLZ|g4PjP>j#2nW*Cs13>V8Q}9cbW?(|>SQ<^I#Vee}|lZP}4q5Y&k0qaf+G+e?DCEHjm!k<<|>=C`Z`P8=m@>wmXO'
    '{i-i6pneJ{7$09<X&fy>?4;L>AgJG8YCQh8{BxuT;(Okf`)3@PNb}9~3yAisCKN~N*|$F?6RfnMnoTMqY!@)FGTm;Ui1DLyo&~(mrQ37KYsLa6Ws%1t8K-SQ'
    'h}s=j^AzvqtPR#6-^5241g}xo`#<>>T3LO11nFPLSX;6m@R}k$UN}+$53k(51E_OATrxg7NvguXbAn8nfxFm_<mpBCak`y;OM-pz(|ouMoYT<yOXD0E<D985'
    't&t!9YoKGUh2C?=OoHL<a|daoDod_3%})okVBJ>Y9rf`wbpoN=r}1@RMegol>5J*Abi#wKZ%s|>z9noFp8tf9VtYQ>29Vua^^N47;Bls!BKrnlVH<|K(xK+u'
    'R?O^br#~4F#)dh^QuoH9y9{?DFg!VCZ`W-(qx_-32@SE>oj3|O1_C|?@wA4bCYeOu=?>{%_5BF>4ZesWx-UFReglX>G$G{Ks{u96JaBboWa=Fk@YIbOg9Mp='
    'd}_YFyFPGZ`wTpV<P1`htEj~~5U3aJ#1}8TYTSzK7z;rS*f#qA%FG+F2{OK@95e|;pjNQ~BAF2A!zD%RE03?DDeTm<Pw?TUOyu_s&-I=hGtNh0b?tA<dnDG?'
    'GWM{~0&{x@b0Ul1UtPaT8}VYK&MZ!9E3>B-9(~^ej>2UmzV~l%8SqPRBp*AY^KNPt`HDPIw6?a!eypS1zd2&d5O^i4`vAZn*o@&O3RBDlUIR`NRDHD-A<2w-'
    '6O&U71KS)wU>G#!i$vAHf$%?4iah4Tz<Xx-xMkWnR_s;5N==E1jOT=qC{!<1P=oR_!w^C#aDkKks7i|-Q4fkBOH$!^+)?ptM*^jWm9$xV<57ql>e;y#&`1Yc'
    'vx)KZ=l9|#nG^XisZh+Ju_AH#o&wo0h1mf{o$7OwMrT<^$MQsQSaXx2GCtg09ezN%=L2oEoi8FHSVGPmN@MDEo#%nDIwcQ*V8YTup%RoA#Cm>uqTn<}yFRe-'
    'XNG#%T=Mf$@o<<foZJTnW5om3!i4lW!4>GUivY87#}UmsC41Ozu@xW<g<Z^5G^d=Syho|DW6{34p1|EBBc3TVO%=N2=~$k9qr$Kxfk?i2MRkl$^AZvWomQ<='
    '`ih!!4KD+Orxp-D_P}^EnWlCY{eEy1yfE^(nv=R8Nuei>Q5$T_9c`L}__r>H&YA7LQ#29D-RcmFwCHZ~q?EbIL*##2uA{Un^^;r`z_+B~L}rtUgGg8vqn3r<'
    'OSq1@pEu^tD&EeEa8F*(d4VjTiQ4-!m`IRL2MY*ExLH>_KRkz6&y=FOM^+Mr1MJnxPt^|E@MbukI8L$92z8CR^DDR4QC7aL`lVxhx=P4%W$=~(FP>EM9W85y'
    '9!37cwpGmR05h&9q-U!j`Ekf$(f1A+rOwz`)3<YGF?^s>0S8=SSCcf;HYX&NAma@1!W|-WxO2R(pR#fGq!CLi58M?!qkM>dHZn!QoqmMCur;{NQE<&(r6Gj#'
    '_bzTA-XV@ZyQg}XUq)`5_y;rr+8qmvhoL+KnsW|ZKlF0=hr6A?*(EWAx6jGT7~SmPiy^=#c|UOFKde;*prG-)M9QLBbOH0$wM{dSt*LTig!r9~sGcBR7gDdO'
    '`wED)T26E?cviytfv9h5wU@9FA?Y&OCOnV|r~GD8a11wNLpZXlaJ}OZh*$rdV8Zm0qCai6?w1GaiHi7fmlSslZm-*~Hlo%~-F_@3&)I^vQ?$eRDH~R`E}8t^'
    'jJErwpXI_%W=|A_!3t)!PB#CZxJ;B<a6_D>C&5%FoT{)G9G{~mkFUI2hZVe_>TNq?m9QROXWUrr`V`gb)k@LP|I|{$lbLq0gzvt3{<cc(>9EYs*naI)&|6Fq'
    'p#R1zxg$@zuL?Nf-epc$9W;;qcz-r-n=@dLU3aIujV?eSr709?)g&TWr1D-#6l67q0FPRVj9ZM)mWzM`-lelz;2Gr$N<K602AiD#ZiRDqfg87sBgFKBK4N__'
    '9hsFYj)@dCA*NxEYLyWKsbDWSF5&<70^neL&zpyxH8cmgw2tidZNuG|^cttJgsQ*4n86g3?z$QNO4~9f5;T(dn!^L9qJvT?;CZx(A&^1cN2=<__hRyaN}3qO'
    '6i0T@0|D7LcG{2~J}*Bph>V!NdpZ+T`q<y2aM-Ku-Gu_IN4)V^=TAWgsg5>1IYkd?jgiHW#!^;H{95d!!1Oyx)b$5_w#mK-<OL<AJm)An<LR(z)*+O{jaZiZ'
    '3+TFxwEE6J%DU{`b|%qbjLf~0RASH(-{uaB?A#BN5E12TqGh}0Dp*0>y#6&JrUs^ygF(OgkAnRDpGP97WVut_H%79z7?JYHGa+}`mI6Ah&(kk?5E5Q~*OZ04'
    'f=^!!uM_9Nk|R?OdF(`2V5aXltxUXRFh$zMd0e^HBtd;D$ix*SnCM0okL6c(jl4`%n;8pDc8!^;&2hHjjnTm-xijM$h8XxY`dA~5iSwF(Txy2C&<0yQYv$FX'
    'j18`$#NCsl<mpkFm0CnrePlfntt(1{<V<z{Ce1XhfXzsFyW=gtyOh<*xd2~~>U>R9M81TYi#96mequ#C?vY&s;Wsxy63{HbrX2e!zm#P=q4@;$?&tnAoZN(F'
    'wQ-eP>bBeHf~Om6q1013U*^8j23)L3{9y9M$O4CByvFhiQm4H>wg;$0$R4@o8&;aP=Z)_*Oga>YGzxyCWIr%W(Py{Q*k+{CGNEX^v!GV?0VJKO4p4jWf!fN%'
    's$Et3>Sqsqg;Z;lAZ!;qDOCKB<bAKehmQCF>3@;VsYI-aeO)_g$CqxN3g+CX9pCFLVju=jff)hA4+p!_B?2btcY^!^jHYc2%QnY0C(pYkRK$)C;UxZN$h0>4'
    '9Q(2ohRFG)!T$ziZpjx?KaK5Qbt3N=yADiA6W!DLz=BB`$JhNO#Jg!ofsq4uB2qZ004N<SefEW4RRj2CVK6a$CD+JAr-$g@qcOySzgNh4SXrJ}m$w4C(Q^M2'
    'PL(l!&<e?R;#0<rF(!ZZGqK=ZPz%YO*~pqFcM58SD7M=YahckGDaAozfDvK)1brn*Jcnf#-jF){-C@X=Z+vZ~4-YVTR<g}M0(Jt!87M^&0z%lKZcROTF(Rr@'
    'UA13w2#sbOL~D%I#9w^;e#H|yXQ3P6@EhmqQ|3(lLvKnz=K%Jam29^^Oo@Nd;q4+KAdv?s0n%~+W#(qlXG8ePItHUf<{<=%A#lYZ4S#1fc5kPL^f1L9AY;Bp'
    'zf$T7hDXXlNck-D2<27_AP5NeFH|3u?ck<n^<O|1V_h-v3NMhtzJ^}xs-5in2z*z(EbGvpBygG07e%-8Y86PQ{+%r)An#gL2rza;Td|2`6cUhi?0~2#zET;J'
    '<#+j)fD12Rfm3AsYH7oNp(efvDL2R@tL>$1UVQET??Dg3?YAFCo?NK+^H+zKe`p-nJ6HSvinTmB;Y_<bkmX1gd%c|<YVIP0SGZH+Lbvtm$B1=)*uS>Iye6%+'
    'Ey9*Z_n9upOf2YojL&4{bqFf^Mxu`8y$nbd&^&9Ko7fj;o{d%<Gl4-6y;G~aT52>q5<1IwL=pz{5te^xVL}~7(}TL27$zu&#z@v*fgMrqk=vxBA5j+b^H#SW'
    '&7Oog{y%es0GXw?l+8(#e_+euveh=aof26@L3<;&gN8?n*c_!Oa{8eF4fpgEgF{~3U|Ros69Q_8tgm9d>be$A?KZrLqn!x9Ez&~+{3AV7W!T-A7Brl(E9M-+'
    'xQOY`B5_){wadbDUJl*w{E^uTA>&OQnkdb#jwMInz0fz92U8A|c>yrI&^&n5_cv%EJt?ae5FMK=<_AjVc___N+7|&Gk$&9$zzg9sOeqGq6-v<(ye1=yIgswK'
    'kR5u{!!I!WLm>2E@|pTJJ2j?A|30fGmsZiqT%=M8sOO~M{{MOu5V>WP$V2v+J+`VALAFpHHODFV3WGnrL;}Ap`7OImG7h$Ac&mP#0prYwmBGHpA+TKWe*bh#'
    '=K!ZlUOwF}091AV*h!{sxMy|F4N$0Vzh(F?HnEMhAn3$8!%n=MXzR*Oi7=0`#LC+5-NE+EOz`?&klL=6M3PZC|NR!$>9#UpXzB{EiR{~1qA6~qtMPASAP?>F'
    'TG1gSSrZ1&g`!vqyyb-B=w%ED<F{pyBi_#YJH{j#+S=YNnxJ?4b-_bsewc;7QnbjvlTRCW=-I77&ct=eYH=tm1Tg30o_SN##a||xtBIT0Q&YPxpkx^!QX~`i'
    '_)E1mt|On%&ga^~(=pySAg69ZNx#utecP70WJ&FV#k?ldn6sYJfQ74&T|Ql|xdOW;=z{mkFsSh%ax0@RNg!^)eZ1;~ESp8Mk=GsH+SX4^2-pXCZ;@2d@8Kxp'
    'iG~=eD667G1M^40bF)w$=eU9n-&LywSmk<nL4E4M!g#r4^nw87kMXl-Gp|tXEN8K~jYL%e?VO-g;9-^^(9qU`h4``<HOaDt6!2LvPhhlQ-#my-+%d-kV0|>3'
    'ku5d9bg(<~bN*vj<a#u&myA+=aGLv!ReX`nqpoAG&E=NoVeR163t~k0)90h&vxKls1jK8EerjsmY@DWR-&j^=hk~d)yAV4pZ=(FV&QUYoZ=W1sU7|Z+1l(Qa'
    '!nqqXpdKL_we%H5iuGh2aEv)Ze<XgSGrsn%e%R#L^wI|Y707kTdk`H1yNLpAi?G2S&ksreKVCtkX9HVToneW`^KQ#eqLiC=C5>5&DCVL!?Ov-gx9lL*1v7s4'
    'Sr2q(RI6idT4q^7vP2!>1E%?#v@R|4<f4+{tIf5(M2sEUg3(rL&vAU^j1$hMLk)<owpgrhJGJ0(g`~@+kLN(D<!x#lJ8R83L#B^UQ1$K0v(kF*O<XKH!-qV?'
    'g<Hojt=h3#3SHH01JKG?NF0_FjCU5Z`C1B{kV!gk9p?>*!w!`ziX8WqH}Q2s{3Hv$77BqFi!pxeFsklt_TJnY{)0Y%C-kqNEY@=Zo<Z>L?e-dPE0^?mT}4D}'
    '#}!$097fp1Vmv2^p4{i2y^A77Cvt9|jwgDG)+LL>V>M{bw;5Dsn5l3x0Mry?I5UQ~1>n<rLIqrAtuZ4&74kniA%FvVQnAhqL7*oU*NBT>H&5Q=nt3iKe<^JU'
    'Kg8ck<Q951i0+rTGy?|6ES`fS0)zNDDibefnaa6fMKC7g1TDUN468JSynoO*?F7%Uc>ff*8Auv4-R7%XB@x-bl&q{C(4TfT&hO;^DKjAeg<D{73sfaf$*6Ll'
    'OBAg`Yg>Z{M#?q1z_;cqGc_kB#N+6kREfN6q(-7_69it4x_YIZAuJwp-AUQ=V^%!+s*lU12ELVWhM0)`uI3;GvL@w3Ja6f6`^9p9Ag-r<ph+avi1RJSZOBIx'
    'loZ~7#_^f!q#nkvi0k;dA%#ngY}ew+F^(te^Ga+I8~t7jVg#lLES~a7%`&G(_g0uOvFk81(@@30w=S>t_4=U%#jzb2ssyLMj^)Nbo~X?NXl9q6j1Staho@jY'
    '@zs==K_N*bS_U8GSqvO>e;CbNF%b2p^?J3VVcUZP@d$<JJzq8e%;V2&ugwypLKY|pLT?DX_gUYlk0nY>-isFv^I*0RZ;U~P-THK53vU&+#nGvi@<NUe6KyIy'
    'F<Ym)zG%QhJPvdKJYAo?GmKWj@G9TiHl)PI%&Q{S8};Z_%6y#$(62LUm62|agiJd1>-yJdZ?b%HU`JqR2ftERM{2mRYPa!){Lbhxjk&jfZ;r<M=wBOcusk&3'
    '-#8>H(by`j)$9xk_3Gs+c8A~!w|C6d+|ktN>l#K7w|5GG1!o2M1totPNY-moIi&^M(p|(68!2dEskre^aB<kijktz`?giV^yn3j_nEX|7l)ZsiwsXyeb+wkJ'
    'O6Z(8$@^lh+p&7pccI%FLXf^ep{EVL3_*a|o10~)yj5ql=qH0fH;TLzRHG}`$V+}z1d4=qDC6WxZU-*u%9ICz&^`!w1Xn@40Eh>cL14;wcnIgA3GS)z>YQ0S'
    'tPnZcRD-@u*Qy&+KaKU_j+)sC<Mo+tD>_YjE6}{kMga4YJISYIuF@QRiR=5`)5B8fREKZ_wmdiJz<0x#=|~6#_e-S9dvw&U2)u|v!XE6-Ug5Jfk_yR5ht1ep'
    'B0N?pQM>_cOac_A{03sdd%)LDfnxTBEDz+reVWo40@yu<XZv2m<LEyz2*ady5)(WXhZC;3s_{kk!UW(w#(^FN1IvIbu>h%ShiQo9llt(yqV^?>1CA%UI8$Ke'
    'I+vSGrx}e-V<UwfZ_@VlF(S3=(3?D=Hb>qy-rs`GF1zh%zH#A_zHaeL)ptyEf&VlR)f4GoWb^+#*wws3Nnc{NhtzGp*?hL^xnTxN)o}lj$6}AW-H(^ysHt~l'
    '%G3{W=NE}Sp`7<U9=A`V-X8<i_^pJ>%lV%)9ogtm_KYC1@jOL+rsC(ju`xfrRZ|mFrq?N|4%IDRy>&x1m!TqD!yxXA?2;t%SxcGP7n{yiA%xbvS5{+<-=DaY'
    '>X)B~M{M%%gz744ga35_?J;#HqBp9j{8+ly!&Y}MU|PITlPrEoyaW+M@Q;uN(+#-^F;@VW3{rCn>Xx*@WZ~G9Ay-+<A~S)PHAmR{?t1!1$6fp}_5PqDK>AaE'
    'B}{`RI2A)km*i^o_5dNg?Wq~!!I&jE(Ec>UnwFjtCjPtbi6jgBeMnr>&Tt!-%X3Zx_UBX#i#>BhG$W|g2(3&1mh^6u`dgYER%an>$DtRlKf=hA#X|bY%!lBb'
    'K*6S}iwJ?ER_vNl8n_RJk{v_R(DF307o@2(HDE|t4mw%(t=Gh2LCw!5XZ3G+NpuFv?cLGgZ3QB20Wz=j1W%VLZLj;wYJE3(Ly&tz+0C&u6Uz&{-(v5gbYAWP'
    'EB{h38?4INH(d2CmOH+->{Ul3NsY!Tw{AFe9Kd+VnG3k5=sYgdA7UbH;tnC&e&7pwfVll6+=It)Gd$rP#YDAL1c1_W5Rcih1(2!;)3R&ppNOlA^P4dZ9Do20'
    'L3>V+w8MWHU)|Q9rhzi&D73z5K5DFK_uHK{aO!IcGLcQ4P1>=i`aNq+0Jd(=UyPTY>E}Mh99Gyk!c5mN#tw2N_rl64Y+zfFwO_Zi%%pL{(@b~*jO6Rsn%&XL'
    'c-R|cgdWWYxN|Yc7gJ~%NLdfw0tp5<3KDIWzG#J3oksO3*=3eJ8S!TTQ@{F8-?H>NPk|F*E?q(OU+|m4yuCW)CK6AX?iGB0=ogi>8^M+gTUBVyi2orEubGz?'
    'bLTD0+t8!)lBiND+z8iHZWO4G5c24}U5Ms8hJ_dt$L<3lh6IVI7MX;cT{82556L7c!Df^+e_groCY+N+*p5{13HuBJ*ed%RB>P|pJ4T-|p)M<0FWdiJIct7a'
    'PGQCHW7x3WzgxvipW(F-R>vfR>y5~X*mX*X2c|wDNf?~EcWto)mBaA5dWfKxn|6W}vTj-008d%rlY+38rIUsXL*Q|YxkwrO_<L_l8gOyixQXN)<B_{b0o&h('
    '8*UtR-lb=yd>q&93-6;l@M!aZoBLC5``AyrqZSAQrTJTOv6M(o|2UYux*yhNV6x~-KV$d>7Od-rpo)dDkj=RjzK}BkZ3)*vNVN}fEJ$$d!YGbiyy0JBFHtyB'
    'G4}U(AcsjkpQEqyI?L^$@vp+9i#u}h0sHL=@wBU!Guw1wKYZ*BSLJo!5OP?o=;F^)Yl_@12|fGIX6(LACmT2?{lkS=4Y?@|tRe4bJDVq`mo~BkmviG2oS{fo'
    'pJk*D(-v|0csdgDVMcL*;+3qb6cSEP9mS~ucLB>-rBZL%3pZTmKi6h7xrf(L5@Ux%yb9(BqR!-R;4wv!{iO0HUu41nmur^=`8Fu-YOtWP#v9-Gq{$y+5&c^@'
    'F%;0SdEvu%(9mewI!guAtoaEbr)%=S(spkek@nkI<Kk>nM+j#Kfhh!W%#ll?QB<X7$89$Y){dHSaGbn}rApZX1(XH@q&()h54P<(+QuhOxwEo3KekzgeRQw>'
    '%P8RcZhYU!B=<+g0X>fR#P$u}2e=dWn=w8J-Nat&P$2DH5EsN-Nn*^&7{N_0<d=}d?ir#|rN0{~Edx93hPYyF&v^XDiqbepI-e(2!G>v(Yok$gCBp5+NB^h8'
    'yB2rXC7!LyRxX(N;cd4Am3EyAzrA5s>Kdoi_qqRGP|81^B3zP)bUv2*{8@OEf%{GVK}N~zB%I0DSvSrV2YhgT|EVBlk7Cdp`~9hjT4CcK1Xr4jQhXi6mliVr'
    '0?hgHWo0F*tLd-_hsg0N9Lj^zlwTFYE@W*Kwl+jvDSRWP4<r~j5W)ZdrZgCO!HUVqGi6e7tV)pl?lzFbI6?|{HnGS*$5{p_Ir?pMIa*5V*gx)%f?Y>bUZ6_|'
    '0t$r)tdFM+g@SeYKCFI0wYI%ZMk?VGc6>0Q+5?CC4QbaJdnIP=8ZEDQYZS8Q{b=to5AJYSRLU;4kMdRSn4=~4?Dn%RLrc9_e?&ek2m$(U=Ke$VP^uL<`~|-2'
    '#}nY1cg<}1qqQ}MG%W>gi3pZwczo(vbcU|ZkeEl-8+uLrV%2|`PoR%o3s$48MsVlVh9D<$(-mdpfaD(u9pUB4NZ2B|9c0SZkgHW&^DuxqmR!lKPZWMnm`bZy'
    'j{h=E%FVGYoddzR!PXI+Dc2U(wgj|WQvcaSqFZC87W)}Y<WWI&aZbyrdO07cxDWfaKo4gnEB@Lg0Gj}@pbdKkS9XK-63|cDa_b>HnkH5JoedSt2aAFhzAj*&'
    'Oe*)O4E!TaMjM<?P%W>cib$1Of=CrP2F?nK6(mSV#c9c%T8KCa8L*J|F30(q;zFM8f{&oh%`fk36q%hMpojX~&UP6GSO^d;Ajrqo@khl4kUNbGa`{6?FhOj9'
    '_$V?kpCX2zq78P@yp<<DS0V<8x-+g;`}H&~Yn4VZ4Q<5}GRg+AZf%fT#&Zn$es1#}{d(NqFm*2|e5p3vv)w*+Y}kHIzCf@V7AcU)HQ;6}H=$PuoSo-QZRcBJ'
    '*+bs5-7s5jT6z^ttLgf~pcTs>AO1Wn7!sInjcq$TJ+w_%nR*=`62T`3=rxf$-U|ocL%6{v_MGQ1(_KqSKwOSxEk_z&D|^+rgXw0_7_PP(ps}vg31?rY7@X<@'
    '%bq^5QBxL7Tn_(ciHR{304G4aY9I3Vn*Kexk2n3nOeZWMVx8+pF0${%i-$nmD522&Y$=5xB1{+uq|UBVp!_H76@H#q7|JbX65HeHqx6^!<tH+rLLbA(!4?C8'
    'M<mqxI#E-t$$i?>Vic#{I@uTW1Uy}PbHf9w*)!`?A}a5D7r(o1Qi12MPX_^&+X{MNl2pw{<(Z7hV)968+|@hM?K7_S!KT|)WEFk?u_1#`cU%@y%PK|i=Xz8o'
    ')qoo^X5m9|-w#WnLQ>hhWuCY}dJK~S*73Cs@Y^tFnmeG=IR}hx6kQcEp)UCm0&<}vfrh;nk7Tley~{cunT6}aY8>kuYWEZhP=t4#*^1_t(Eb_21rlhtnRsew'
    '>u_zl*#&m#cWsWRG>645>Ib)hMxhlWWTkXFj9qyT#KeOCd3|4PnCj3g$B?J=wVMDwhr^qP&f%sLlS;LO13&v8++Y+Zx~+asye{vgUh{r$Fv2<8pgsD2&m(*A'
    '0v@d=3#7u_H|yZx26b|ASKAVR>>6*_(Z5hYX2MZN>PCcTl-(V<_QhlSXM3-F){Mh`gZIfRqshc#xvOukDvl!ChXE542q;$EN~NsuyDCSb8MvYhd=`^MOtiux'
    '3az0bk&knXF7M&vhI;FPFIkq)K^*2JHnY~Pkc|2o$sCJ!D^x_zUei2I&sm~*mC-f(!D!%&K@BKt7-exLS~5GfM_|oc!l0Z20v><bPQADk%T&ZUsK1Z5LM!{2'
    'DhOweI8*2)OjK4<kXkZU7KyDn?6KAch98WLQ9~r8h>LWaR7XWYXwXVTsTy?nX(b)xGR}EXpAcGXY|kxXF7o4Zm;-y!_N0C7^(sG~#_m>;F2WOEC^Z|sUqDCn'
    'Uou`XGwY9&8y<bR=uuuKAFpGH>**PiR}Xpt>XPb8jePX)?#<&)bsb7qcOKz;axY}w4vp+b8G5T_QR|-UXMR881}my2E_2zfudmKafcX=$y_6svO(xGCkW64s'
    'n!}EkuFQ`WqwTX;N}=PPfe?i2e9<NW5Kwnx5~9KhnV2qV%;B%AeiYgxVvS*qziOjhY^V(D7YBwN1#=ZY9^ue7Ef~6z1jS^<HXh;*-aH1Kh0STJ5!HGD9#|@c'
    '?mcojHQXWmYGp|@rU!jrNK1(U=m@U;$mu`NcZomd+F!h8WxjY|PhjrpKYLT34(oSV0adQSpuU?48>T&=$0yRt6fMP-Z|64xihAPSH>gVv+!jw!l)xT}`7M2o'
    'd{fTvw^yxI4bYHWWAz%VuBk~UI(nv#hO+vOTkU#?p9|qCL0wJO(-Y5x$^_7t^kEK(jD>Q3nR?=@!fK_4ReiVwzBl(O?w~o83;xE4Ye@<(tD}Ul6l|gl42O`Z'
    'uWiVr49XZw{h)Sl9Q27wzEnyY8q;3$UAfm@;sTEflFD9eng-)clLp7wz{HRV=oj_KR8FveFC6$_iZ*!h*o$*@@sgK~6Eq5tGHz63eD}QNL2e>mT&Xjz2FIL?'
    'z}EuPucrAl0+sYZ*GGrlAD?p_d?%GhU0;iZsA5RB;xj8#MuRn+If|G>7HA%kD*hUwCu<)Vnq&8UBqZ0Z5hyK0><PZKAL#Iz<6)i&+bxv}ZU)Ov7-`OUe0g6L'
    'W5Z#a0WNV%`nMyQ$V5%D&-t>1<_*UR4WIfnhcbjzGifQrf45%0K8-E@s5JeFpbnFtqFbY5H_5ou0ek0YnBxI_(m#f|b--7v^m@{gR2x45WZ_Sh#`3M9*144l'
    '9*Kg?3BJmfXKrV5{3)H@LFPy1J%~D>H&@QhY1zXbi(cTrFK8-e9&)`ywgM}cFK_#(jZ%lvJdnu-5$tT-LG9a>VtreP3=p_Y2cl_gKWxpec>zy?u@DtP$%VO3'
    'lGt3L1Y0T5S10iYta$=k?dNO63U9Csz2Ia43PHdK;L_n%LB=h)si&3f>&~G=$d0+l)4qMeQ^2ej1zJrN5O8q=1m2j*E2Kk$wfxMf6ozx$dyiut9cN@~?x_5-'
    '?8Qfin7Uq8%1Gc&b5+cH3QCuoC_bxW$Eoil#>h<woK(bMmnN@44DB_;xOhfu^dE${DG+|p$AtUW(+q|P8Qm|3|8J%+KSvFqu%#er#j0ZFWV7M77n&{meVJ2#'
    '4->|)AH<ATb5-z`v6kp6VU9(GGx#M0f;%3KWJ&-a00'
)


@pytest.mark.cythonized
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

    def test_quantum_decompression(self):
        result = {bytes(c.meta['path']): bytes(c) for c in _MSZIP_LZX_QTM_CAB | self.load()}
        self.assertEqual(
            result[b'mszip.txt'],
            b'If you can read this, the MSZIP decompressor is working!\n',
        )
        self.assertEqual(
            result[b'qtm.txt'],
            b'If you can read this, the Quantum decompressor is working!\n',
        )

    def test_quantum_win95_cab(self):
        # Trimmed from Windows 95 PRECOPY1.CAB; Quantum level 7, memory 21.
        result = list(_QUANTUM_CAB | self.load())
        self.assertEqual(len(result), 1)
        chunk = result[0]
        self.assertEqual(str(chunk.meta['path']), 'command.com')
        self.assertEqual(len(chunk), 32768)
        import hashlib
        self.assertEqual(
            hashlib.sha256(bytes(chunk)).hexdigest(),
            'd17dc7b0898c16b9e7ead2c8e450269f972e3044cb6756974b0504a105ce4e4e',
        )
