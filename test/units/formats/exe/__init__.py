import base64
import lzma

MACHO_TEST = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;30Da`CR~iJ6l07aCq9#O^f?>cF@J*dh$^*PX2zHgR^1R6+w?}@(&}ux=whol3`-DaFpiRplvpJb-+HcW}w8(Nzd}n'
    'cMtnIZ;=3G&K-0{!KTwUb`}K6XuIP0(xBR^5I1ppiZgzzsU6h|&d?LXmE-t+<Prf6GwBMNRfl88m`(Lev5Y16sZi1ttMAj%mp%a*i;l>O+h$NzQ29sw!1qR`'
    'Qwk)P6ml>87`RW9MqQfCOHt0;_&|M7%^w(2-^yfyRGD+`ngHpkb5fO^$-&IAKtybEDhr6Y#k<;!!&EB48=XOoS0>qkR*JeHiMNe?oAX;J#+t&c=9qm~V=|aw'
    'mrw$;zrkkEG!ek%N{M}!(qIjFVfS>Tc_X3!k7~P1;K$>ID*9tbZJe??Yz6zq-%VFF2QRUD?2^va-HS(3Nn%Oa+KU0i_1eX3P^l1CkD^8flW7MQ-@MUOa4i=B'
    'sx%un?h*CVW{AJNwX3D&zL0@u@`iGZ<wBkj8#fgS>fr*WRHW$QO9JW}5l^u-i6g{k4M3x%My;3K^pw)XRcq;W8nhvyz}}3xPIvaEr;gJLwUGxZstaV7Smq5X'
    '-vgb8+}%B|4?xp2u?OWRdyRb*YqH}!1e{658Ar|0rZ0gUlhu!xepKXfd~ybEY_S?cbHfLOq0Fh@FI=hp9T%~{zIYoVEKr1hX$KhfL9S;YD{HP?g54l3Oa-T8'
    'R~Pbs=uEM%gAAUw*Ze&`7S+v5mt3*}2&n?LE^Q)iPwT+)9<lU%z`3BSDeacuMTPGaQi3Wn;(1YIW09*sAw}XE%J&(VGj)-<AUN~z0Ml!zuVzQ|6TZftg0cnY'
    'q8HS)IA~xMwnx|tLK%>U>5=u1RTCn7=xLSg+7dUc8U=|l-cxX$GwkvK+v6+0@t?5_*4l3eT~mAfFb|b*KM1HVXsbTT)DmU-+>ix*Xn`3|Nu1?5n9OC7Y<WJN'
    '*7jNSMWo27eWj_Vd{r!bo^P0Bsr3Fr>Nk^I0lHsg#cSIsGyuuDYTzW&56geJZ)9Mfh;sU_`%`jo4AP%!k*~i{*BwC}A)U3C%?6rTrAFk=;$HH~ntdz<Zmy&H'
    'blbdJ2z13lTr6<K3#6y&sMooBR(?gs5$UUbusqfs=amYTh|bds={0UwVd>^&LN_m_5y#M$!TrZmOQ;hI4{zI8XxSAp5`d7{Jq&fT_A=nq)u@{Kt8mVW9pzID'
    'W-B3lQwK1@%PjdXvmel2Z<BruS=$`!Nb7r`RYD!7#VNM`?IbA}>~uR)eNLSu5Z+R4-Z(sy{MvODPPgqvBJ@;M7u^P53UeIXc%?)~so1)*EFx5xrD6q^q7bo='
    'OZ+jy2g+ssBE-+>p;i?R(<+M%aE1B-JmO=gqi<e5{PjdKdgMTh&}~Exv-fIxF8LU^DaN5J*&6(L)dLstpXc}((@i?-b=DVW;9t(-xXkvuA3%WDB<~;lpY*cL'
    'SDN(oqX|d?AKk$R?U1wB=mW~Y$4{ti47+WSa>wPC?#K%o8{CnYmB5fin6azHRnC4g|0^VP?I(D%CsV0jkt1>^?#FSHE&o`WTihwyfYS!=z$o?h4CUb5mB(*M'
    'W)>MITszU;14oOV?t(ZtmN6zBYvfD-Kq_MYMINR(l(*%H7mMFo12W*NRV65FBZq8^AuwhD00000Yl$wDh!H`700ET>^g;jt(vwuavBYQl0ssI200dcD'
))

MACHO_TEXT_text = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~^8X!(9MA0sKm*=K5m>YwC7XXAu7W6Y9GGeJnT-MII|A6x^tiLl{*x_^dU#RXhnIfNznt&K^n;LjtGWKwzutmwyZ>'
    'wqk2xqQO?!v{_fWApP~Kac=>gM9A<`xO0QihaLtPz1tCJ*g5nD353ZIB1I7%c?5zB1L&8v<KH!(K0x4KAnvjZd#bCrGfaczHJJi2{Uc@g4`>^au$e%Apq4Nb'
    'eyg4Rl0CEq63xWrwgh@C`XKM6M4{~D)Xp6Jv*vj@5@81PdLd`V`PY8D;pj(5wT7#hH}!A}%t|)%kc1*{L!kZUv%9C%3XYZQth?H?(`_XcwQhc72qKeSCpfnH'
    '4>0d4;u;#53rOgb_MOA&hFyJ^Xa|<?poYV{5tn|V2Zn#vJ1?ulB@mB6N=YwJ$9NuK$C`QtB%w?mvF9X1C%=<w{Z~XEmRmT@&s6z*xt0A`igJn#6tUD(C8J#e'
    'r6CmL651M;_WUgIaBwuVWkb-2YBH&{VkBnRKE__8#ro>NDBfD<Gq-XjWR3%0L!6kU*CL=%UZ5B+7RvPXRgK@_-+y~oSCB?n=a+Hc=Eb`5sD8cRj^_+IZvP2T'
    'GGj+R)!!~1SEc_mJg&F7{Wa4<ro6we!ofdxlld-G2-eLD?{U2jVnM@j(_^1}Dg-#~iN_aRW7(H6M+u#x-SxBAt=t1pH&`2n@3FK1dBlm$2Bs|(LE`R&Wg$<b'
    'bm*#2qMLcjebfS?Qpw*B0%SAWR6bF>7a?jg>{{`Zz|dX$Da7rQnjvowPOc!wn!y$ZDslnje{~sW;X2>P?KwJRO>vhe^|sU>5%=PdDVPZMGlEk94U*P-wDEY+'
    'n{wsspkH!13fB;sCS|Up38S|@wv69>us9aVhko<4Q69Q37B^i)(LXD5$UhhzR?)ztK8c&yR1%(Lm&dljFbn_y6+5Z?_XD~a00G|xkO=?)d@oE|vBYQl0ssI2'
    '00dcD'
))
MACHO_LINKEDIT = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~n?0(p>-mU_OBq2YoP9_ZXq$Ptz`BpN}<p0T6`aAV=ASql()=K-`reKtlID?@B2Qk8<KIfIsGR_d#c0`I3eK|9%|+'
    'koN0^%uPW}l)9U3_D$y)ex9XX*ZV!9xeeUA_leK6_y4(tD{E|6xXinDb;PJ1E&qJS*`i|BQc8blplw-O8U()2CCG?3q@!Mio8fXjgsqQ*UMyn9f{#L1dA&*!'
    'J!4b|<)fbU4PFC`SU(EyO{nzE<`bBd?H75PfmS6~yp7!>c$ws%2SMo(s%Zeg00000I9-f-HSK4s00Hg+^a20?0n+=}vBYQl0ssI200dcD'
))

MACHO_TEXT__picsymbol_stub = B''
MACHO_TEXT__literal8 = bytes.fromhex('4078000000000000')
MACHO_DATA__nl_symbol_ptr = bytes.fromhex('00001090')
MACHO_DATA__dyld = bytes.fromhex('0000000000000000')
MACHO_DATA__common = bytes.fromhex('FEEDFACE')
MACHO_TEXT__cstring = bytes.fromhex(
    '666C6F61743332746F7331360000000000000000766C6300617564696F2066696C74657220666F7220666C6F617433322D3E73313620636F6E766572'
    '73696F6E00000000617564696F2066696C74657200000000'
)
MACHO_DATA__data = bytes.fromhex(
    '000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000CF0'
    '00000C60'
)
