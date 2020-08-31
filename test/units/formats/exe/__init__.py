#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
