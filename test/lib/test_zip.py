from .. import TestBase

import codecs
import base64

from refinery.lib.zip import Zip, InvalidPassword
from test.units.compression import KADATH1, KADATH2


class TestZIP(TestBase):

    def test_deflate64(self):
        data = base64.b85decode(
            'P)h>@6#xJL2>@?Gms<ePea<EV008F$000XB003)YWMOn@F)nm?bWKxBveYmP<S078ymtXs6e|{NC@!ERn%IT>!ICG0)6=%0id`bB'
            'TitE>duSr$F^SPP&PUN2=rcE$Mn@A)a!`4a2cg96C90(x?a}WCp`H9c{KZD-v&_B+;P~R3t`HS9kE-Laa<@U5CuN9dAdG6f3-MN7'
            'Lebyp6ME00hvYd!QP&$Mv?>1vIxe*JY~l~Pq6Z9DwFk&jRl&zzwB*c(*b>TZYT8;nPO;(XB{8D{Tbs&*Eb2?z+r~D_&(gDV%(Jz&'
            'Xo)@UWVJD*WDpfT$bNQiVsk>3_Ut3ClN+S3xe#{@`$)-+(ohleNt^g3uy=^Yom~hGiv}KxSxIlo!+&pimE)_l8$|3~YzR12I1R2='
            'F8jE09=V!}RLZ4!xFCc~O9f)rm^O&>C~bObasXPMi@xYEz(1z^O#ukVrSvu?Xmkg;a$d=ujm>UEyp7Ix`r`BMnVy0O|Lx0J4(LLW'
            '^AjPBvUP-%Sz))QD!yhj#IXf5#FU^L=lh*DR#1Pv;RnV;hYp4yAA7*VPw9uP(j2n&xtcw{qD3DU`}YPvt|9hst<6griy-U)@|Onr'
            'Rb_Y1zE+c+Fu$8OK0sBuG2{+gFk+Wfr(Vemg_x$<TH={G@AqW0ZdI~P&#bAKzr8p|3qzK`<Na7D$QwP14iu2}+M2)b?Z5`0Mp=Nv'
            'u&VQ&oC9?Q9$N7q_yC6Z5-Uk2JmDid;#iRP4}SnqO928u02KfL00{tZLYG?r(0$G(0ssK#0{{RE03-ka0000003ZMW000000Bd1n'
            'VRUFQE_8Tw3IHGg000000RR{P&{N`h+;iLk00000000000000000000P)h{{000000RRC2T>t<8PXYh{000'
        )
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 1)
        test = zipf.read('kadath1.txt').unpack()
        self.assertEqual(KADATH1.encode('latin1'), test)

    def test_ae_crypto_bzip2(self):
        data = base64.b85decode(
            'P)h>@GXMbqV*q5Gg<Ajs002w?001xm000623jlO60htE?0suip0{{TfTx`?=Av?BcA;urlLQDcZ7!zolb}kvPoU*L;nb|ex`py1u'
            'dtdD{b9fXv>*bdI?6cjkV}Iv|(1)>-KVeQ_cbjl0Lq%#1E3ey7O9KQm0097F0K=YzTL1t60B!;R0Otb$00ICD0CX||nFjy@06|3q'
            '3;<ZBOmN)OnAJ70Rx87zsr4WwyLJ*N@*u5onN$ljPl<C}p^2E<{wv3%b<~~E+AqPU=J_~mYtP}X^NC16b+<k*y-_@gv(AgW=iMdQ'
            'Vsr1j8HeLoFO~sBVQ5DKW^67!2e;YgjN*uAVnztta+FDPwh88e`)&JzDD*q&#(dI|Aej02CsRRDwPst?m17KfLX=&(h8az~>z-?!'
            '(L9zKq+fF{u|MGVK_6~xR*l<cQZ&SL$HwdJ{4;e^?1y2N<8)iUMSd8=5DUWpk!Cx41@MA{TyogAc|l^DKR*h>b*M>i>GpH48Ye~)'
            '$GC{nnI8BlQ(7^dx_)h37arUj#XgLs%S~Npuv`5~-M1XFKlHcEYgt+Smxir?u$)tiEKqc);a%Cdh^AUy@#&ct5-eLO%_VelH#1UW'
            '@?r3-tls@j%}l8eMitirZ|(t4&k37(jc;^<1PD*j8?%%5A=-ldiM03zTIa29Q#v~P00Ysr2`j@#XIH;UC|G%_{N8Gi=1Yuc+Z7|*'
            '6>XOD;g`0D6=twwj!;R*?zZ+Mu1(>s7*+_by%aqk;+1Dvt2<&t#!m6f;}*Z`<yy7iYY<(5-}2mqEkZh(a8SOSz+&#b$@Xyi?^-2+'
            '#bUa0=xA&k<H7{FUH_^TW1a#7tJK`Idq9HOSgdZLn+JU2Fh6+Yowa&LVlvY}aT*M<k+@YkG)v#e8OJh?eM+OMB-}$L>f$uJF)37#'
            'maR|t5e!a(X)}a~<t{u)*;^sd3C@1!chPGYf4hzHd3)pEl(|umlp-^iu2CIj7}6P)sj;BiDR-qa5=DaQP)h*<KL9fT0RUqFWSxau'
            '00000OaK4?FaQ7m0st=n00000001BW000000049`3IHGg000000RR{PJ$;e?7G~T5000000000000000000000htE?0suip0{{R}'
            'O928u05bpq0Am2do`qWg0001P0ssK#0{{R5051Rl0000003ZMW0CxZY0CX}603ZMW0000102lyG&BTWoX50Y)000000000000000'
            '00001nFjy@06|3q3;<9|1qJ{B000620sy`M000mJ00000'
        )
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 2)
        test = set()
        for record in zipf.records.values():
            if record.is_dir():
                continue
            self.assertFalse(record.is_password_ok(None))
            test.add(codecs.decode(record.unpack('FOUNDATION'), 'latin1'))
        self.assertIn('The binary refinery refines the finest binaries.', test)
        self.assertIn(KADATH1, test)

    def test_pkzip_crypto_01(self):
        data = base64.b85decode(
            'P)h>@6aWAK007ipg<Ajs0000000000000F50047!VlppKO9KQH009610MuTETNz4LqE!F@07(D<01E&B0CRO>GB0#9E_8Twrp-_='
            '9sz*{%;^IJ#wze|*quPMpVH>FaCQqgntM9trP&bBZ0|4=&qGz|Tc2Z2?B1=O-J6r1!0w&-*RZCr)-c|m+?2JAcHFQ6*7G+KOqMhD'
            'k5Eek1QY-O0002WUWHo#0000000000000050001Ubz(6uP)h>@6aWDL000PdgIj`$(f1Jm000F5000I60049{E_8Twi`ja&&2cTk'
            '_#7mP4u~cWUQkN|1QY-P00009bc0(*KDPT200005000060001VF)nm?bc@3!NO)-s42)8{nwV!`H6Bn)0Rle&6aWAK007ipg<Ajs'
            '0000000000000F5Bme*a000005C8xG00000b9G`eFA4x4000000096P0Gh1hjn!q`0RR9100000000000000008mQ-0zUv000961'
            '0MuTETNz4LqE!F@07(D<01E&l000000000W0000Z0001Ubz(9vbTck=cytN?AOHXW000317yz2A<Bip2+yMXp000000000000000'
            '002-+0Rle&6aWAK007Efg<Ajs0000000000000F5Bme*a000005C8xGp#T5?b9G`dFA4x4000000096P08fbQfz@T)0RR9100000'
            '000000000008mQ-0zUv00096100?x0TY`zv_YnX900jU500sag000000000W0002Q0001VGA?v@bP50<000000096P0ByKpJXvJi'
            '0RR9100000000000000008mQ-0zUv000961010%1TSq>&`w;*D00jU500sag000000000W0002_0001VF)nm?bP50<000000096P'
            '0Ms1tJy~Sj0RR9100000000000000008mQ>1^@s600jUA0J{MI04@Ol0000')
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 5)
        self.assertEqual(sum(1 for r in zipf.records.values() if r.is_dir()), 2)
        test = set()
        for record in zipf.records.values():
            if record.is_dir():
                continue
            self.assertFalse(record.is_password_ok(None))
            test.add(bytes(record.unpack('FOUNDATION')))
        self.assertLess({B'Hello', B'World'}, test)

    def test_pkzip_crypto_lzma(self):
        data = base64.b85decode(
            'P)h>@KL7&&4ghswg<JY7vOqcl002G%000I6003(;E_8TwQ(25mT(;_wW}x*0@L96I`SY6jDrL;Ip;r4Abws0t0~76kGC^%ifIW)>'
            '{q@t!T79T$M7mVt&Wco7k}TMsX#*h`DJ2=kA=AVekZ)hlET7IjnamC7q2~1`WHMpoTf1)N_BbAOJJ}2sY&qgj)1A{FKCiHFAQL~M'
            'XvtMG()>#DD%%c|8<;u?fQjZJo6`p4V}46y!SPml%hkZ(5qEf_y3>|re<t58_LdE`4*B$$Q~g2_Gth%nvK6#fB*1GU6vuQrOH3OG'
            'j*Bef@vKaB)n0gCH$-PJf)7;P`k(MhUr5^<tB{>?RlPRtQs0v`yz`u9LQ8CqbR2hwU5FNruN}46lW$*H%raQccd#hOpdwbq`L;}d'
            'C^9u_yt(E!Q7&*mJ}jVC=Y%Ti*fmt^Oi3^%v)m!}DaB36ty{anaoNsP?GOGYJ4Z{H)2jD6yNaP*YE5qCOKp6qJYWF7V$RX$iyrQi'
            '8z0-nRN}jS(CM>5P(#d65<(kVx59+4;QY<nf(;vPXrM`uS|f@8$TY;+Odeg7)bS{nby)eZpYEJN9A15+@-b=`z+3eM?32t_93GPB'
            'dHoFTu@9a6NH(fY+5omu;GjYx&y`#Cgnad*uK+3ztteV=J;v3)EgFA|8LPT#!?acisp`RG1&qerCJ!0kZ^5Xr%Ffm66{aZ5O<n>S'
            'bb*$)y})}q<~K=;Ca<4WNJc?OB#S4mLTL8!eGeSzn;=DhR#QA5#3JLhA+k_Q0|Y++0{{*HaAAd80MLETivj=u=K}x$1^@s6YcVc#'
            'cyx*cRQ*_nsZ(;ejR2w=>%Ujbt&UDwXQ2VFRLUrQnY$1#UvE{@GgG`^mME6b#Z9<U(G4u5xuEM<3K$?BjIM_SYheT@WN;r+x)y~z'
            'Ae!%CVGLvQFH9osBS+;jkzSIdh(h3}zb3KQ$)eWvF@})~?O@rSslArgPh|Ld)Iem|*}l-0Qkk<?Ae|hv;nUKkx`V+W(w1c84`v&('
            'fH5W}v9ao+6kg5~%}4m<DUn7(ChM&}sB%W99R^MC7>?T#iXz>OXoM{%B>WJ;^S3Q)?5X3Q^UETV=(D)=X%?d~=9qdd6;1=>(gSu8'
            'B<4e|)@FS{wu@)-$3OoCwZOM~Pqs*aG)ox%U~RFg(XqKkAcuxP;Czn?VrZ_89zK72%d_Q}U8o!T^4yite-jBO{BGI3EuA8C$c(wd'
            'fCPrs?U2F7(mNKxR=Q0*NVK-&(KZKwjx#8avu!a|R2J%0ACII~l!H%V8#s`uYykdb=s>C|ZkHw<v>XP&Gkmuze6L`%abiD9pU8+C'
            '!G}VxZFWZK7mHHXh7`VM0rXd*ET2f|i+m`!tvg5a2v%@+z(By`Ee%C%ASuyTYP)QBrSp$pYen?*B?A_&>7zt&bSKq=&<d0TStag*'
            'mS_2;4b9G@=_NEA&4y>_2Lcc(?v||Y%&qwG?yOEh0?>~!cI{4?m8r*LIX_FVW1~x&c=yOXMxde~xch@Naz+T$@65%HEQrkQM4DPU'
            '69{7SQ=Hwd%urwsGtW36-%}V*(4PgIp}h3aqD6j;_X@}c(FVubqPb&My@3T-{c(*%NOjErltnw>1P|pV>|(w^!6x97O)l_;6!P8u'
            'zS+pfy1QRP_E!g!w@^y~0zUvh00RIH0Ci!7Tly=qKso{d06qf%00sag000000000W000000001MGA?v@bP50<000000096P0G1Eb'
            '?$>490RR9100000000000000008mQ-0zUvh00RIH0B~W2TL92~&Wi#70Otb$00sag000000000W000190ssJOF)nm?bP50<00000'
            '0096P0PNX4>DOi40RR9100000000000000008mQ>1^@s600IC40I&c601X8I0000'
        )
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 2)
        self.assertEqual(sum(1 for r in zipf.records.values() if r.is_dir()), 0)
        test = set()
        for record in zipf.records.values():
            if record.is_dir():
                continue
            self.assertFalse(record.is_password_ok(None))
            self.assertTrue(record.is_password_ok('FOUNDATION'))
            test.add(codecs.decode(record.unpack('FOUNDATION'), 'latin1'))
        self.assertSetEqual(test, {KADATH1, KADATH2})

    def test_pkzip_crypto_ppmd(self):
        data = base64.b85decode(
            'P)h>@KL7y$VgPkvg<JY7vOvfI002G%000I6003(;E_8TwWK&$F?}CW|DDWi*8QkNvxI^3;k8%d1J;?#Lp>HxUNR|@&TY+80+h$x!'
            'pEyxq%#iq0pE8`Yx@-XnXk#N3&1=9+Foc$_q5xOKm|2|xRH9i7s&~r)hby2q^EAoNhqGYdL}sYkQFu$*mz5mg%U`TdQj{W3ZSiUn'
            'CPs2h0Ph&}{Qt+jlZ%EqJX&xc=3iCE=Livpcu;5DzxPAodHW3JR;~+pL7?xLGH!`T-6T1R{2(+jGxW3Y?fN4@tb<TMc3AA-<curr'
            '9V56VbxoXx+Kv_&8)8|4afU|mw&n1sj{;PQ_U%$ka*dtZ4Mx*vrMQ;$65HRZR|3Hl<y83iT}WZ_9MbL&_zf?vZWvKNO~(#b7g8=v'
            '1dqMe_Rr^dy?@XDeCcj@$aBhe_5u}>KB&mXY@-}>-q<5^hW@g-vLvd>Y*%!ThIe_Whti<0Te$gOIo9lRC~Q<4AcOQ-Rg0@~(uI>Y'
            'xrd0!=ee+DxhcA+)GAlFy6-hrCqt$fF3QJfdRTpDPr>2x(^I~vtNW+P6SyCApkf&7n_Jt1^SX646fK}VS}FbLAwa5d9N>BnT~7>R'
            'E4mGWNwEq$PjwGtP)h>@KL7y$VgPVqg<Am7ea;sG008F$000I6003(-E_8Tw!X>(rz`Qw1J=sB*3h?7K3*pjhBrS)9bI=JZ*`0`6'
            '2=mpGAZs7EyohNA(^hoes!WH<OrpMfdH2QHlytijV-UBGID^?{A>qz&C~VtcZ1~emap8^xJ%psjp3yn6$3(Vvk;24%7*HFg$b?H@'
            '5UT)OkOi#mnRJ?W998=t%`4B_0bNx3VG%mV`6t-{Tc*<VkClK*(vbO6C-$2AG&eucDg3%Bz1*|%@-3&CJPY2GMwXayKs^L(^=~uC'
            '0D&D#)>oAql9yVngiQgup0&DU*5A>`;F0>$bH>G=52%KFKm1G03x3$Hextv7yf1c+&JdW9r(S1kESbz7$l!R2olpw?+)i_Qf(wAQ'
            'MmXk`xr8W9=1EG0-cb+GPOUGJFr@wD2bK;g;djIil!SgX`BQ(2oRHXZXKoB_vUft*5T$z1AbSva+RIt!!a~u&NarBnOt*uv_tth0'
            '4s^Fe<J}933kz-b;-ta;N2$gaU^QVE9jrXp9Oss_Rkv#qIUGf&fLv<&s<Y|JqTTOa6yHo!>{%4GM_!^R@<ZbOcXSM!f2G!PG4s3$'
            '3anvB`D|r@v-hNB*wDi15a;mz>3~ctKa3rfMwSxQq(6c>%{S8RW~*5;7n>4Cs@--RdM#)6;MkH2ohy<PXCJ~h>R4t@v72m!;yuQV'
            'lU6jlD~=PG2deCK^%68C)P?NZqGsAqO928u06zc$0Ac`jVTD`zE3!by0RR9#0{{R903-ka0000003ZMW000000BbTXba-?M03ZMW'
            '0000102lz457h40W!wP(0000000000000000000`O928u06zc$0Ac`eVTD@&(0$Gq0ssK#0{{R903-ka0000003ZMW0PFz(0BbQW'
            'ba-?M03ZMW0000102l!5**)pkW!wP(0000000000000000000`O9ci10000200IE80000d1ONa400'
        )
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 2)
        self.assertEqual(sum(1 for r in zipf.records.values() if r.is_dir()), 0)
        test = set()
        for record in zipf.records.values():
            if record.is_dir():
                continue
            self.assertFalse(record.is_password_ok(None))
            test.add(codecs.decode(record.unpack('FOUNDATION'), 'latin1'))
        self.assertSetEqual(test, {KADATH1, KADATH2})

    def test_pkzip_crypto_deflate(self):
        data = base64.b85decode(
            'P)h>@6aWDL2mp0qg<JY7vOwMe002G%000I6003(;E_8TwAeb*-QHsM*m8_8zV3Mp~C(_$sLl+A=%gg7Ug`NE`@`V)wX}9t37N{;>'
            '?Yrru2Z}eqx*KZd`r$>%tuOUe!Dm`z%=57LK~6}$?(A;Ql_4XkHj(mk_{p}?vjYtDTAsYKAL#a*PHfTcmihX3RS*Unlh_Lf`YK{h'
            '2l5mYw2-!s%F>o0&Lo}T-If2+ywq@I{7Rh|t~3sJu;!8PFNjt8<(q3Q-<fB&c!gFaG!hCTTTTD0sO*gukuP*TA?h)>ZD6V?B5o3D'
            ';u)Nyv){U6ffUx5X^A7)y5{b9=U+andqNKV#UbviRetd8lr7$Z-7X_uRmjT-Kh|>KMdD-d=kX2Ze>Z~dVQ|KfwxJ@Ym({m9^P}o3'
            'bRc-*jBc9hBY{C2JdbE7rz4(YTMgGrJ^B8Lz*BEXOn_hvuoQbzxotOqy#Nzl{~tWo8^H`A;!)slCG#yM0R=!4n^@uemAjF4{5Q=b'
            'lFHgi<sjQ4%1fbA+HGup5*yZj-T1S(mkut-FL$zCqcsabk*~4pqEFuCRB(D#bIMQKyt<-JUaPp6@|uW>R_9Df)$8Yz-aR9cxNGjL'
            'F_Sh?e=~@lINVP6scShHZqIGNC-A>&&UV-v{HK0Gjy_OJ0|XQR0RRX9aAAd80MLETG6Dbq=K}x$1^@s6YcVc#cyuUF4suddIbHAy'
            'z-Wn|p}7>nc~sn`8Q1ICKK)V=36s4zdBPyiv<}qt$LO~<!t9;QSvo$TiWnex;%`9T2B@+LN?84_B`RVRYd4X)Fac|OBOD;=%#UkW'
            'UhifCbNi<riM2ihF;m;jQHZ7v-SkcFxjwunBzZEVl=+KI<WT%_7Ym&%hBKY`(w6kqwF_U2OkYh2s>BG(O;H%fQhX3O1mz8&HXvB!'
            'r_&Ct6RqV@E~txr0&B|>@_{^3nVtvI$>$CcbH@^Hi{|JfMZ&<q9?tY1p7fC!hCbwnAUB*?ArXHmN5pcTpDITW7G=eZPp64vxQiSb'
            '=sR!4g9tvabc|4s@!LBHW9rkj|GC>Pe}C>6!B`FqU<yB&c5u;d4sy$K+$e&AyaRtptPDq5Dot6}S&A~NfAhpBA1h{ziTVkySRSyZ'
            'dWeGoy_y$qlk$~jzN@!v6#w9lKC|r4=@NeXub%N*WzI^<-=MkkCx_YRPxGc|N}-EZ;XgM3#Ia>{^ATQielqeuMe@^)wD)36KqCM*'
            '<w97@=xWZ`#q>UaJ>@=eNxY}&cSL0NjiVR!mBNL_-1U2GC{jmT6Y@J^#fUch@tCF`C@prD3Mi+*me4115T?Pq!lU7BF4ID9><(&%'
            '(vIj@kBzVvW8HuA=tEbMGdRYOn=P^+lnm-OY`?*!)_%{f?heiExQ}swAwEo?$~pO=B5U!ulQa2_NK7n3pt7`lY{<E+P)h*<KL8W}'
            '0RRX9bzy~D`YW<P-T?prJ_7&%1^^@g00000001BW00000003(;E_8Tw3IHGg000000RR{PmJihK*Ja!R00000000000000000000'
            'P)h*<KL8W}0RRX9aAAd80MLETG6Dbq=K}x$1^^@g00000001BW00064003(-E_8Tw3IHGg000000RR{P?Abl(*Ja!R0000000000'
            '0000000000P)h{{000000ssO4umAu6SOfq7000'
        )
        zipf = Zip(data)
        self.assertEqual(len(zipf.records), 2)
        self.assertEqual(sum(1 for r in zipf.records.values() if r.is_dir()), 0)
        test = set()
        for record in zipf.records.values():
            if record.is_dir():
                continue
            self.assertFalse(record.is_password_ok(None))
            test.add(codecs.decode(record.unpack('FOUNDATION'), 'latin1'))
        self.assertSetEqual(test, {KADATH1, KADATH2})

    def test_pkware(self):
        data = self.PKZIP
        zipf = Zip(data)
        for record in zipf.records.values():
            self.assertFalse(record.is_password_ok(None))
            self.assertFalse(record.is_password_ok('pw'))
            with self.assertRaises(InvalidPassword):
                record.unpack('pw')

    PKZIP = base64.b85decode(
        'P)h>@G5|vW2msHnb2;>}{jOFG008zY000;O004Ata4#+{P)k&0cyumMOH)QzE@f_CRZ|cEkLZdL3P+*F4WYga3Tm$Y7y$qP0{{bN'
        'r~m-~hydldIN+E&Pu$>|0|FO+mq9L-Z(ht&pEH;aIf>eQnNUUw%w#tpZ*sn6V~79H)4GP-;k9v%A=dD#9g&5=W_8r9WbWUWew=*j'
        '!et@h8wpm#j=yIjp>i>h)rc7#qY_HlX=Wk(&oj%GcUuHl_hvwZI@w9XF=<#sj}?MOr5sbi0Sp5ZDx3fS004jh;H3oqf#iO{nMj-C'
        'P2{Py2~lM80Y}DImV$$8m#TcyM}7xQ%YWGlmxj4`VT@%^xBM}KaB}wfM8WOPgg0_VyhVH&3DMa+_V)SUVfhUuqCMDrpEVH^R7vDW'
        '_~Rme_8<a$u#NfOJm@wv{n7aya7d3dg>R9R%?ig=05&VK^Yg-N7aY@@E0LYaK|p<uuP{a$M)lE~yHE5r(sz-n)uOYBN<SSHiz_<%'
        'y-w`$6(I0Zv3R(7vj!Qh8Bl|=kHE@aI#cO=tZt<hB2He$@?XQ`RyT$m8&z+64<HP9$Y4`oUanwMEr!xa>q7-=d00s4Nm`L7*2?Me'
        'xMR_tw2iKTEMR4k=CXIQN_%MMPM#}dBgz*AJ!tO(2Qh|&HB|*1K360_wB*zwM?fpch=g_BKOZj$V|Q^9<oAgr^m?F?zmW;0(RiAV'
        '8;%%V{p|LZJ}1wF8RauL%~;R8I;>uPqxdhc=s(o=-GppD%RznWYLz_;xJy0RyZ7XJ)xK!cM<z*sDhKkAIfW2qS;FA95wVX(jn@MU'
        'd$C*K^IMQ$1gas@^0Lo^%5s6PgE}lY9HZKdg3@wy_X}c<%K$0JocTY5$P?X+^1XJ9O#taJ`%ALq1vl8$%wZ?voo^X`?io^GV9e6p'
        'WZwwVKkg7)RqVn~pPC|-!4_=Eqqe!G$lQSm**q7g^6m=hLg$KS@9=CE!#g>HEPZog4^)-;AjtU_v&G){Gj{7&9+nR=vt$U2ML-%w'
        'p!Z2f%aD9{T!uMkP7p2V8Xi<yj@Mg1=K>TH7hU>)+Ax_7HPkr(C^)j>xiMMGIKk%bd|R9XNeXe9=N2xIGW&CmNcN=-oB<RNQYSE6'
        'KY6uLh>tzG_G!$?MgH{@SG15Lo2%J314>mHHtXO=XT^FRXBWXHIQ=A{(|e}T+AaEh3q}{T#v!+cu6#O&+9g{tmhV!p`e<`#R%ElB'
        'Hr#WPzRYsD#X2^O=u?Js)oHK<yNu2DTBGQ7fH+TV*o#>U;+&YI)I?42DV{0o5d1D^ubl&&4W?gpxKrk9{Dg7(reX>Sp8n-OAax`J'
        '!~Hv<>pzdPj2L%d+q~cQP>HekI@s5Zz;paz+509i?I8(gF#4-G1I#HLpN8n81S^bNIk3JH<2$OwRoCa)x@HPDm<N+{?cVDW-Q?-J'
        'LWuagT0D_k6ciFj*_92Ag>3EEXd3yrUH&JRU4!M9hkvG|Xr(qu3hKfUUG32u7qqxZmJ@ScLrHX;?2z<kwj@Oqqj)@UUbDB`65?}4'
        'aTwSZ;@_LgkOms6Vinn1{xX)eAD5O(pshaNfPKRsR($02>;a_o*qjO(D74LI$zR}xOQKC3D8h;lkK$o2iRVM-fKVkMdT)^L%v$dw'
        '^nXf)Xi?iBPn`QIx|SxoP3TI3Y)R6@belEo+r5}5idZ{B*+A1aFFp>*a0c+!^&V9W!d1V;LR?iXkm3WK6xRiNgPAP?(KC?{mtF>K'
        'I<{{}EJmZ&E<UXPP|ihpUGL#x?dczV^@6miB5_9Iw%B^~n1<&mHElXg^|mH3W=7_w&LZlovgtZ}A4r7HkwjR*T3Ce4c&pyG1xs@y'
        't^in|<&oxW9tewSmd7DkufJ-Qq^OWoKCaNsZ4`}ua(oUUe)ZKPncmQY3ut6idEfFU>|g2-BB%y+f-fjT=B|u)MYgW}{C+`V{}Q6b'
        '5q8*cq7j~DO9R0MJk@%g`CXMN;?NbBlE6MJCJNm`B0d6W4Ld7nU}PzK129X)8#dI<V7%XMTn-szwY-v<8jHfMA`$ZQxBrxrSw>_c'
        '>e3NfPhZuZiq6;8zZPq+f>^v|(yTIunPTr*#Xw^4v{7Rwfzs1OL7T9bc=?)6(SgN9#8N2n!^uiWAnAnrj9C(Rxc(oiElnYOW8%g?'
        'PEYAj_{&m0+;vU9!YtdG(xBz)J=2MbL|{_!g(h<TWQbGfnBRtn4WO;a>pFOMxRD@8^$C@qtMV<<N^uOtwi@Ugqsvu`5TVY*W}=^|'
        'ciA81mr(jqzCRi|@gA<I?w>;p?n8;k<V;t8YfDJ^;IT&3=Sb&cinXeiEPTU{qIdaME;DA=$j=F-NQkw*2Aw9q&E7K|A1#4088fRz'
        '34yS<b<xDxtFs8R7gUyDR(47}P774!d3itn1F4v4Y-2-{8hFR8T|P8|*VcO`j039I3rKrtRG>A{zxj*G=su}1{60IeHPHHUQ6&=b'
        'I2NhAD|%+Ta3tW1th^?sHhsjOu_6SD+>+IahXo5aZPk`_`REe&-_Ez7j@5{lRyJ1Ej+alL%+p`9^Ld_|8TWmRAx$?+9Zw1v0M(u;'
        'MX3khnM-^{>~B%hVyk8LDPWb}3r59Rch!&hN#h6=y}J5|tfU^R9od0d*65JH?qWAa!-v5=);7Grh1&XGj6Wc<WG+|PLcWX4H?=(H'
        'IQ2|u2!tbt$pL$YL<kA54+CJP)@8S*0_wK&m}a{ITECow)r!=2YL*|KTtRwDd~m=1Ej{Pv%C!s1zd0VevA0vShMx>BVjCN2Lzc<~'
        'Np^6_WL;g373WrYjEh1bm!Te-1oOW5bcneVJ_LXyiA{yc%)3!e&g(?+uZJi4>T&kL2w2w3z7~!#FpbGcf;2c&XRlN#PYM|$Ho{)9'
        '9a=;GginFw(&6b8`cXR!^QVI|;R|t`iR!c5cJ0&hwOf7WmW9fV+VBE~nj*;2n(^yXLi;fT1CDJs<9Y@+LcZ>NJ&#SNFYb+*!=-PQ'
        'Q-KTzy_Qn~21WYUhHCU@i8I0@qWT=sAd{5?OjmK$yO4I2aKx^1Df=U;2F`$IQS_@IH53wogp5I@mS;%+Lk4wEfO4%2N^qRDwENja'
        '*^v_qQwa9{7N9hOG7^~VZuSKrS_zNqcFG|pW+wnTt=oLZ<!T;u@@FDYtA%(gzL$_3g3?8@QJ^$qm*Zd9GjhidbAV78w*8|d7!qv!'
        'Q^|qsnhW@!Kh&RC+{!mu*JV*-!El;5XZA~S_r=NlL^|EENFf=G95NA76MLM5FcCTSNUpHvq2GkBcSG7|{r1$Y|0FFtu2|YMl~m|b'
        'YM?U=U`cb0IeC3JWIlvDQ_DpW^j#go=+kA)xmBP$tni^}Y{m8rLrwNUA?0as)-Yek<I{Si#H4?ua~8b)lnhx$d%d|e&+EAJXV{~l'
        'RvlMz04`#AEK-s-SnJEtZay9qpelKd*5yhxrYL@Q5df5+tWN4J9{d^R6Rb+e=i%>u$-I&EH1<i;xTr@2xS#7^`U^mCYv(n2OFT?n'
        'h$#6#&fCQ}A7Zd;Z$o7QAD8)YEX3g2x4#wDb{sx9Nu`fA5PGR#p3Fym00dq=mC^DH3)`QFwsZD<cDvdvVByc|JK%P#>P>}jsP$rC'
        'W}<loJ-RMMih}!sq9}<b#kIM^7F=rvnF}$c3TY3EXNG)}-a335jf$A-Ln-nU=+O;)`>UJT){jRSj~u3ti_SN$<`n)zBlMDOUr05y'
        'z1rhtV_cetdNg2KIVlx<I<v{IeX118vvg4#Vvp&R2z~iQjwrjU^kFHywAgu&ByQi5QcFSFY<)W{6zbtI7mam^$mZGXSWWWuF7PWq'
        'B{{v@pAgpNco?fayu3>itm}LPO9eM~lX|W!4UZt!?ai-s!_zEeU1@$#{)&!m6I!$n73A{Tv&ONOR<@KLeJfVLghk#_71J`TZ#rWg'
        'j?(z3m2GUYg+&x1He=MlZFKU%uJU#uo*r;mv!hS8(nx<`!Dv4M!UsJfzTgO=YeBEdRuohwhaG>VZ&#+!AscnQ(qUkf5ExCXXMdPo'
        'dPLmAB<V!Ieyfv<k;j`n*8A#zRKG(hH1Uxgz{6FXiQEuva11M}PE#Bs6$^`><EM?z&xlc^Mc4aa{dUH4?p7O}g^TM%DdXcM3C}&y'
        'B~{B5w$xWlIGOsU`ih!ux3aP2V%Exk_2-s32g=b>I23ix+oo85{9%iVu)NR)+(LT&;#*!X8DWrfibsT7Q|aIRbMhi_LdBYT2b@6B'
        '7G+bSi6bPESeI#-qYQ^KEblTL`@w`xYN1|)n0!mKYhMb_;hj~1XBr<&un(ai3<rPKn|*5_rB6d#GB|wXgD6lfh*tSo@GH6*<eA8~'
        '>EN>>Qj6ppEC4=d^|wz=BXV(rxlqx?@m~bds1oRq6f%yYC$}Hv5Hc<EjOR!kyPt4;xRuUINM7!rfjBDC%eZXj6VXflnwwF`BuglD'
        'zZ~d3uz4&J!O6Bu;-;NK2+WOKP+^(^(2f}`P)h>@G5|vW2msHnb2+plNJ7pG00871000;O004Ata4#+{P)k&0cyumMOH)QzE^1+4'
        'N>C60^V_tpW?-WnuBf6pF7yo*7y$qP0{{bNr~m-~hydldIN+E&Pu$>|0|FO+mq9L-Z(ht&pEH;aIf>eQnNUUw%w#tpZ*sn6V~79H'
        ')4GP-;k9v%A=dD#9g&5=W_8r9WbWUWew=*j!et@h8wpm#j=yIjp>i>h)rc7#qY_HlX=Wk(&oj%GcUuHl_hvwZI@w9XF=<#sj}?MO'
        'r5sbi0Sp5ZDx3fS004jhyQQ5kj&sNC()rErMTa52bwW+UsdpwzvqE8wAAx0+CAGC~<%$bikfa{iY}++LB|1=gC<L2}?vjx2zi(*)'
        '!XOV*fqa{>jc##P2f1k}TfDr2T!0ya-y)LqNjH7-{rli?h4ghyytVn_hdP6EFIJT*t`)(52!uG(6fzBiwDrP5aRg+X#z%yRY%BWG'
        'J~-xvQG_4xV3@Exco$kxMK`xvg0hR2Ab^v5#vioqWs3Cz<mrZMfkcoWCV>fW_0p9|L83E9z$>2$RaTZP7S36aeXJ#icsns_Q&r+I'
        'wF22=^j?uFt}6EUz-j7PN5s)TJSVA~w;eyI4nz66mW_T6_)=zRXarI`Qhe4Y%vMn?;0UkfP4>U^W^mEnV`_V5o89E}LD?c71Y(Yu'
        ';|qweX~9m?bHlQgG&=$(en9UOmue(Rgb3xOL>=T&xUbQZ%>>j(rLsm2Oq^lhdafJ!<>d4C+W98szE+LWZJYw6{fg)cNb~|RWiv?&'
        '>H#P!=f8T&GToeNHw-@o%+D4{C7>(<$VW$m^hvho4VW!lgoOGD6q)<uU|uvWxBNj)aT6lXh5j&eRLc<UKi`k92s1&9EW2<xhd>5U'
        '4Kb~T>FAA!fjeSD@0wP^@j0S?ilT8A@9%z^1&>ZaippKps%KubMN*ULL3<d*)XB!3xqA+$g41B{T(K%DDcNgFJc%5E_4~2Sl%h7*'
        'uv-TT*zoq(3IdzkQpSq_s1lM{>LP}KH#*<gIjUDTO)l=)R82{gF%)3LI+~pw?hS3!W@)Ds{A;BtLe!{Sr;LA-g(UycdRAOvht;^k'
        '3c2gsoXH8mW0-2B=7LM<%7sUYec|lEcs|IU!fG*l)0q;RhkFi7`#iKoAm^lK?qc10B|VF*>j?s&_Ho;+&LV_7YTEe!Vg|!iUhZRx'
        'Y4Wv^VqW@CD}P8E<2gcqBJ&SmB9KhmiREi@-G{xLRdEyzro>#mmIzGKMe)T_ld>ve0NmQ4UlY{#yJ>Wunz-csHB3HpQ(IdQNo4Vm'
        'PdpPommp<>2aNIk4x;gm7;xc{CBxgA;&~fj5M6?NPq6A@l%uI;A5NLKKD5vaU(^qmIGMt=rJ#;^0F$_-(J)7LtKJcSjYK3I<TYah'
        '&~5G>5k^qMH@(E49g{nEui)C4;@6>ak4wJ1+tIzItxfZdJ^olq4*<st*$7T=2<N5%{noT5S|tG1AhB|{rDIa~(^VwB4<h0APN+r{'
        'L9!!Sh?Zs7w2=xo1iJJtR)|Ri#@mK>zW(<3Yt<f`Ih-Ju0Itb4dd>j{n>Yr-0h^W|T;$!tE2jm<7A@PF7x28snH>JXzyfK*hVYmJ'
        'wMw5!H&_mVtQq$`g&9&}T0*ccPdLyI(Kv^_9lNQ_Cfv1BjyEU@tuw-%jU6q<i~;-wZJ2qMF}#KXWEc8R50Zhs&^0L_Hb7EY65^#h'
        'n0|+}@HuXsS=R{0-3#L!Fim|S%*Dkm>s#wI3YKk=QSaxd+)A7DiS-)!py7iECx#o)g->SZ9}qyXI7Fr~lUdUc`1J_Ls0Z_eNnP#t'
        '8VKQ}Jk?Q@F<3>xx<3jfMPnBaT*PGkf7do2xb3pxyxtN`mYe8BEG?v~EIA7qGvMxEz{`i|NMoa>oh;IM3UXByl_Gg*+qNfS9y&8I'
        'kmNNyze?#7zN3gcHzOP|(I^@!*QK-gf>u#}u*UWgql2QC_Y~^o>7`FbXX3YP1<2XyxwYQPA#d8Uf|LM#4Ra@I4L69=j>ss5)_4Z3'
        '^!V-Q1CoJSg*<2v3JeIsBi1!k@+a(7RWy|V{SkF#MD@qu;lNS7(_Jops?zfm?Kywk4ILbGn<wip?@~=em^~;@z=^DOuZ2<*Hemzg'
        'jR#1sq`k?Tt#`U8?;?k7!|w0H;wKaRxJlHEahs{hkPhwSTV|VN0Hj2q0ttYb|1uP^14xfy<Pb%!#=2<HV_)j^H-!JEYsxiuAU(Vw'
        'hOL8a!F5Ps$*S0`&xqbV+I<0zh0;`M^3s>vn-Z<-Su#Kf8(-uq>P*BqW_LvifJ)sYp^ChrFo(ro#HG{}7(DFy=<4X|FTlvHE+(^q'
        '50^>VEcGePbi9^~-cp<(GxUtIoE_2@U^SDc5fjGruQG7#DLJ42egW*H!X+6HsrkOt6swEY!3rT>N1<1(pWO*H;W|!%1x>9lp<k8x'
        'WQiO)r6ge{^EnhpTy;OadeRJ8WQv7Xb?#&jHglt`F4&!U-Yjbaj92Ar1`k0Bd+nfI<n$ykIW}bvqI8L#zpG6A&WMR|@Ix3|Q*9w)'
        'P3<fvsT>ajr_p)GuikIScH(Rrvsa!!-=7AnidIr5n#iY1wz(OE%+ElPJy!(0_Ie;%;MF8kY|qguSE8WnR~xQMl-t=gS;D#!DXF)B'
        '7xhaOz)+1^`4TRR2IF|V1PnSPO*Ir~h4kOOz@A*;hVaL6{V`-#ab)sTZU4MPR}Lzg1=g(cErU}J2x(`VTH=o=+!~_ae%-)#+HNIt'
        'STGy@LlO7m7B@QbK^iX5)76kpK<-AL*5vITq%n7XXnCUs&1YE!A6;?tD#2(KdJ`{G0e2;sNCc9xR5~sr?kKDB8(_+N=K@E@;~XjO'
        'vA_-o=I3iE-}t4;lSq~o%iZ}k*;DW~Zq=pJIQ@xK?(k1xJ1(Y;L>ln$Vv`ZWu@C)rQ}VjkzV${qgjx${qs!rSCG;O+4oiC=UmA!s'
        'w=2~IiEY14b!5?_j4f8`f0>_bG1qtRql@PTHHNyZ`)a_!V8Nn#4IVbYq%r%3+*?_@ZbB*4ljwZj3D}Mkb}h*}It7jmj6j_w6BZTL'
        '62j1<vF&G;N~&0K6-9vE8eE9?r+ItnKuVe-nlo{I3o{s?BJy8`Kbz16r#$*m0leb{Om8OP*w~}&ccK_PC{-*P@2Wjfs(~%N=0Q1a'
        'D$>CmZ(>%q3cI6t0ujbSDL?=@Q(K=9EbM<yKtDiTlpclJUZ~dD>E?8hu_gwzwHG`#bDl`?&`^y!6Wwt(R-KOSD#=M%A95VnAZO~R'
        'shea>W&gsZ|6@f$5GeRMQv90G`HSZN)Dv!{&gP7v-OUJU|BNN(F4M5B?%v>ekPof=o5VO5_R%JmL(bgf=LFX9*i33C>|ENY)L$U}'
        'kPC;wRcU>#WeqYZzRkyI0Yw~g;MgvGkv{jRJvC%iTcmQrX_AP$mUJbp(gzvz0+BG={%VNGRZKS=cl6t6dh>AKSOWl2V_m**c2^a8'
        'CwM5zM0>~9D`N@oQM$}u*BRMCn)z{+(?-H2oCy%Z@L^8BPCO6F4pp)IAegEr$|5gv9eigj2X_mE!Sa$0g^~r=a6xr9BN{mfMY*q6'
        '{5g;seM@D5w7-sq$ZGJL>Av+KT(}@L>CT)?(XWo@@#3BK9LL`XoH51Zdp}pzyPO_LfOdjx!x&(Dqsg{#xc_+_uT|v?O+@rJ>E(e4'
        '(m0vanP*x^Pc0ta3C;%8KF@IN81vS~^QTwajtF~pt=r+&dKPU)GaQpxJ78Zm4CCk`kZKBQ3;!i`KJt4Y39p8tn?_z-zB_<LMwZ|r'
        'YmMlMKxJB@oE*|KgVg5TiQJ<+3_zlt4|`VU&OnOuKUi(NWH$O9<!?BJNfn3Ij936(%6+M%AgK*0{M<|VtTO0Rypg_cAvt0M{N0CP'
        'EDh9%-RqaCuD8N&!@ON-kV#fDt$DUDC!yw{@xS`ZtFIVZDecF$<P;QF4(kTLpHCL@kQ6ZGh@eUW<--*^CTxDcF6aHI)bz#J`9;qT'
        'D`!!nF@<+7HK8fPA|AfF=qi1%K)i#oIngkSANza4IM9R6BFZAgx_PRXo4nt7+qDeD6U^%FkMvPm@OyCMEA}P@N$#0&+R{$T{8#dP'
        'rdbt*c&kdoGfQ*IXLK{w_cAE(B?qfeTJZ=TVq_m_4&b;RW$+?r>%+qWZ3%P_2!VBs6t-zC3Jbui)KBRH#yc0_-SbdA0H;d6w?OF`'
        '<Qya?$7_gTc7%Q6K2VgIrCTsB>0Zvo$miJ6eAwQX{R8U~Fm(>5rTb1_r*X;=L6mh{JvK2yvli_WGWIK{zOAmk{R6}<4#w?%d%(El'
        'P)h*<KL9cSLjVW>&#rSh^s)V}Rt*3E_A3AY7yvW?00000001BW00000004Ata4#+{P)k&0cyumMOH)QzE@f_CRZ|K8AOHXW00031'
        '7yv`jov_17$pJ&rov_17$pPGMo3O)5$pIGt3;+TE17@fI0RR91002-+0Rle&G5|vW2msHnb2+plNJ7pG00871000;OGynhq00000'
        'AOHXWj12$)bZu}iE-p|@RAqQ{E>KHTMp!OtVP8s63IHGg000000RR{PL(!eE!%E2kL(!eE!%E2kL(!eE!%E2k7XS<Z0ssSMr~m-~'
        '00000P)h{{000000ssO4^Z)<=kQx90000'
    )
