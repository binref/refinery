from ... import TestUnitBase


class TestISOFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('d4bd4131c785b46d7557be3a94015db09e8e183eaafc6af366e849b0175da681')
        unit = self.load()
        unpacked = unit(data)
        self.assertTrue(unpacked.startswith(b'{\\rtf1'), 'unpacked file is not an RTF document')
        self.assertIn(B'EU48RUK5N4YDFT73I3RIF3H3UH', data)

    def test_real_world_01(self):
        data = self.download_sample('1c4b99cb11181ab2cca65fca41f38b5e7efbc12bf2b46cb1f6e73a029f9d97f0')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('4963339bb261a8abc0dfdc95cd37dd3d5624f283402bfd72c6486e19bb5aedd5', chunks['start.cmd'])
        self.assertEqual('bdceb5afb4cb92f1bb938948cbe496bfa3de8c8d7b1f242cb133e2b18600256b', chunks['macosx.dat'])
        self.assertEqual('36484434a281c6ed81966682dede4cbb5cfb7eed775cdcf001a348939e3bb331', chunks['Attachments.lnk'])

    def test_real_world_02(self):
        data = self.download_sample('3b215a9d7af057b5bcdd2ad726333d66ef1701eae11cb1fb9d12c0338f5693a0')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('c826cda4ccfe815e0be4e9a007c0c32a6e7d9757140f0d1123a4e1e134e553c3', chunks['readme.txt'])
        self.assertEqual('81deb33e1cdd6bcca6e8464141ddd28de8cf3c586ddca2ce39c5448b43461c1b', chunks['readme.html'])
        self.assertEqual('b5bec5fab272c825a54b6eed129949db9d79b94fa8fce5a550a5901b2ec3937a', chunks['plpinstc.com'])
        self.assertEqual('90cdf6e126e574409d77b1fafa1945ec251e59a7c050d88d43e838a20d6cf590', chunks['liesmich.txt'])
        self.assertEqual('cf8f25af4cfe40ae8e1be28ad49220ed01c6ec7e23917cb4c181078532e352b3', chunks['liesmich.html'])
        self.assertEqual('e303921ad81f685d35ec38122320c8633255d05fa191b8d97e7a7d6555b26b8d', chunks['licence.txt'])
        self.assertEqual('eaf3aa81fe9fa245e4b9f9d0978e70b1a3822ef8cf4f4d7f2029aeadd3970b47', chunks['isolinux.cfg'])
        self.assertEqual('2ecb32325499df028e8cf980918a91964c0c15c4b0e65cc01c5f2a2899a77363', chunks['isolinux.bin'])
        self.assertEqual('637e2c44c586bb18b4d72791eda901fb5ff8c1e80a7977719df2f98768b1f75d', chunks['boot.catalog'])

    def test_stripping_revision_numbers(self):
        data = self.download_sample('52e488784d46b3b370836597b1565cf18a5fa4a520d0a71297205db845fc9d26')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('187c69325af91afb8df501ba842fe993496f1e4e7914c437f26cdb365f1105dd', chunks['TL2064100007xls.exe'])

    def _test_coverage_sample(self, sha256):
        expected = _COVERAGE_SAMPLES[sha256]
        data = self.download_sample(sha256)
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        for path, file_hash in expected.items():
            self.assertEqual(file_hash, chunks[path])

    def test_coverage_00cd(self):
        self._test_coverage_sample('00cd2850489cf197ac4ba99786d192dd0135fdbd6922130a0ad17ecf905de2d1')

    def test_coverage_ff42(self):
        self._test_coverage_sample('ff42e1a03e7d70b48305d83edf6ed5fce0a858ef001acafab86e9e03c561f30c')

    def test_coverage_e81a(self):
        self._test_coverage_sample('e81af9201d76081c695f616a118b0c7e16087d8a8bef5e44daa63e7396bd8c4f')

    def test_coverage_276e(self):
        self._test_coverage_sample('276e7a55df16522ee3e187815ff76fa3562b8a609632acbb9fea4ec385941694')

    def test_coverage_1ee7(self):
        self._test_coverage_sample('1ee7a84afebc657e0252a828b95e19eaeb95d9eb59f025de4ce5a85d8637f7d6')

    def test_coverage_06cd(self):
        self._test_coverage_sample('06cd1e75f05d55ac1ea77ef7bee38bb3b748110b79128dab4c300f1796a2b941')

    def test_coverage_d17b(self):
        self._test_coverage_sample('d17b4c19412a5ad927b6249a29a3b7901ce8815dcfa048531e67a4439298dcc5')


_COVERAGE_SAMPLES = {
    '00cd2850489cf197ac4ba99786d192dd0135fdbd6922130a0ad17ecf905de2d1': {
        'vmadd-full-0.0.1-1.i386.rpm': 'a6d095e3d4de011fa5d20f5b700f087f33df7f9873bc3af73ac243039ca3bd4b',
        'vmadd-heartbeat-0.0.1-1.i386.rpm': '69fdb6c78b8f7f4f13b8189f039e553e8a0f414b33e32ca60d41e04ff7015ee5',
        'vmadd-kernel-module-0.0.1-1.i386.rpm': 'ffbd04d3c2d395c82ecf273d57bd500e4be07a1dcfc2279e4236e9a2ba3b5d5b',
        'vmadd-scsi-0.0.1-1.i386.rpm': 'eb07dad2cce77cfa7191dece180671137cefd799c62e2cb428edd881fddccd27',
        'vmadd-shutdown-0.0.1-1.i386.rpm': '5a0a7e4efc93f87817628ab0bca56c53affa1a33ed1bd52b9644c5364465b495',
        'vmadd-timesync-0.0.1-1.i386.rpm': '1b6791ffa3ef5957efd7a3ca2a91b09c1aeb279d888ced2d5cf46ebd252bfb11',
        'vmadd-x11-0.0.1-1.i386.rpm': '66cddd2d9c6faa88b224ad5eb70b88d829de27463ee4436517c1b540112e2368',
    },
    'ff42e1a03e7d70b48305d83edf6ed5fce0a858ef001acafab86e9e03c561f30c': {
        'CDVD.IRX': 'b4c4f14a36817ba189ba7c8363bc042d84c032c14a7d223bfa9cdbd40cc3a738',
        'COLECO.ROM': '990bf1956f10207d8781b619eb74f89b00d921c8d45c95c334c16c8cceca09ad',
        'COLE_000.02': '91abd78bd73a27a0ccaf283e44060ab90ea449529b0383301c61e91b4dde87c0',
        'SJPCM.IRX': 'af8921698a38918407dbfdb672b693c2427f2eef0ff0f1aef4bffb59728f533c',
        'SYSTEM.CNF': '3c33e162a206418d4efac11ff02f5c99cd6e6010f3ae2910b2bb69b6cb6f6542',
        'COLE/2010T.ROM': '6dd7e4103ac1d2c66347eb56024bd4f4f9a6d337d07f3e8a1333671b3fd5ea05',
        'COLE/ALCAZAR.ROM': '60f1f950ff632f0c52320ffa80b603f920327efa2d397b5bbb063ad6dccc732f',
        'COLE/BEAMRID.ROM': '1bd4d65d529d32d5bd1015217e56b76767bd8870aedb54d3989a8ba27329941a',
        'COLE/BRAIN.ROM': '2f32895b9d8cc6da4e53d9d5486ec02c64d9961f8a02407f34b8a9bfaa7bace7',
        'COLE/CABBAGP.ROM': '56983cab4ed13557e9a18e309c8782d007727bf9a4c062ea9cee2a4945c6ef31',
        'COLE/FLIPPER.ROM': 'daad0566e18772fcd77a7173cd0327e39a13dbc5c337bbc3f1dd8a622c165b76',
        'COLE/FRENZY.ROM': '147bfd5d30562afaf52da2da18ba251ff799b81a87f41ca44b5412782845f979',
        'COLE/FROGGE2.ROM': '11f6adfdb3e9865acd9318d2203e151fd432ea8f4ed77af881db727daf99e81e',
        'COLE/FROGGER.ROM': 'c6ab01add1496516487dc9541301124a6f6418d3fc7be6a62bf7a256824a8f4d',
        'COLE/HEIST.ROM': 'b1bfbf8e6cfb4231cfbd4444504ac9f90757409f46670e520050ffe6d5972e6f',
        'COLE/HERO.ROM': '89c35cbf611d26f1020d4aaa4bd501a8a5c181957314835464661e738b353b16',
        'COLE/JUNGLE.ROM': 'fdb569d6aed8900130eb8253a2d81d790041aee0d78f29e1c4362bd77ff8918f',
        'COLE/KEYSTON.ROM': '2f62c92d9863fdbb3c09362542968c13b4790c8e086ed5b65d39bcadf20477e2',
        'COLE/MATTP.ROM': '0966c82becff0142cb76cb4d5d5d164d993d077364433d0b4e41de15e6ec5137',
        'COLE/MONTEZU.ROM': '826ff5ed50f34d94db8c0b9a104ff472f4bb321c643346fdee9f4a3b365405ee',
        'COLE/MOUSETR.ROM': '6c0a9a6b9e455c93e41b8de4c55c60acfe6a81a325b0c887e3945a46a4401fce',
        'COLE/OILSW.ROM': '52324b442f353a055671c3df4e15525a823608ea45f00cbb261da5d4405484d4',
        'COLE/PACMAN.ROM': 'd69a41374276258c44743e42938072404d9d39be3c6dd01ad408086f194a9664',
        'COLE/PITFAL2.ROM': '37ca8e071058d53465ff54afdd3151e76a6db2e9ec916069051a429897aa5835',
        'COLE/PITFALL.ROM': '7a34ee88fb0d1bc7f59aa79aac62ecde04fdb09305061cdaaf6f6f296a306ddb',
        'COLE/RIVER.ROM': 'ed2dea3caadfb8087c52b911fe381eba58d81e0af1dcf14ff3889c9c2d0a68e4',
        'COLE/SKYJAGU.ROM': '2952eac4f9c5388ecb2e9228ab78911592050aca82357a8050d6ce903d7f9da8',
        'COLE/ZAXXON.ROM': '440a043660e041ac5021df37d65ac402e121bcfa498a1cb796e0c7c91d407ab3',
    },
    'e81af9201d76081c695f616a118b0c7e16087d8a8bef5e44daa63e7396bd8c4f': {
        'gm.exe': '6b62b1084fcbd39c67c946a1b054bafb6d315223535f7afea19fc382a8dd5ce7',
    },
    '276e7a55df16522ee3e187815ff76fa3562b8a609632acbb9fea4ec385941694': {
        'ForestDumbForever!.info': 'b7b89faf65b3dd1df294b5ccbe44d5741d5d245aa6577882be9c95694c03ed70',
        'Archiv/ForestDumbForever!_D1.dms': '328057e1a6b27b74e27de609c21f86b367e94d48d7d9ffdd08375eeffd95f409',
        'Archiv/ForestDumbForever!_D2.dms': '5c371148152f73403c045e0eea327cb67ac17342c41f20c87f10a49e323410a8',
        'ForestDumbForever!/!EAGLE_SOFT!': 'f47d02df8ce0735ae84539715563eb6aa66314ccbf94eeb396fd2062edd5484f',
        'ForestDumbForever!/Anleitung.asc': 'eccc1baf4f41991b436594da6cca3a2008c0342f04a055b55e4a94570caa03f1',
        'ForestDumbForever!/Anleitung.asc.info': '846d5c78da6663721f38ae8d091baa931da86b0573c43eac8ca13ba21f4a7396',
        'ForestDumbForever!/EasyInstaller': '1ec7681d3d67e9586533b65ab78f9e86d978eaf4abbbf9bcc6b382092c074d28',
        'ForestDumbForever!/f.s': 'dc012dc33d1a4d7efa2020e7e83b75eef60f37cc03570abcef09c82f9d527d82',
        'ForestDumbForever!/FOREST_DUMB_FOREVER': 'a8492e745afec22307b144bd55222c7250335e717e8e10e44bf2ef21677c203b',
        'ForestDumbForever!/FOREVER!': '196ae4c28809adf8d2f1b2914f82c0da851462a944aefb8c6766225fa6792961',
        'ForestDumbForever!/FOREVER!.info': 'f651e87bb7258d17435182dfe99fecdfbcd94c48accf0a045cfcd5c81a1200a8',
        'ForestDumbForever!/HD-Install': '908c4bc5baad58e95104165e89beda4a6875286ee10854580aad9ecfb68aceb8',
        'ForestDumbForever!/HD-Install.info': '7c466a54e38154b71193e50eab9a8c0d6ef20f31b54729232fa339d400a18509',
        'ForestDumbForever!/IconX': '042b8e0bb79f7d91d542f239d40fffe9421781f42c31e1087ebfeb9f173d12c8',
        'ForestDumbForever!/Installer': '998a87560b1e0d17cc62832ff5d67e424a81680489f1170b7437c168c1041268',
        'ForestDumbForever!/Instaluj': 'f6f25c3b82dd206844b86973c51079fba328bc4509ac5d11f13ad8e310671efc',
        'ForestDumbForever!/Instaluj.info': 'e431bed21f0610a5bff5bc4af595e70842bbc703ac8c9f415264b07cd03e04da',
        'ForestDumbForever!/Manual.asc': 'b72a57f33d35b06a97887f65b72e9b27650d410a1a020b845f500b9e10d2ab8f',
        'ForestDumbForever!/manual.asc.info': 'd76b49553f1fe4f56847c5d2e9b9ac6c70d077ef4d9af5f7cc02c82d75cf3508',
        'ForestDumbForever!/StworkiNew.mask': '5bea38fffaf780264bc4466768bfd8b47a1a6c72fef373680c11c2c712db7cc4',
        'ForestDumbForever!/StworkiNew.rawm': '106e55c18a042d22a9f3c826b5e7a08ff5b54637a1d97e4ec07d8cd372c9e3b1',
        'ForestDumbForever!/_BALLA': '6e6e145693a7155385e8b97e46f3d7a64115283f36b2207ba15e77139ef3e66f',
        'ForestDumbForever!/_CZOLOWKA': '38f0d0e5fdcacbde33d12d9fff86ca40c4d2f2549b99a56b9f0b8a09549296a9',
        'ForestDumbForever!/_ELEMENTY.MASK': '85d181c112a3783c9b2dbc4a68cd5ae814f0c3ab844b94456585f93c8e7df72a',
        'ForestDumbForever!/_ELEMENTY.RAWM': '202dfb32baafcfa9b8cee0e34f143878e29e650f60393c6ba0d9f87bf3326956',
        'ForestDumbForever!/_END': 'd4f758fd1c307c9b45b9a6f03696ce99c6aee6c5e3ec661c076c9146b7867a4b',
        'ForestDumbForever!/_Gen1-1': 'ed31a0e198f6305a372067815767cf645407f417c2b976cc08472b9a56d3ce26',
        'ForestDumbForever!/_Gen1-1.Mapa': '10b52abde0e8cb693f64388ba49eac549a31e3ea93d678c720466fe725f54f26',
        'ForestDumbForever!/_Gen2-1': 'd811c75a23b59ad29a05013c8de2981f39714df6cf255b13fb694a6f06f46872',
        'ForestDumbForever!/_Gen2-1.Mapa': 'dab2653d9f204818cdf7d39861fd8901287690cd2d85f70be9fe2dbcc13d0261',
        'ForestDumbForever!/_Gen3-1': 'dcbd76a87873ed1ff303e33c2c333747ea077a0058e8719b5bd1ef3505dedad1',
        'ForestDumbForever!/_Gen3-1.Mapa': 'a56e7ff7d6472d59bd69a31eef70b4df40356359b4f8b63ada89fa6b329c3a2a',
        'ForestDumbForever!/_Gen4-1': '219b2031dd38ac16e4c61bea81de9e1a1633a5f21cf680d99b408efbc502d65f',
        'ForestDumbForever!/_Gen4-1.Mapa': '5cc857d1d4204af21415ccf4d140e23e012d66c2400e9cdd51855062d359da84',
        'ForestDumbForever!/_Gen5-1': '970b3423f7452fac10e0f6febfbe697e6e50b5154563a47a451e89917aa7a4aa',
        'ForestDumbForever!/_Gen5-1.Mapa': 'dec46614a68f102b50eab534b82ed80c8775c9ca605977f75040da77f007ed8c',
        'ForestDumbForever!/_Gen6-1': 'd68db2086773401ea7572feee0faa5abe614575160177628a813193993d09664',
        'ForestDumbForever!/_Gen6-1.Mapa': '66648d29d22ded00558d53bbfa4ef9a00dc32fe91f7684def9a2407a5954c54b',
        'ForestDumbForever!/_Mapa1-1': 'd97000598c9e06e2c2f3c387869b282b95ee62718b1912dd5597d0bbb8e197e2',
        'ForestDumbForever!/_Mapa1-1.Mapa': 'c4c7f0c8026189444323d414ad0a63fab83ef1b95ae1fc63adb4def32403869f',
        'ForestDumbForever!/_Mapa2-1': '3ad6ee3b512a87e518c9301a6cda8590c276ff0ba46d2e9e0003c7b62de0c0d0',
        'ForestDumbForever!/_Mapa2-1.Mapa': 'f6f99453d7736a38696e369bc13171751efde84d1bf824162a7b88f0a7ca83ee',
        'ForestDumbForever!/_Mapa3-1': '6a9d092a08cfa14d02fc3409ae4136a66b0aac42c40bca4b55c7f63200194597',
        'ForestDumbForever!/_Mapa3-1.Mapa': 'd3b9213fe8d767b2872a6bb5f17e53107a839b286c859b85cc8089ca4b264c17',
        'ForestDumbForever!/_Mapa4-1': '0badd45a9aa39f1c1ead82a6e06eaa556898c51d9e29d54a5ddfa8cd47a147f4',
        'ForestDumbForever!/_Mapa4-1.Mapa': '375ead289287547b179a972830337e64a8b75e1e02d386d34a60e524f88e13db',
        'ForestDumbForever!/_Mapa5-1': '30a4bd65cae79d11c377ecb5e9a5434f8683b7df0c31148c8a54350eba9c3b11',
        'ForestDumbForever!/_Mapa5-1.Mapa': 'cd273471f28c2b91dfbb723e60d249c5900ce23d4cbc3e15c085877d40d76dc1',
        'ForestDumbForever!/_Mapa6-1': '98286bd7346213e3f915e9c1367389e1bdf14dd40a97c2a0ae7d96786bb2a17d',
        'ForestDumbForever!/_Mapa6-1.Mapa': 'e8a80f4b1f0f97ae7b22f50b829f225002c14a8c7650f21e71f51be3950123be',
        'ForestDumbForever!/_MapaBobow1': '0b0c8e4a647179a0c4090fda46dbb67c1f3979517cc27929e5ab1b9dbe87250e',
        'ForestDumbForever!/_MapaBobow2': 'b2f32f974ceecf1c2be538c4b9cc6b45b35d7656fb82a368569cc7ef2a083377',
        'ForestDumbForever!/_MapaBobow3': '82e0c2382d8aba820f8214c8dad48c87d7a11429708199c2067cbca7291bf538',
        'ForestDumbForever!/_MapaBobow4': 'c36f857ef1599645506721dd7df0a6d589a252ac2ee2a61fe55ec9ad01c2868d',
        'ForestDumbForever!/_MapaBobow5': '9b17dae077e21f9487a5e392437ce155891ba12092f77e22bdf520cfbab43e11',
        'ForestDumbForever!/_MapaBobow6': '36026d32fda65f9809aaf93061add410cebae4dacff42f08b0f8d8d0eeaef1dd',
        'ForestDumbForever!/_NAPIS': 'a11c42268b3f4501d1faa8633047ff37c7e54ab9fc673ec68864f10ca7ff162c',
        'ForestDumbForever!/_OPCJE': '5cd46f6ea047e2f44dc8874a6f583541983f38631f18c669a2333428fa7f650a',
        'ForestDumbForever!/_Plomien1': '0bcf1d2cd0d9afaf9478a5e32a838236257d14dfec72f6012e3d198a399ce6d5',
        'ForestDumbForever!/_Plomien2': 'c11693b4ca39c305119a2c8497adee7de638b3f32b0f2f5813e19e21fe10f19b',
        'ForestDumbForever!/_Plomien3': '8706fd9d9bca68b8eaebdd88b260702165c09378f1d116a5abbeacfbba00baae',
        'ForestDumbForever!/_WYBIJACZKA': 'aab16cd94aa5e16aefd02bfcb528cc05dd62df6f4ab506cf1c3036496fec25a8',
        'ForestDumbForever!/_WYBIJACZKA2': '51241fbd5beb72a9169c702bfe4a39d9f616f05fb5d1abff93e8d3a57b3a9684',
        'ForestDumbForever!/_WYBIJACZKA3': '6adb01acf9a71b246f6415f9b61ecc3cbbb26539a9dcc6699f6fde1af4ef0508',
        'ForestDumbForever!/_ZNIKAJKA1': 'd8ae0a0246e4f24c2519268433b0435af3393c8c4fad8a94ce32ce6f026e7c11',
        'ForestDumbForever!/_ZNIKAJKA2': '68008d046b7d6c2db8c4f33cd1a712c09b26588729f7f3a8f6f329cbc4cd8cfe',
        'ForestDumbForever!/_ZNIKAJKA3': '944ab690cce4bfe500505b5b133bf464e3f98897aa9090d755a1e88ef465cea4',
    },
    '1ee7a84afebc657e0252a828b95e19eaeb95d9eb59f025de4ce5a85d8637f7d6': {
        '.DS_Store': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        '.MacFlyPro.plist': '986f980c0141dbf666ca9bbebddaa81f6685416aa27a6b3c60dd72e7dffb0cb3',
        'Macflypro_Installer.pkg': '5781664580189b69b1553f65b5564c08baaf94c049c37a08151ec561e717897f',
    },
    '06cd1e75f05d55ac1ea77ef7bee38bb3b748110b79128dab4c300f1796a2b941': {
        'LUBR302JKMSA.VBS': '717e93d21b7e30d00dab94fa41f5a2348976ce7841c3223ced3675495ad9bdee',
    },
    'd17b4c19412a5ad927b6249a29a3b7901ce8815dcfa048531e67a4439298dcc5': {
        '6ddd602cc282b8a72-816779ddd662cc282b8a72-8166-9ceb-898064d602cc.vbs': (
            '838bd2701eb717008085a3eab646d939350ae920b514628d2da492e35bd762f0'
        ),
    },
}
