#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestUrlGuards(TestUnitBase):

    def test_proofpoint(self):
        unit = self.load()
        mangled = b'From:\tKundenservice https://urldefense.proofpoint.com/v2/url?u=http-3A__flug.de&d=QvLrbZ&c=9bHxBirl7V2BSNQqRIlZm7QPNwtLyu7ZHB91-N5hDPk&r=8uoIV2slkgrz5DYvEV5xGmj5ibGk65FDGf7CywSLVkR&m=FhF882hCZdp8vB-uZdWzjR9Za-O_BkusWxxYolPiSCO&s=p8sGWK1qfzyeqyRjPjq1mrcScK4yzSdLsS24vqqfbGY&e='
        cleaned = b'From:\tKundenservice http://flug.de'
        self.assertEqual(cleaned, unit(mangled))

    def test_outlook(self):
        unit = self.load()
        mangled = u'Report to Dropbox <https://apac01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.dropbox.com%2Fl%2FMsV4FlOqB46esYrRR4h37fZuRXl4lHkkB93%2Freport_abuse&data=02%7C01%7Ctim.kelsey%40digitalhealth.gov.au%7C31d152ee19d64a3b53a908d6b7dc42a2%7C49c6971ed0164e1ab04195533ede53a1%7C0%7C1%7C636898553972831008&sdata=MYXFcUyJ5Sxfo31AJJu3%2FdebHsiYaE46n%2B6wF%2BwKvQw%3D&reserved=0>\n\t© 2019 Dropbox'.encode('UTF8')
        cleaned = u'Report to Dropbox <https://www.dropbox.com/l/MsV4FlOqB46esYrRR4h37fZuRXl4lHkkB93/report_abuse>\n\t© 2019 Dropbox'.encode('UTF8')
        self.assertEqual(cleaned, unit(mangled))

    def test_proofpoint_from_docs(self):
        # Examples taken from:
        # https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/URL_Decoder_API
        unit = self.load()

        for example in [
            {
                "encodedUrl": B"https://urldefense.proofpoint.com/v2/url?u=https-3A__media.mnn.com_assets_images_2016_06_jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg&amp;d=DwMBaQ&amp;c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&amp;r=BTD8MPjq1qSLi0tGKaB5H6aCJZZBjwYkLyorZdRQrnY&amp;m=iKjixvaJuqvmReS78AB0JiActTrR_liSq7lDRjEQ9DE&amp;s=-M8Vz-GV-kqkNVf1BAtv38DdudAHVDAI6_jQQLVmleE&amp;e=",
                "decodedUrl": B"https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg",
            },
            {
                "encodedUrl": B"https://urldefense.proofpoint.com/v1/url?u=http://www.bouncycastle.org/&amp;k=oIvRg1%2BdGAgOoM1BIlLLqw%3D%3D%0A&amp;r=IKM5u8%2B%2F%2Fi8EBhWOS%2BqGbTqCC%2BrMqWI%2FVfEAEsQO%2F0Y%3D%0A&amp;m=Ww6iaHO73mDQpPQwOwfLfN8WMapqHyvtu8jM8SjqmVQ%3D%0A&amp;s=d3583cfa53dade97025bc6274c6c8951dc29fe0f38830cf8e5a447723b9f1c9a",
                "decodedUrl": B"http://www.bouncycastle.org/",
            },
            {
                "encodedUrl": B"https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$",
                "decodedUrl": B"https://google.com:443/search?q=a+test&gs=ps",
            }
        ]:
            self.assertEqual(
                example['decodedUrl'],
                unit(example['encodedUrl'])
            )

    def test_multiple(self):
        unit = self.load()
        result = unit(B'https://ctp.trendmicro.com/wis/clicktime/v2/clickthrough?url=https%3A%2F%2Femea01.safelinks.protection.outlook.com%2F%3Furl%3Dhttps%253A%252F%252Fearlyyears.register-me.uk%252F%26data%3D02%257C01%257C%257Ca33fd5f06d894aa2440608d688424db3%257Ca708279dde884b62956085a6be8c08cc%257C0%257C0%257C636846215676444342%26sdata%3DFT9IDMzDty7e%252BHKSV4cKQCci8aXVAM8b7P9FTae4n6o%253D%26reserved%3D0&uuid=2dd83146-2964-11e9-913a-02f49198539e&auth=31bbc6a83b73e178539aa463ed38c9bab679818c-b4a3fff82d5c0bbc06a9f06593ed41a47737ef34')
        self.assertEqual(result, B'https://earlyyears.register-me.uk/')
        result = unit(B'https://ctp.trendmicro.com/wis/clicktime/v2/clickthrough?url=http%3A%2F%2Fb2bnetwork-online.com%2Fr%2FwISqFfT4067ms210.html&uuid=7c9f1b02-85a7-11e8-9466-0a5a4136c366&auth=2dc9e1234ac4d7d7fe90b44830cb6a6ab54f5623-38190d35acc1780880f39ebca32c99369e78122e')
        self.assertEqual(result, B'http://b2bnetwork-online.com/r/wISqFfT4067ms210.html')
