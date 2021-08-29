#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline

from .. import TestUnitBase


class TestPCAP(TestUnitBase):

    def test_pe_extraction_from_pcap(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = load_pipeline('pcap-http [| carve-pe -R | vsect .data | add 20 | xtp | defang ]')
        c2urls = list(data | pipeline)
        self.assertListEqual(c2urls, [
            B'http[:]//setup1.tqzn[.]com/barbindsoft/barsetup.exe',
            B'http[:]//setup2.tqzn[.]com/barbindsoft/barsetup.exe',
            B'http[:]//setup3.tqzn[.]com/barbindsoft/barsetup.exe',
            B'http[:]//setup4.tqzn[.]com/barbindsoft/barsetup.exe',
        ])

    def test_get_request_summary(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = load_pipeline(R'pcap [| rex "^GET\s[^\s]+" | sep ]')
        result = str(data | pipeline)
        self.assertEqual(result, '\n'.join((
            'GET /286/pop.asp?url=http://www.puma164.''com/pu/39685867.htm?2',
            'GET /favicon.ico',
            'GET /286//update.txt',
            'GET /286/soft/163.exe',
            'GET /286/count/count.asp?mac=00-0E-0C-33-1C-80&ver=2007051922&user=00&md5=258a993832e5f435cc3a7ba4791bc3de&pc=BOBTWO',
            'GET /mh.exe',
            'GET /12.exe',
            'GET /286/pop.asp?url=http://59.34.197.''164:81/804635/adx352133.asp',
        )))
