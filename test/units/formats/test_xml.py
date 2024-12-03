#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
from .. import TestUnitBase


class TestXMLUnpacker(TestUnitBase):

    def test_xml_unpacker_01(self):
        @inspect.getdoc
        class data:
            """
            <?xml version="1.0"?>
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
                <name>34C3</name>
                <SSIDConfig>
                    <SSID>
                        <hex>33344333</hex>
                        <name>34C3</name>
                    </SSID>
                    <nonBroadcast>false</nonBroadcast>
                </SSIDConfig>
                <connectionType>ESS</connectionType>
                <connectionMode>auto</connectionMode>
                <autoSwitch>false</autoSwitch>
            </WLANProfile>
            """

        data = data.encode('ascii')
        unit = self.load('WLANProfile/SSIDConfig')
        test = str(data | unit)
        self.assertIn('33344333', test)

    def test_lure_document(self):
        data = self.download_sample('e6daa00e095948acfc176d71c5bf667a0403e5259653ea5ac8950aee13180ae0')
        data = data | self.ldu('xt', 'settings.xml') | bytes

        pipe = self.load_pipeline('xtxml w.settings/w.rsids/w.rsidRoot [| eat val ]')
        self.assertEqual(data | pipe | str, '00BA5B2D')

        pipe = self.load_pipeline('xtxml docVars/10* [| eat val ]| hex | wshenc | carve -dn5 string [| dedup | pop k | swap k | hex | xor var:k ]| xtp url')
        self.assertEqual(data | pipe | str, 'http'':/''/trust-certificate''.net')
