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
