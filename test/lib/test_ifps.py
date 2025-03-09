#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestBase


class TestIPFSEmulator(TestBase):

    def test_variable_representation(self):
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.archive import InnoArchive
        data = self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
        inno = InnoArchive(data)
        ismu = InnoSetupEmulator(inno)
        self.assertEqual(repr(ismu.globals[1]), 'GlobalVar1 = 0')
        ismu.globals[1].set(7)
        self.assertEqual(repr(ismu.globals[1]), 'GlobalVar1 = 7')
