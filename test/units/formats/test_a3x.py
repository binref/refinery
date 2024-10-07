#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestA3X(TestUnitBase):

    def test_ea06(self):
        sample = self.download_sample(
            '3b775e678568cd3d55187443a3f7aae2116b7e9762b3c3879f5e1c6225434b25')
        taint = sample.replace(
            b'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D',
            b'\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0\xDE\xFA\xCE\xD0'
        )
        for data in [taint, sample]:
            out = data | self.load() | {'path': [...]}
            self.assertEqual(len(out), 4)
            for key, value in out.items():
                self.assertEqual(len(value), 1)
                out[key], = value
            self.assertSetEqual(set(out), {'script.au3', 'msc.exe', 'MSWINSCK.OCX', 'DrWatson.exe'})
            self.assertContains(out['script.au3'], Br'FileInstall("msc.exe", @SYSTEMDIR & "\msc0nfig.exe")')
            self.assertContains(out['script.au3'], Br'FileInstall("MSWINSCK.OCX", @SYSTEMDIR & "\MSWINSCK.OCX")')
            self.assertContains(out['script.au3'], Br'FileInstall("DrWatson.exe", @SYSTEMDIR & "\1096\DrWatson.exe")')
            self.assertContains(out['script.au3'], b'jan1_milan'b'@yahoo'b'.com')

    def test_ea05(self):
        sample = self.download_sample(
            '9b66a8ea0f1c64965b06e7a45afbe56f2d4e6d5ef65f32446defccbebe730813')
        out = sample | self.load() | {'path': [...]}
        self.assertEqual(len(out), 1)
        for key, value in out.items():
            self.assertEqual(len(value), 1)
            out[key], = value
        self.assertSetEqual(set(out), {'unicode-script.au3'})
        self.assertContains(out['unicode-script.au3'], '''new ActiveXObject('WScript.Shell').Run'''.encode('utf-16')[2:])
