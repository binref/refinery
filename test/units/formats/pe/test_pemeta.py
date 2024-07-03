#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from ... import TestUnitBase


class TestPEMeta(TestUnitBase):

    def test_rw_dotnet_sample(self):
        data = self.download_sample('426ace19debaba6f262dcd3ce429dc8fc0b233f3fa02262375c4641d9f466709')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertIn('Version', result)
        self.assertIn('Header', result)
        self.assertIn('DotNet', result)
        self.assertIn('TimeStamp', result)
        self.assertIn('Signature', result)

        self.assertEqual(result['Version']['ProductName'], 'shimgenerator')
        self.assertEqual(result['DotNet']['ModuleName'], 'shimgen.exe')

        self.assertEqual(result['TimeStamp']['Linker'][:19], '2017-06-03 22:05:18')
        self.assertEqual(result['TimeStamp']['Signed'][:19], '2019-06-03 21:07:55')

        self.assertEqual(result['Header']['Subsystem'], 'Windows CUI')
        self.assertEqual(result['Header']['Type'], 'EXE')
        self.assertEqual(result['Header']['ImageBase'], 0x00400000)

        self.assertEqual(result['Signature']['Serial'], '07fb45d9f70b5529036097b4f4e14370')

    def test_rw_delphi_sample(self):
        data = self.download_sample('ce1cd24a782932e1c28c030da741a21729a3c5930d8358079b0f91747dd0d832')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertIn('TimeStamp', result)
        self.assertIn('Signature', result)

        self.assertEqual(result['TimeStamp']['Delphi'][:19], '2013-05-18 21:34:26')
        self.assertEqual(result['TimeStamp']['Linker'][:19], '2013-05-18 17:34:25')
        self.assertEqual(result['TimeStamp']['Signed'][:19], '2013-05-18 17:39:43')

        self.assertEqual(result['Signature']['Subject'], 'Usoris Systems')
        self.assertEqual(result['Signature']['Serial'], '67fd5aec0d8f9f6f1caa40589f568a0c')

        signature = self.ldu('pesig')(data)

        self.assertIn(signature, data)
        data = data.replace(signature, B'')
        result = json.loads(unit(data))

        self.assertNotIn('Signature', result)

    def test_adware_sample(self):
        data = self.download_sample('7fa4aeffba01ad34ed2fa4b77d3dee11fd881075f37a5b840e15ec86bef320ab')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertIn('Signature', result)
        self.assertIn('Serial', result['Signature'])
        self.assertEqual(result['Signature']['Serial'], '0ce8111784c41955f33511aeb28c9ab8')

    def test_serial_overflow_and_authenticode_info(self):
        data = self.download_sample('480ca9086fd1999975c1c060a36c57a746f87e51681417d8c8b89648796f78ca')
        unit = self.load()
        result = data | unit | json.loads

        self.assertIn('Signature', result)
        self.assertIn('Serial', result['Signature'])
        self.assertEqual(result['Signature']['ProgramName'], 'KMSpico')
        self.assertEqual(result['Signature']['MoreInfo'], 'http://forums.mydigitallife.''info/threads/49108')
        self.assertEqual(result['Signature']['Serial'], 'ab81dc9f367529be42665b07570ffa05')

    def test_broken_signature_01(self):
        data = self.download_sample('2178989d216d0d62d354076e7fb172b6450695613bc971495e14a21a2d6a7603')
        unit = self.load()
        result = data | unit | json.loads

        self.assertIn('Signature', result)
        self.assertIn('Serial', result['Signature'])
        self.assertEqual(result['Signature']['ProgramName'], 'MozDef Corp')
        self.assertEqual(result['Signature']['Subject'], 'outlook.com')

    def test_broken_signature_02(self):
        data = self.download_sample('dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78')
        unit = self.load()
        result = data | unit | json.loads
        self.assertIn('Signature', result)
        self.assertIn('Serial', result['Signature'])
        self.assertEqual(result['Signature']['ProgramName'], 'Microsoft Windows')
        self.assertEqual(result['Signature']['Subject'], 'Microsoft Windows')

    def test_all_pids_can_be_shortened(self):
        from refinery.units.formats.pe.pemeta import RICH, ShortPID, get_rich_short_pid
        pids = set()
        for r in RICH['pid'].values():
            pids.add(get_rich_short_pid(r))
        self.assertSetEqual(pids, set(ShortPID))
        with self.assertRaises(LookupError):
            get_rich_short_pid('BOGUS')
