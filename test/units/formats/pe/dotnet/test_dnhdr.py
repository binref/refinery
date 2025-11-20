import json

from .... import TestUnitBase


class TestDotNetHeaderParser(TestUnitBase):

    def test_hawkeye_header_01(self):
        unit = self.load()
        data = self.download_sample('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        header = json.loads(unit(data))
        streams = header['Meta']['Streams']

        self.assertIn(
            'HawkEye Keylogger - Reborn v9 - {0} Logs - {1} \\ {2}',
            streams['US'].values()
        )

        self.assertEqual('Reborn Stub', streams['Tables']['Assembly'][0]['Name'])
        self.assertEqual(0x2050, streams['Tables']['FieldRVA'][0]['RVA'])

    def test_hawkeye_header_02(self):
        unit = self.load()
        data = self.download_sample('094e7d3e6aebf99663993e342401423dff3f444c332eae0b8f0d9eeda1b809a7')
        header = json.loads(unit(data))
        streams = header['Meta']['Streams']

        self.assertIn('75ae5928-d641-49b7-a7d0-768dbd3a3d80', streams['GUID'].values())

        for sentinel in {
            '_FakeMessageShow',
            '_FakeMessageTitle',
            '_FakeMessageText',
            '_FakeMessageIcon',
            'RebornX Stub.exe'
        }:
            self.assertIn(sentinel, streams['Strings'].values())

        self.assertEqual('RebornX Stub', streams['Tables']['Assembly'][0]['Name'])
        self.assertEqual(0x2050, streams['Tables']['FieldRVA'][0]['RVA'])
