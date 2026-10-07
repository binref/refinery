import gc
import json

from refinery.lib.dotnet.header import NetMetaDataTables

from .... import TestUnitBase


class TestDotNetFieldExtractor(TestUnitBase):

    def test_real_world(self):
        data = self.download_sample('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        unit = self.load('mykey', '6DDE')
        key, payload = data | unit
        test = payload | self.ldu('xor', key) | self.ldu('pemeta') | json.loads
        self.assertIn('DotNet', test)
        self.assertEqual(test['DotNet']['ModuleName'], 'atwork.exe')

    def test_a_run_keeps_no_metadata_tables_alive(self):
        def tables():
            gc.collect()
            return sum(isinstance(obj, NetMetaDataTables) for obj in gc.get_objects())
        data = self.download_sample('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        before = tables()
        list(data | self.load('mykey', '6DDE'))
        self.assertEqual(tables(), before)
