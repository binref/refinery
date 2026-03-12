import json
from .. import TestUnitBase


class TestCarveJSON(TestUnitBase):

    def test_wikipedia_unicode_example(self):
        data = (
            BR'''---------FXFFGA-------##:{"data":{"cobaltstrike":{"status":"success","protocol":"cobaltstrike","result":'''
            BR'''{"config32":{"License":"licensed","Beacon_Type":"0 (HTTP)","Checkin_Interval":7000,"Jitter":37,"Max_DNS"'''
            BR''':0,"HTTP_Method2_Path":"/jquery-3.3.2.min.js","Year":0,"Month":0,"Day":0,"DNS_idle":0,"DNS_sleep":0,"Met'''
            BR'''hod1":"GET","Method2":"POST","Spawnto_x86":"%windir%\\syswow64\\edpnotify.exe","Spawnto_x64":"%windir%\\'''
            BR'''sysnative\\edpnotify.exe","PublicKey":"30819f300d06092a864886f70d010101050003818d0030818902818100d0e198b'''
            BR'''6d7b3e2511a877e25395013605643f18835496d711ec25a0c818f4cc33819d7d81fa2a5f5ea96516fd6d06013b6b853ac4c7bee9'''
            BR'''3043547bd20de7bfb04e6598a98e503c64438fc2ddf41b9a2a599fc7b0ca34b9ea40b557d3d5f5df08720b8362056f830b72c44c'''
            BR'''7ad5f8bdfeb907a10a6d6a65fa1c6f6f6f55a4cb7","PayloadOffset":348,"PayloadKey":3882455566,"PayloadSize":208'''
            BR'''388,"XorKey":46},"config64":{"License":"licensed","Beacon_Type":"0 (HTTP)","Checkin_Interval":7000,"Jitt'''
            BR'''er":37,"Max_DNS":0,"HTTP_Method2_Path":"/jquery-3.3.2.min.js","Year":0,"Month":0,"Day":0,"DNS_idle":0,"D'''
            BR'''NS_sleep":0,"Method1":"GET","Method2":"POST","Spawnto_x86":"%windir%\\syswow64\\edpnotify.exe","Spawnto_'''
            BR'''x64":"%windir%\\sysnative\\edpnotify.exe","PublicKey":"30819f300d06092a864886f70d010101050003818d0030818'''
            BR'''902818100d0e198b6d7b3e2511a877e25395013605643f18835496d711ec25a0c818f4cc33819d7d81fa2a5f5ea96516fd6d0601'''
            BR'''3b6b853ac4c7bee93043547bd20de7bfb04e6598a98e503c64438fc2ddf41b9a2a599fc7b0ca34b9ea40b557d3d5f5df08720b83'''
            BR'''62056f830b72c44c7ad5f8bdfeb907a10a6d6a65fa1c6f6f6f55a4cb7","PayloadOffset":333,"PayloadKey":1633212012,"'''
            BR'''PayloadSize":261636,"XorKey":46}},"timestamp":"2020-12-11T14:34:03Z"}}}::#FGAX12'''
        )
        unit = self.load()
        output = unit(data).decode('ascii')
        output = json.loads(output)
        self.assertEqual(output['data']['cobaltstrike']['status'], 'success')

    def test_incorrect_string_parsing(self):
        data = """{
            "bugcheck": "]",
            "escape": "\\"",
            "problem": false
        }""".encode('latin1')
        self.assertEqual(data, data | self.load() | bytes)

    def test_carve_simple_dict(self):
        data = b'garbage{"key":"value"}more_garbage'
        unit = self.load()
        parsed = data | unit | json.loads
        self.assertEqual(parsed, {"key": "value"})

    def test_carve_nested_json(self):
        data = b'junk{"a":{"b":1}}junk'
        unit = self.load()
        parsed = data | unit | json.loads
        self.assertEqual(parsed, {"a": {"b": 1}})

    def test_carve_list_with_all_flag(self):
        data = b'garbage[1,2,3]more'
        unit = self.load('-a')
        results = data | unit | []
        self.assertTrue(len(results) > 0)
        parsed = json.loads(bytes(results[0]))
        self.assertEqual(parsed, [1, 2, 3])

    def test_carve_no_json(self):
        data = b'no json here'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_carve_dict_only_default(self):
        data = b'garbage[1,2,3]more'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_carve_json_from_surrounding_text(self):
        data = b'Here is some log output: {"status":"ok","code":200} and then more text follows.'
        unit = self.load()
        parsed = data | unit | json.loads
        self.assertEqual(parsed['status'], 'ok')
        self.assertEqual(parsed['code'], 200)

    def test_carve_deeply_nested_object(self):
        obj = {"level1": {"level2": {"level3": {"level4": "deep_value"}}}}
        payload = b'PREFIX' + json.dumps(obj).encode() + b'SUFFIX'
        unit = self.load()
        result = unit(payload)
        parsed = json.loads(result)
        self.assertEqual(parsed['level1']['level2']['level3']['level4'], 'deep_value')

    def test_carve_json_array_with_all_flag(self):
        data = b'before [{"a":1},{"b":2}] after'
        unit = self.load('-a')
        results = data | unit | []
        self.assertEqual(len(results), 1)
        parsed = json.loads(bytes(results[0]))
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['a'], 1)
        self.assertEqual(parsed[1]['b'], 2)

    def test_carve_multiple_json_objects_in_stream(self):
        obj1 = {"first": True}
        obj2 = {"second": False}
        data = b'AAA' + json.dumps(obj1).encode() + b'BBB' + json.dumps(obj2).encode() + b'CCC'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 2)
        parsed1 = json.loads(bytes(results[0]))
        parsed2 = json.loads(bytes(results[1]))
        self.assertEqual(parsed1, {"first": True})
        self.assertEqual(parsed2, {"second": False})

    def test_malformed_json_is_skipped(self):
        data = b'start {"valid":"json"} middle {"broken: no_end more text'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        parsed = json.loads(bytes(results[0]))
        self.assertEqual(parsed, {"valid": "json"})

    def test_empty_object_is_skipped(self):
        data = b'text {} more text {"key":"val"} end'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        parsed = json.loads(bytes(results[0]))
        self.assertEqual(parsed, {"key": "val"})

    def test_nested_arrays_with_all_flag(self):
        data = b'noise [[1,2],[3,4]] noise'
        unit = self.load('-a')
        results = data | unit | []
        self.assertEqual(len(results), 1)
        parsed = json.loads(bytes(results[0]))
        self.assertEqual(parsed, [[1, 2], [3, 4]])
