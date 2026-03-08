import plistlib
from .. import TestUnitBase


class TestPlist(TestUnitBase):

    def test_binary_plist(self):
        obj = {'key': 'value', 'number': 42}
        data = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        unit = self.load()
        result = data | unit | bytes
        self.assertIn(b'"key"', result)
        self.assertIn(b'"value"', result)
        self.assertIn(b'42', result)

    def test_xml_plist(self):
        obj = {'name': 'test', 'items': [1, 2, 3]}
        data = plistlib.dumps(obj, fmt=plistlib.FMT_XML)
        unit = self.load()
        result = data | unit | bytes
        self.assertIn(b'"name"', result)
        self.assertIn(b'"test"', result)
        self.assertIn(b'1', result)

    def test_nested_dict(self):
        obj = {'outer': {'inner': 'deep'}}
        data = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        unit = self.load()
        result = data | unit | bytes
        self.assertIn(b'"inner"', result)
        self.assertIn(b'"deep"', result)

    def test_boolean_values(self):
        obj = {'flag': True, 'other': False}
        data = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        unit = self.load()
        result = data | unit | bytes
        self.assertIn(b'true', result)
        self.assertIn(b'false', result)

    def test_reverse(self):
        """Test JSON -> binary plist conversion."""
        import json
        obj = {'key': 'value', 'num': 123}
        json_data = json.dumps(obj).encode()
        unit = self.load()
        plist_data = json_data | -unit | bytes
        parsed = plistlib.loads(plist_data)
        self.assertEqual(parsed['key'], 'value')
        self.assertEqual(parsed['num'], 123)

    def test_list_values(self):
        obj = {'items': ['a', 'b', 'c']}
        data = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        unit = self.load()
        result = data | unit | bytes
        self.assertIn(b'"a"', result)
        self.assertIn(b'"b"', result)
        self.assertIn(b'"c"', result)
