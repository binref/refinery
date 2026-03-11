import json

from .. import TestUnitBase


class TestPHPDeserializer(TestUnitBase):

    def test_reversible_property(self):
        data = {"42": True, "A to Z": {"0": 1, "1": 2, "2": 3}}
        ds = self.load()
        self.assertEqual(json.dumps(data) | -ds | ds | json.loads, data)

    def test_wikipedia(self):
        data = B'O:8:"stdClass":2:{s:4:"John";d:3.14;s:4:"Jane";d:2.718;}'
        test = data | self.load() | json.loads
        self.assertEqual(test, {
            "John": 3.14,
            "Jane": 2.718
        })

    def test_null(self):
        result = B'N;' | self.load() | json.loads
        self.assertIsNone(result)

    def test_boolean_true(self):
        result = B'b:1;' | self.load() | json.loads
        self.assertTrue(result)

    def test_boolean_false(self):
        result = B'b:0;' | self.load() | json.loads
        self.assertFalse(result)

    def test_integer(self):
        result = B'i:42;' | self.load() | json.loads
        self.assertEqual(result, 42)

    def test_negative_integer(self):
        result = B'i:-7;' | self.load() | json.loads
        self.assertEqual(result, -7)

    def test_float(self):
        result = B'i:0;' | self.load() | json.loads
        self.assertEqual(result, 0)

    def test_float_value(self):
        result = B'd:3.14;' | self.load() | json.loads
        self.assertAlmostEqual(result, 3.14, places=10)

    def test_string(self):
        result = B's:5:"hello";' | self.load() | json.loads
        self.assertEqual(result, 'hello')

    def test_empty_string(self):
        result = B's:0:"";' | self.load() | json.loads
        self.assertEqual(result, '')

    def test_simple_array(self):
        data = B'a:2:{s:3:"foo";i:1;s:3:"bar";i:2;}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'foo': 1, 'bar': 2})

    def test_numeric_array(self):
        data = B'a:3:{i:0;s:1:"a";i:1;s:1:"b";i:2;s:1:"c";}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'0': 'a', '1': 'b', '2': 'c'})

    def test_nested_array(self):
        data = B'a:1:{s:5:"outer";a:1:{s:5:"inner";i:99;}}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'outer': {'inner': 99}})

    def test_empty_array(self):
        data = B'a:0:{}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {})

    def test_object_simple(self):
        data = B'O:7:"WP_User":1:{s:8:"username";s:5:"admin";}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'username': 'admin'})

    def test_object_protected_member(self):
        data = B'O:4:"Test":2:{s:7:"\x00*\x00prot";i:1;s:3:"pub";i:2;}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'prot': 1, 'pub': 2})

    def test_object_private_member(self):
        data = B'O:4:"Test":2:{s:10:"\x00Test\x00priv";i:1;s:3:"pub";i:2;}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'priv': 1, 'pub': 2})

    def test_mixed_types(self):
        data = (
            B'a:5:{s:1:"n";N;s:1:"b";b:1;s:1:"i";i:42;'
            B's:1:"d";d:1.5;s:1:"s";s:3:"abc";}'
        )
        result = data | self.load() | json.loads
        self.assertEqual(result, {
            'n': None,
            'b': True,
            'i': 42,
            'd': 1.5,
            's': 'abc',
        })

    def test_reverse_null(self):
        result = B'null' | -self.load()
        self.assertEqual(bytes(result), B'N;')

    def test_reverse_bool(self):
        self.assertEqual(bytes(B'true' | -self.load()), B'b:1;')
        self.assertEqual(bytes(B'false' | -self.load()), B'b:0;')

    def test_reverse_integer(self):
        result = B'42' | -self.load()
        self.assertEqual(bytes(result), B'i:42;')

    def test_reverse_float(self):
        result = B'1.5' | -self.load()
        self.assertEqual(bytes(result), B'd:1.5;')

    def test_reverse_string(self):
        result = B'"hello"' | -self.load()
        self.assertEqual(bytes(result), B's:5:"hello";')

    def test_reverse_dict(self):
        result = B'{"a":1}' | -self.load()
        self.assertEqual(bytes(result), B'a:1:{s:1:"a";i:1;}')

    def test_reverse_list(self):
        result = B'[1,2,3]' | -self.load()
        self.assertEqual(bytes(result), B'a:3:{i:0;i:1;i:1;i:2;i:2;i:3;}')

    def test_roundtrip_dict(self):
        data = B'a:2:{s:3:"foo";i:1;s:3:"bar";i:2;}'
        ds = self.load()
        j = data | ds | bytes
        rt = j | -ds | ds | bytes
        self.assertEqual(j, rt)

    def test_roundtrip_nested(self):
        original = {'key': 'value', 'nested': {'a': 1, 'b': 2}}
        ds = self.load()
        rt = json.dumps(original) | -ds | ds | json.loads
        self.assertEqual(rt, original)

    def test_unicode_string(self):
        data = 's:6:"hëllo";'.encode('utf-8')
        result = data | self.load() | json.loads
        self.assertEqual(result, 'hëllo')

    def test_uppercase_object_opcode(self):
        data = B'O:3:"Foo":1:{s:1:"x";i:1;}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'x': 1})

    def test_lowercase_object_opcode(self):
        data = B'o:3:"Foo":1:{s:1:"x";i:1;}'
        result = data | self.load() | json.loads
        self.assertEqual(result, {'x': 1})

    def test_loads_invalid_opcode(self):
        from refinery.units.formats.deserialize_php import dsphp
        with self.assertRaises(ValueError):
            dsphp._loads(B'X;')

    def test_loads_unexpected_end_of_stream(self):
        from refinery.units.formats.deserialize_php import dsphp
        with self.assertRaises(ValueError):
            dsphp._loads(B'i:42')

    def test_loads_expect_mismatch(self):
        from refinery.units.formats.deserialize_php import dsphp
        with self.assertRaises(ValueError):
            dsphp._loads(B'N?')

    def test_dumps_bytes_value(self):
        from refinery.units.formats.deserialize_php import dsphp
        result = dsphp._dumps(b'raw')
        self.assertEqual(result, B's:3:"raw";')

    def test_dumps_bytes_key(self):
        from refinery.units.formats.deserialize_php import dsphp
        result = dsphp._dumps({b'key': 1})
        self.assertEqual(result, B'a:1:{s:3:"key";i:1;}')

    def test_dumps_none_key(self):
        from refinery.units.formats.deserialize_php import dsphp
        result = dsphp._dumps({None: 1})
        self.assertEqual(result, B'a:1:{s:0:"";i:1;}')

    def test_dumps_phpobject(self):
        from refinery.units.formats.deserialize_php import dsphp, _phpobject
        obj = _phpobject('Foo', {'bar': 42})
        result = dsphp._dumps(obj)
        self.assertEqual(result, B'O:3:"Foo":1:{s:3:"bar";i:42;}')

    def test_dumps_unsupported_type(self):
        from refinery.units.formats.deserialize_php import dsphp
        with self.assertRaises(TypeError):
            dsphp._dumps(object())

    def test_dumps_unsupported_key_type(self):
        from refinery.units.formats.deserialize_php import dsphp
        with self.assertRaises(TypeError):
            dsphp._dumps({(1, 2): 'value'})
