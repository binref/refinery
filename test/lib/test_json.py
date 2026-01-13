from refinery.lib import json

from datetime import datetime, timezone, date
from uuid import uuid4
from math import cos, exp
from enum import Enum

from .. import TestBase


class E(int, Enum):
    VALUE = 1


class TestJSONLib(TestBase):

    def test_orjson_is_available(self):
        self.assertIsNot(json.dumps, json.py_json_dumps)

    def test_orjson_vs_pyjson_01(self):
        now = datetime.now()
        test_data = {
            b'key1': [
                {
                    'a': datetime.now(),
                    'b': uuid4(),
                    'c': cos(12),
                    'e': exp(1),
                },
                {
                    'a': datetime.now(timezone.utc),
                    'b': uuid4(),
                    'c': 1.3,
                    'e': None,
                }
            ],
            'key2': {
                'foo': self.generate_random_buffer(10),
                'bar': bytearray(B'Hello World!'),
                'baz': memoryview(B'The binary refinery refines the finest binaries.'),
                'wut': True,
            },
            True: date.today(),
            False: now.time(),
            uuid4(): E.VALUE
        }

        py_dumps = json.py_json_dumps
        or_dumps = json.dumps

        for converter in (
            json.bytes_as_array,
            json.bytes_as_string,
        ):
            for pretty in (True, False):
                py_dumped = py_dumps(test_data, pretty=pretty, tojson=converter)
                or_dumped = or_dumps(test_data, pretty=pretty, tojson=converter)
                self.assertEqual(py_dumped, or_dumped)

    def test_orjson_vs_pyjson_02(self):
        test_data = {
            uuid4(): 569493374326423423723463737777473821332347344463,
            b'key1': [
                {
                    'a': datetime.now(),
                    'b': uuid4(),
                    'c': cos(12),
                    'e': exp(1),
                },
                {
                    'a': datetime.now(timezone.utc),
                    'b': uuid4(),
                    'c': 1.3,
                    'e': None,
                }
            ],
        }

        py_dumps = json.py_json_dumps
        or_dumps = json.dumps

        for pretty in (True, False):
            py_dumped = py_dumps(test_data, pretty=pretty, tojson=json.standard_conversions)
            or_dumped = or_dumps(test_data, pretty=pretty)
            self.assertEqual(py_dumped, or_dumped)
