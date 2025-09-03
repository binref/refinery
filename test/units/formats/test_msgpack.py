import json
import inspect

from .. import TestUnitBase


class TestMessagePack(TestUnitBase):

    def test_reversible_property(self):
        @inspect.getdoc
        class data:
            """
            {
                "jsonrpc": "2.0",
                "method": "refine",
                "id": 1254,
                "params": [
                    "Binary",
                    78,
                    0,
                    false,
                    true,
                    2,
                    false,
                    "FOOBAR"
                ]
            }
            """
        msgpack = self.load()
        data = data.encode(msgpack.codec)
        self.assertEqual(
            json.loads(data),
            json.loads(str(data | -msgpack | msgpack))
        )
