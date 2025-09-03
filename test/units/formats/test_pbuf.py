import json

from .. import TestUnitBase


class TestProtoBufDecoder(TestUnitBase):

    def test_mixed_bytes_and_repeated_integers(self):
        data = bytes.fromhex('0a04746573741202ff0f180222020204')
        out = data | self.load() | json.loads
        self.assertEqual(out, {
            "1": "test",
            "2": "\xFF\x0F",
            "3": 2,
            "4": "\x02\x04",
        })

    def test_repeated_integer(self):
        data = bytes.fromhex('220568656c6c6f3206038e029ea705')
        out = data | self.load(try_repeated=True) | json.loads
        self.assertEqual(out, {
            "4": "hello",
            "6": [3, 270, 86942]
        })

    def test_recover_map(self):
        data = bytes.fromhex(
            '0a1e0a0662696e617279121410111800220e546865207375627374726174652e0a1f0a087265'
            '66696e6572791213101218c73e220c546865206d616368696e652e')
        out = data | self.load() | json.loads
        self.assertEqual(out, {
            "1": {
                "binary": {
                    "2": 17,
                    "3": 0,
                    "4": "The substrate."
                },
                "refinery": {
                    "2": 18,
                    "3": 8007,
                    "4": "The machine."
                }
            }
        })

    def test_fake_map(self):
        data = bytes.fromhex(
            '0a46cab8021e2a0662696e617279321410111800220e546865207375627374726174652ed2b8'
            '02202a08726566696e657279321410c73e1a084d616368696e657322054d696e6473')
        out = data | self.load() | json.loads
        self.assertEqual(out, {
            "1": {
                "5001": {
                    "5": "binary",
                    "6": {
                        "2": 17,
                        "3": 0,
                        "4": "The substrate."
                    }
                },
                "5002": {
                    "5": "refinery",
                    "6": {
                        "2": 8007,
                        "3": "Machines",
                        "4": "Minds"
                    }
                }
            }
        })
