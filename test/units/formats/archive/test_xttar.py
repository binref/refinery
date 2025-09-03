from ... import TestUnitBase


class TestTarFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = bytes.fromhex(
            '425A6839314159265359B51B05CA000156FF84C38040006001FF80100014C873719E30008005083000F803003269A0C86086'
            '988D183003269A0C86086988D181148226994D3D27A9A0C4D0369A4F535FA4FCD30FD8DCE45896BBBC64032DA0A3663C32E1'
            '4126932511BE7594C6C132485024C410924C5249A07CF68202ADD883EB70AF23E3A74C15A89CE49212E3663C695486A900CE'
            'F99056C3CA992511DC4C4D86DA11384B6D6DA272A5168D825D625E9DDBE4275132C93892EEF33ECA89521282752B41341331'
            '3A9D8C1334D05B84CEB6ACC884BD2F7B89E027BE5AC6BB04B1F31354CC30DEA07F8BB9229C28485A8D82E500'
        )

        self.assertSetEqual({
            'test/foo',
            'test/sub/bar',
            'test/sub/baz'
        }, set(self.load(list=True)(data).decode('ascii').split('\n')))

        self.assertSetEqual(
            {B'Refinery!', B'Binary Refinery!'},
            {bytes(c) for c in self.load('*sub/*').process(data)}
        )
