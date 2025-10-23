from ... import TestUnitBase


class TestCodebook(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('1b2926eed1b62a8120186cec15a881a2ffc857aa6671c963fe302479e7b29d02')
        test = data | self.load_pipeline(
            R'push [| csd strarray | pop w | csd string | rex client-([a-z]+) | codebook v:w | chop 2 | rev | base range:64 ]'
        ) | bytes
        self.assertEqual(test, b'https'b':/'b'/mfaesmilenutt'b'.org')
