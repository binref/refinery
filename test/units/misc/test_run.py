from .. import TestUnitBase


class TestRun(TestUnitBase):

    def test_run_simple_command(self):
        pl = self.load_pipeline('emit HGT DGBA [| chop 1 [| sep ]| run sort ]')
        self.assertListEqual((pl | str).split(), list('GHTABDG'))
