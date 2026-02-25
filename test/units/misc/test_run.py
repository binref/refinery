from .. import TestUnitBase


class TestRun(TestUnitBase):

    def test_run_simple_command(self):
        pl = self.load_pipeline('emit HGT DGBA [| chop 1 [| sep ]| run sort ]')
        self.assertListEqual((pl | str).split(), list('GHTABDG'))

    def test_stderr_output(self):
        command = (
            'python -c "import sys;'
            'sys.stderr.write(sys.stdin.read()[:3])";'
            'sys.stdout.write(__name__);')
        pl = self.load_pipeline(F'emit binary refinery [| run {command} ]')
        self.assertEqual(pl | str, 'bin__main__ref__main__')

    def test_timeout_output(self):
        command = 'python -c "import sys, time; time.sleep(2); sys.stdout.write(sys.stdin.read())"'
        pl = self.load_pipeline(F'emit Binary Refinery [| run -t=8 {command} ]')
        self.assertEqual(pl | str, 'BinaryRefinery')
        pl = self.load_pipeline(F'emit Binary Refinery [| run -t=1 {command} ]')
        with self.assertRaises(Exception):
            _ = 0 | pl | 0
