from refinery.lib.powershell import NotWindows, get_parent_processes

from .. import TestBase


class TestPowerShellDetection(TestBase):

    def test_process_trace(self):
        try:
            processes = list(get_parent_processes())
        except NotWindows:
            pass
        else:
            self.assertTrue(any('python' in p for p in processes))
