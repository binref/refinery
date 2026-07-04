from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestScan(TestUnitBase):

    def test_running_sum(self):
        pl = L('emit range::5 | chop 1 [| put n le:c: | scan m=m+n ]')
        self.assertEqual([chunk['m'] for chunk in pl], [0, 1, 3, 6, 10])

    def test_running_count_alongside_sum(self):
        pl = L('emit range::5 | chop 1 [| put n le:c: | scan s=s+n p=p+1 ]')
        chunks = list(pl)
        self.assertEqual([chunk['s'] for chunk in chunks], [0, 1, 3, 6, 10])
        self.assertEqual([chunk['p'] for chunk in chunks], [1, 2, 3, 4, 5])

    def test_explicit_initial_value(self):
        pl = L('emit range::5 | chop 1 [| put m 100 | put n le:c: | scan m=m+n ]')
        self.assertEqual([chunk['m'] for chunk in pl], [100, 101, 103, 106, 110])

    def test_at_least_one_register_required(self):
        with self.assertRaises(ValueError):
            self.load()
