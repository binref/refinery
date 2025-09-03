import io

from . import TestMetaBase
from refinery.lib.loader import load_detached as L


class TestSorting(TestMetaBase):

    def test_with_scoping(self):
        with io.BytesIO() as result:
            L('emit F2 F3 S4 S6 S5 F1 S2 S3 S1')[
                L('scope 2:5 6:') | L('sorted') | L('sep -')] | result
            self.assertEqual(result.getvalue(), B'F2-F3-S6-S5-S4-F1-S3-S2-S1')

    def test_trailing_chunks(self):
        pipeline = L('rep') [ L('scope 0') | L('chop 1') [ L('sorted -a') ]]  # noqa
        self.assertEqual(pipeline(B'8492756031'), B'01234567898492756031')

    def test_sorting_by_size(self):
        results = list(L('emit A AA B ABA C ABABABB CD EFEW A BVB')[L('sorted -a size')])
        self.assertEqual(results, [
            B'A', B'A', B'B', B'C', B'AA', B'CD', B'ABA', B'BVB', B'EFEW', B'ABABABB'])
