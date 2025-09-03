from refinery.lib.suffixtree import SuffixTree
from .. import TestBase


class TestSuffixTree(TestBase):

    def test_string_is_reconstructed_from_suffixes(self):
        data = B'The binary refinery refines binaries and includes fine rhymery.'
        tree = SuffixTree(data)
        self.assertEqual(
            [s.suffix for s in tree.leaves],
            [data[k:] for k in range(len(data))]
        )
