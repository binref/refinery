from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestMinMax(TestMetaBase):

    def test_max_01(self):
        pl = L('emit the Binary Refinery refines the finest binaries [| max size ]')
        self.assertEqual(pl(), B'Refinery')

    def test_min_01(self):
        pl = L('emit the Binary Refinery refines the finest binaries [| min size ]')
        self.assertEqual(pl(), B'the')

    def test_max_works_with_pop(self):
        pl = L('emit Y:FOO:DN:GOOP [| push | resplit : | max size | pop ll | ccp var:ll ]')
        self.assertEqual(pl(), b'GOOPY:FOO:DN:GOOP')

    def test_min_works_with_pop(self):
        pl = L('emit YY:FOO:A:GOOP [| push | resplit : | min size | pop ll | ccp var:ll ]')
        self.assertEqual(pl(), b'AYY:FOO:A:GOOP')

    def test_max_single_chunk(self):
        pl = L('emit HELLO [| max size ]')
        self.assertEqual(pl(), B'HELLO')

    def test_min_single_chunk(self):
        pl = L('emit HELLO [| min size ]')
        self.assertEqual(pl(), B'HELLO')

    def test_max_equal_sizes(self):
        pl = L('emit ABC DEF GHI [| max size ]')
        result = pl()
        self.assertEqual(len(result), 3)

    def test_min_equal_sizes(self):
        pl = L('emit ABC DEF GHI [| min size ]')
        result = pl()
        self.assertEqual(len(result), 3)

    def test_max_by_entropy(self):
        pl = L('emit AAAA range:16 [| max entropy ]')
        result = pl()
        self.assertEqual(len(result), 16)

    def test_min_by_entropy(self):
        pl = L('emit AAAA range:16 [| min entropy ]')
        result = pl()
        self.assertEqual(result, b'AAAA')

    def test_max_by_content(self):
        pl = L('emit AAA CCC BBB [| max ]')
        self.assertEqual(pl(), b'CCC')

    def test_min_by_content(self):
        pl = L('emit AAA CCC BBB [| min ]')
        self.assertEqual(pl(), b'AAA')

    def test_max_by_content_binary(self):
        pl = L('emit h:FF h:00 h:7F [| max ]')
        self.assertEqual(pl(), b'\xFF')

    def test_min_by_content_binary(self):
        pl = L('emit h:FF h:00 h:7F [| min ]')
        self.assertEqual(pl(), b'\x00')

    def test_max_with_custom_key_expression(self):
        pl = L('emit HELLO WORLD HI [| put n size | max n ]')
        self.assertEqual(pl(), b'HELLO')

    def test_min_with_custom_key_expression(self):
        pl = L('emit HELLO WORLD HI [| put n size | min n ]')
        self.assertEqual(pl(), b'HI')

    def test_max_two_chunks(self):
        pl = L('emit SHORT LONGER [| max size ]')
        self.assertEqual(pl(), b'LONGER')

    def test_min_two_chunks(self):
        pl = L('emit SHORT LONGER [| min size ]')
        self.assertEqual(pl(), b'SHORT')

    def test_max_preserves_content(self):
        pl = L('emit ABCDEF GH [| max size ]')
        self.assertEqual(pl(), b'ABCDEF')

    def test_min_preserves_content(self):
        pl = L('emit ABCDEF GH [| min size ]')
        self.assertEqual(pl(), b'GH')

    def test_max_by_content_lexicographic(self):
        pl = L('emit apple banana cherry [| max ]')
        self.assertEqual(pl(), b'cherry')

    def test_min_by_content_lexicographic(self):
        pl = L('emit apple banana cherry [| min ]')
        self.assertEqual(pl(), b'apple')
