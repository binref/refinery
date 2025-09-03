from .. import TestUnitBase


class TestRepl(TestUnitBase):

    def test_limit_with_annihilation(self):
        unit = self.load('-n', 4, 'e')
        self.assertEqual(unit(12 * B'e'), 8 * B'e')

    def test_limit_with_replacement(self):
        unit = self.load('-n', 4, 'e', 'o')
        self.assertEqual(unit(
            B'The keen explorer entered the cave'),
            B'Tho koon oxplorer entered the cave')

    def test_without_limit(self):
        unit = self.load('e', 'o')
        self.assertEqual(unit(
            B'The keen explorer entered the cave'),
            B'Tho koon oxploror ontorod tho cavo')

    def test_with_longer_strings(self):
        unit = self.load('foo', 'oof')
        self.assertEqual(unit(
            B'my food tastes like foo.'),
            B'my oofd tastes like oof.')
