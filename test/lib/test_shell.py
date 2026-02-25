from .. import TestBase


class TestShellModule(TestBase):

    def test_missing_import(self):
        with self.assertRaises(AttributeError):
            from refinery import shell
            shell.bogus_unit_that_does_not_exist
        with self.assertRaises(ImportError):
            from refinery.shell import bogus_unit_that_does_not_exist

    def test_docstring_example(self):
        from refinery.shell import emit, pop, xor, pack
        self.assertEqual('575', emit('ABC', 'DEF') [ pop('t') | xor('var:t') | pack('-R') ]| str)
