from .. import TestUnitBase


class TestPPJscript(TestUnitBase):

    def test_simple_formatting(self):
        self.assertEqual('a=9;b=10;c=1;' | self.load() | str, 'a = 9;\nb = 10;\nc = 1;')

    def test_comment_preservation(self):
        result = '/* header */\nvar x = 1;\n// line\nvar y = 2;' | self.load() | str
        self.assertIn('/* header */', result)
        self.assertIn('// line', result)
        self.assertIn('var x = 1;', result)
        self.assertIn('var y = 2;', result)

    def test_comment_stripping(self):
        result = '/* header */\nvar x = 1;\n// line\nvar y = 2;' | self.load(strip_comments=True) | str
        self.assertNotIn('/* header */', result)
        self.assertNotIn('// line', result)
        self.assertIn('var x = 1;', result)
        self.assertIn('var y = 2;', result)

    def test_unescape_strings(self):
        result = 'var x = "\\x41\\x42\\x43";' | self.load() | str
        self.assertIn('"ABC"', result)

    def test_keep_escapes(self):
        result = 'var x = "\\x41\\x42\\x43";' | self.load(keep_escapes=True) | str
        self.assertIn('\\x41', result)

    def test_indent_size(self):
        result = 'function f(){return 1;}' | self.load(indent=2) | str
        self.assertIn('  return', result)
        self.assertNotIn('    return', result)

    def test_function_formatting(self):
        result = 'function foo(a,b){return a+b;}' | self.load() | str
        self.assertIn('function foo(a, b)', result)
        self.assertIn('return a + b;', result)
