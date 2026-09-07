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

    def test_comment_stripping_keeps_a_comment_inside_text_the_parser_could_not_read(self):
        result = '@@@ /* c */ var x = 1;' | self.load(strip_comments=True) | str
        self.assertEqual(result, '@@@ /* c */ var x = 1;')

    def test_comment_stripping_strips_the_hash_bang_line_and_the_comment_behind_the_last_statement(self):
        result = '#!/usr/bin/env node\nvar x = 1; /* tail */' | self.load(strip_comments=True) | str
        self.assertEqual(result, 'var x = 1;')

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

    def test_escaped_use_strict_directive_is_not_turned_into_a_directive(self):
        """
        The first statement denotes the three words of the Use Strict Directive but writes the space
        as a hex escape, so it is not the directive and the program is sloppy. Unescaping it to a
        plain 'use strict' would put a directive where none was written and silently make the code
        that follows strict, a change of meaning, so the escaped spelling has to stay. The ordinary
        escaped string on the next line still unescapes, so this also pins that the default unescape
        is otherwise unchanged.
        """
        program = (
            "'use\\x20strict';\n"
            "var marker = \"\\x41\\x42\";"
        )
        result = program | self.load() | str
        self.assertNotIn("'use strict'", result)
        self.assertNotIn('"use strict"', result)
        self.assertIn('"AB"', result)
