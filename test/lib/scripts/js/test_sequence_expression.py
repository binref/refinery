"""
Each table maps a source to the text the printer writes for its tree once the brackets the source
was written with are taken away: the brackets in the source say which tree is meant, and the
brackets in the output are the ones the printer has to supply.
"""
from __future__ import annotations

import inspect

from test import TestBase
from test.lib.scripts.js.test_fidelity import _strip_parentheses

from refinery.lib.scripts import Node, canonical
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

SEQUENCE_IN_A_SEQUENCE: dict[str, str] = {
    '(a, b, c);': 'a, b, c;',
    '((a, b), c);': '(a, b), c;',
    '(a, (b, c));': 'a, (b, c);',
    '(a, (b, c), d);': 'a, (b, c), d;',
    '((a, b), (c, d));': '(a, b), (c, d);',
    '(((a, b), c), d);': '((a, b), c), d;',
    '(a, (b, (c, d)));': 'a, (b, (c, d));',
    '(((a, b), c), ((d, e), f));': '((a, b), c), ((d, e), f);',
}

#: The positions whose grammar reads a whole `Expression`, which a comma list is.
WHERE_A_COMMA_LIST_STANDS_BARE: dict[str, str] = {
    'x[((a, b), c)];': 'x[(a, b), c];',
    'x?.[((a, b), c)];': 'x?.[(a, b), c];',
    '`${((a, b), c)}`;': '`${(a, b), c}`;',
    'throw ((a, b), c);': 'throw (a, b), c;',
    'if (((a, b), c)) {}': 'if ((a, b), c) {}',
    'while (((a, b), c)) {}': 'while ((a, b), c) {}',
    'do {} while (((a, b), c));': 'do {} while ((a, b), c);',
    'switch (((a, b), c)) {}': 'switch ((a, b), c) {}',
    'with (((a, b), c)) {}': 'with ((a, b), c) {}',
    'for (x in ((a, b), c)) {}': 'for (x in (a, b), c) {}',
    'for (((a, b), c); ((d, e), f); ((g, h), i)) {}':
        'for ((a, b), c; (d, e), f; (g, h), i) {}',
    'function q() { return ((a, b), c); }': inspect.cleandoc("""
        function q() {
          return (a, b), c;
        }
    """),
    'switch (q) { case ((a, b), c): d; }': inspect.cleandoc("""
        switch (q) {
          case (a, b), c:
            d;
        }
    """),
}

#: The positions whose grammar reads a single `AssignmentExpression`, where a bare comma would end
#: the operand.
WHERE_A_COMMA_LIST_NEEDS_A_BRACKET: dict[str, str] = {
    'f(((a, b), c));': 'f(((a, b), c));',
    'f(x, ((a, b), c));': 'f(x, ((a, b), c));',
    'new C(((a, b), c));': 'new C(((a, b), c));',
    '[((a, b), c)];': '[((a, b), c)];',
    'f(...((a, b), c));': 'f(...((a, b), c));',
    '[...((a, b), c)];': '[...((a, b), c)];',
    '({...((a, b), c)});': '({ ...((a, b), c) });',
    '({k: ((a, b), c)});': '({ k: ((a, b), c) });',
    '({[(a, b)]: 1});': '({ [(a, b)]: 1 });',
    '({[((a, b), c)]: 1});': '({ [((a, b), c)]: 1 });',
    '({get [(a, b)]() {}});': '({ get [(a, b)]() {} });',
    'var x = ((a, b), c);': 'var x = ((a, b), c);',
    'x = ((a, b), c);': 'x = ((a, b), c);',
    'x += ((a, b), c);': 'x += ((a, b), c);',
    'q ? ((a, b), c) : d;': 'q ? ((a, b), c) : d;',
    'q ? d : ((a, b), c);': 'q ? d : ((a, b), c);',
    'y => ((a, b), c);': 'y => ((a, b), c);',
    'function f(x = ((a, b), c)) {}': 'function f(x = ((a, b), c)) {}',
    'var [x = ((a, b), c)] = z;': 'var [x = ((a, b), c)] = z;',
    'for (x of ((a, b), c)) {}': 'for (x of ((a, b), c)) {}',
    'void ((a, b), c);': 'void ((a, b), c);',
    'typeof ((a, b), c);': 'typeof ((a, b), c);',
    '((a, b), c) + d;': '((a, b), c) + d;',
    'd + ((a, b), c);': 'd + ((a, b), c);',
    '((a, b), c).d;': '((a, b), c).d;',
    '((a, b), c)();': '((a, b), c)();',
    'export const z = ((a, b), c);': 'export const z = ((a, b), c);',
    'export default (a, b);': 'export default (a, b);',
    'export default ((a, b), c);': 'export default ((a, b), c);',
    'function* g() { yield ((a, b), c); }': inspect.cleandoc("""
        function* g() {
          yield ((a, b), c);
        }
    """),
    'async function h() { await ((a, b), c); }': inspect.cleandoc("""
        async function h() {
          await ((a, b), c);
        }
    """),
    'class K { x = ((a, b), c); }': inspect.cleandoc("""
        class K {
          x = ((a, b), c);
        }
    """),
    'class K { [(a, b)]() {} }': inspect.cleandoc("""
        class K {
          [(a, b)]() {}
        }
    """),
    'class K { [(a, b)] = 1; }': inspect.cleandoc("""
        class K {
          [(a, b)] = 1;
        }
    """),
}


class TestJsSequenceExpressionPrinting(TestBase):

    @staticmethod
    def _unbracketed(source: str) -> Node:
        tree = JsParser(source).parse()
        while _strip_parentheses(tree):
            pass
        return tree

    def _print(self, source: str) -> str:
        return JsSynthesizer().convert(self._unbracketed(source))

    def _printed(self, table: dict[str, str]) -> dict[str, str]:
        return {source: self._print(source) for source in table}

    def test_a_sequence_inside_a_sequence_is_printed_with_brackets(self):
        self.assertEqual(self._printed(SEQUENCE_IN_A_SEQUENCE), SEQUENCE_IN_A_SEQUENCE)

    def test_a_sequence_is_printed_bare_where_the_slot_reads_a_whole_expression(self):
        self.assertEqual(
            self._printed(WHERE_A_COMMA_LIST_STANDS_BARE), WHERE_A_COMMA_LIST_STANDS_BARE
        )

    def test_a_sequence_is_printed_bracketed_where_the_slot_reads_one_operand(self):
        self.assertEqual(
            self._printed(WHERE_A_COMMA_LIST_NEEDS_A_BRACKET), WHERE_A_COMMA_LIST_NEEDS_A_BRACKET
        )

    def test_the_printed_text_reads_back_as_the_tree_that_was_printed(self):
        for table in (
            SEQUENCE_IN_A_SEQUENCE,
            WHERE_A_COMMA_LIST_STANDS_BARE,
            WHERE_A_COMMA_LIST_NEEDS_A_BRACKET,
        ):
            for source in table:
                with self.subTest(source=source):
                    self.assertEqual(
                        canonical(self._unbracketed(self._print(source))),
                        canonical(self._unbracketed(source)),
                    )
