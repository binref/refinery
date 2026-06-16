from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.cff import JsControlFlowUnflattening
from refinery.lib.scripts.js.deobfuscation.cff.sequential import _strip_trailing_flow
from refinery.lib.scripts.js.model import (
    JsBreakStatement,
    JsContinueStatement,
    JsExpressionStatement,
    JsIdentifier,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestControlFlowUnflattening(TestJsDeobfuscator):

    def test_simple_sequence(self):
        source = (
            "var _order = '1|0|2'['split']('|');"
            "var _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "    case '2': var c = 3; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var a = 1;
            var b = 2;
            var c = 3;
            """
        ))

    def test_array_literal_order(self):
        source = (
            "var _order = ['1', '0', '2'];"
            "var _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "    case '2': var c = 3; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var a = 1;
            var b = 2;
            var c = 3;
            """
        ))

    def test_combined_order_counter_declaration(self):
        source = (
            "var _order = ['1', '0', '2'], _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "    case '2': var c = 3; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var a = 1;
            var b = 2;
            var c = 3;
            """
        ))

    def test_combined_declaration_preserves_sibling(self):
        source = (
            "var keep = 9, _order = ['1', '0'], _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var keep = 9;
            var a = 1;
            var b = 2;
            """
        ))

    def test_referenced_order_var_blocks_unflattening(self):
        source = (
            "var _order = ['1', '0'], n = _order.length, _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "  }"
            "  break;"
            "}"
        )
        untouched = JsSynthesizer().convert(JsParser(source).parse())
        result = self._run_transformer(source, JsControlFlowUnflattening)
        self.assertEqual(result, untouched)

    def test_referenced_counter_var_in_case_body_blocks_unflattening(self):
        source = (
            "var _order = ['1', '0'], _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = _idx; continue;"
            "  }"
            "  break;"
            "}"
        )
        untouched = JsSynthesizer().convert(JsParser(source).parse())
        result = self._run_transformer(source, JsControlFlowUnflattening)
        self.assertEqual(result, untouched)

    def test_referenced_counter_var_after_loop_preserves_declaration(self):
        source = (
            "var _order = ['1', '0'], _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "  }"
            "  break;"
            "}"
            "sink(_order, _idx);"
        )
        result = self._deobfuscate_iterative(source)
        self.assertIn('var _order', result)
        self.assertIn('sink(_order, _idx)', result)

    def test_generated_simple_greet(self):
        result = self._deobfuscate(
            r"function greet(_0x605f93){var _0x4f2511={'RnggP':'0|2|4|1|3','RhaFq':'Hello','PcFhw':function(_0x1e0"
            r"1f8,_0x18ebb9){return _0x1e01f8+_0x18ebb9;}};var _0x33ede6=_0x4f2511['RnggP']['split']('|');var _0x4"
            r"9a67e=0x0;while(!![]){switch(_0x33ede6[_0x49a67e++]){case'0':var _0x19c4d7=_0x4f2511['RhaFq'];contin"
            r"ue;case'1':var _0x1f1f34='!';continue;case'2':var _0x5960d3=',\x20';continue;case'3':return _0x4f251"
            r"1['PcFhw'](_0x5957de,_0x1f1f34);case'4':var _0x5957de=_0x4f2511['PcFhw'](_0x4f2511['PcFhw'](_0x19c4d"
            r"7,_0x5960d3),_0x605f93);continue;}break;}}"
        )
        self.assertEqual(result, inspect.cleandoc(
            """
            function greet(_0x605f93) {
              return 'Hello, ' + _0x605f93 + '!';
            }
            """
        ))

    def test_preserved_inner_control_flow(self):
        source = (
            "var _o = '1|0'['split']('|');"
            "var _i = 0;"
            "while (true) {"
            "  switch (_o[_i++]) {"
            "    case '0': if (x) { a(); } else { b(); } continue;"
            "    case '1': var v = 1; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var v = 1;
            if (x) {
              a();
            } else {
              b();
            }
            """
        ))

    def test_no_match_leaves_unchanged(self):
        source = (
            "var x = 0;"
            "while (x < 10) {"
            "  switch (x) {"
            "    case 0: x = 1; break;"
            "    case 1: x = 2; break;"
            "  }"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var x = 0;
            while (x < 10) {
              switch (x) {
                case 0:
                  x = 1;
                  break;
                case 1:
                  x = 2;
                  break;
              }
            }
            """
        ))

    def test_non_split_method_unchanged(self):
        source = (
            "var _order = '1|0|2'['slice']('|');"
            "var _idx = 0;"
            "while (true) {"
            "  switch (_order[_idx++]) {"
            "    case '0': var b = 2; continue;"
            "    case '1': var a = 1; continue;"
            "    case '2': var c = 3; continue;"
            "  }"
            "  break;"
            "}"
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var _order = '1|0|2';
            var _idx = 0;
            while (true) {
              switch (_order[_idx++]) {
                case '0':
                  var b = 2;
                  continue;
                case '1':
                  var a = 1;
                  continue;
                case '2':
                  var c = 3;
                  continue;
              }
              break;
            }
            """
        ))


class TestRegressionBugs(TestJsDeobfuscator):

    def test_cff_preserves_labeled_break(self):
        dummy = JsExpressionStatement()
        unlabeled = JsBreakStatement(label=None)
        labeled = JsBreakStatement(label=JsIdentifier(name='outer'))
        labeled_cont = JsContinueStatement(label=JsIdentifier(name='outer'))
        self.assertEqual(len(_strip_trailing_flow([dummy, unlabeled])), 1)
        self.assertEqual(len(_strip_trailing_flow([dummy, labeled])), 2,
            'labeled break must not be stripped')
        self.assertEqual(len(_strip_trailing_flow([dummy, labeled_cont])), 2,
            'labeled continue must not be stripped')


class TestCFFArgParamDeclarations(TestJsDeobfuscator):

    def test_undeclared_assignment_not_removed_when_read_in_outer_scope(self):
        source = inspect.cleandoc(
            """
            function modify() {
                x = 99;
            }
            var x = 1;
            modify();
            console.log(x);
            """
        )
        result = self._deobfuscate_iterative(source)
        self.assertIn('x = 99', result)
