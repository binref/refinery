from __future__ import annotations

import base64
import inspect
import lzma

from test import TestBase

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs
from refinery.lib.scripts.js.deobfuscation.b91strings import _decode_base91
from refinery.lib.scripts.js.deobfuscation.helpers import has_remaining_references, make_string_literal
from refinery.lib.scripts.js.deobfuscation.cff import JsGeneratorCFFUnflattening
from refinery.lib.scripts.js.deobfuscation.cff.sequential import _strip_trailing_flow
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking
from refinery.lib.scripts.js.deobfuscation.unshuffle import JsArrayUnshuffle
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.deobfuscation.scramble import JsScrambleStringDecoder
from refinery.lib.scripts.js.deobfuscation.stringarray import JsStringArrayResolver
from refinery.lib.scripts.js.model import (
    JsBreakStatement,
    JsContinueStatement,
    JsExpressionStatement,
    JsIdentifier,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestJsDeobfuscator(TestBase):

    def _deobfuscate(self, source: str) -> str:
        ast = JsParser(source).parse()
        deobfuscate(ast)
        return JsSynthesizer().convert(ast)

    def _deobfuscate_iterative(self, source: str, iterations: int = 100) -> str:
        ast = JsParser(source).parse()
        for _ in range(iterations):
            if not deobfuscate(ast):
                break
        return JsSynthesizer().convert(ast)

    def _run_transformer(self, source: str, t: type[Transformer]):
        ast = JsParser(source).parse()
        t().visit(ast)
        return JsSynthesizer().convert(ast)

    def _inline(self, source: str) -> str:
        return self._run_transformer(source, JsConstantInlining)

    def _simplify(self, source: str) -> str:
        return self._run_transformer(source, JsSimplifications)

    def _deadcode(self, source: str) -> str:
        return self._run_transformer(source, JsDeadCodeElimination)

    def _objectfold(self, source: str) -> str:
        return self._run_transformer(source, JsObjectFold)

    def _unwrap(self, source: str) -> str:
        return self._run_transformer(source, JsAssignmentsAsFunctionArgs)


class TestBasicSimplifications(TestJsDeobfuscator):

    def test_string_concat_simple(self):
        self.assertEqual("'ab';", self._simplify("'a' + 'b';"))

    def test_string_concat_nested(self):
        self.assertEqual("'abc';", self._simplify("'a' + 'b' + 'c';"))

    def test_arithmetic_add(self):
        self.assertEqual('5;', self._simplify('2 + 3;'))

    def test_arithmetic_multiply(self):
        self.assertEqual('20;', self._simplify('10 * 2;'))

    def test_arithmetic_subtract(self):
        self.assertEqual('7;', self._simplify('10 - 3;'))

    def test_arithmetic_power(self):
        self.assertEqual('8;', self._simplify('2 ** 3;'))

    def test_arithmetic_modulo(self):
        self.assertEqual('1;', self._simplify('10 % 3;'))

    def test_arithmetic_bitwise_or(self):
        self.assertEqual('7;', self._simplify('5 | 3;'))

    def test_arithmetic_bitwise_and(self):
        self.assertEqual('1;', self._simplify('5 & 3;'))

    def test_arithmetic_bitwise_xor(self):
        self.assertEqual('6;', self._simplify('5 ^ 3;'))

    def test_arithmetic_left_shift(self):
        self.assertEqual('8;', self._simplify('1 << 3;'))

    def test_arithmetic_right_shift(self):
        self.assertEqual('2;', self._simplify('8 >> 2;'))

    def test_arithmetic_unsigned_right_shift(self):
        self.assertEqual('4294967295;', self._simplify('(-1) >>> 0;'))

    def test_arithmetic_division_by_zero_unchanged(self):
        self.assertEqual('1 / 0;', self._simplify('1 / 0;'))

    def test_tuple_all_literals(self):
        self.assertEqual("'c';", self._simplify("'a', 'b', 'c';"))

    def test_tuple_side_effect_free(self):
        self.assertEqual("'c';", self._simplify("'a', x, 'c';"))

    def test_tuple_with_side_effect(self):
        self.assertEqual("f(), 'c';", self._simplify("'a', f(), 'c';"))

    def test_array_indexing(self):
        self.assertEqual('"b";', self._simplify('["a", "b", "c"][1];'))

    def test_array_indexing_first(self):
        self.assertEqual('"x";', self._simplify('["x", "y"][0];'))

    def test_bracket_to_dot(self):
        self.assertEqual('obj.prop;', self._simplify('obj["prop"];'))

    def test_bracket_non_identifier_unchanged(self):
        self.assertEqual('obj["a-b"];', self._simplify('obj["a-b"];'))

    def test_bracket_reserved_word_unchanged(self):
        self.assertEqual('obj["class"];', self._simplify('obj["class"];'))

    def test_paren_unwrap_string(self):
        self.assertEqual('"hello";', self._simplify('("hello");'))

    def test_paren_unwrap_number(self):
        self.assertEqual('42;', self._simplify('(42);'))

    def test_unary_not_zero(self):
        self.assertEqual('true;', self._simplify('!0;'))

    def test_unary_not_one(self):
        self.assertEqual('false;', self._simplify('!1;'))

    def test_typeof_string(self):
        self.assertEqual("'string';", self._simplify('typeof "x";'))

    def test_typeof_number(self):
        self.assertEqual("'number';", self._simplify('typeof 42;'))

    def test_typeof_boolean(self):
        self.assertEqual("'boolean';", self._simplify('typeof true;'))

    def test_unary_negate(self):
        self.assertEqual('-5;', self._simplify('-(5);'))

    def test_unary_plus(self):
        self.assertEqual('5;', self._simplify('+(5);'))

    def test_non_constant_unchanged(self):
        self.assertEqual('a + b;', self._simplify('a + b;'))

    def test_non_constant_member_unchanged(self):
        self.assertEqual('a[b];', self._simplify('a[b];'))

    def test_combined_deobfuscation(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                var y = 1;
                """
            ),
            self._simplify('var x = "hel" + "lo"; var y = [1, 2, 3][0];'),
        )

    def test_make_string_literal_escapes_control_chars(self):
        self.assertEqual(make_string_literal('a\nb').raw, "'a\\nb'")
        self.assertEqual(make_string_literal('x\ry').raw, "'x\\ry'")
        self.assertEqual(make_string_literal('p\tq').raw, "'p\\tq'")
        self.assertEqual(make_string_literal('m\0n').raw, "'m\\0n'")

    def test_unescape_hex_space(self):
        self.assertEqual("'hello world';", self._simplify("'hello\\x20world';"))

    def test_unescape_hex_mixed(self):
        self.assertEqual("'AB\\nC';", self._simplify("'A\\x42\\x0a\\x43';"))

    def test_unescape_unicode_short(self):
        self.assertEqual("'Hi';", self._simplify("'\\u0048\\u0069';"))

    def test_unescape_unicode_full(self):
        self.assertEqual("'Hello';", self._simplify("'\\u0048\\u0065\\u006c\\u006c\\u006f';"))

    def test_unescape_unicode_non_ascii(self):
        self.assertEqual("'你好';", self._simplify("'\\u4f60\\u597d';"))

    def test_unescape_preserves_quote(self):
        self.assertEqual("'don\\'t';", self._simplify("'don\\x27t';"))

    def test_unescape_preserves_backslash(self):
        self.assertEqual("'back\\\\slash';", self._simplify("'back\\x5cslash';"))

    def test_split_pipe_to_array(self):
        self.assertEqual("['a', 'b', 'c'];", self._simplify("'a|b|c'['split']('|');"))

    def test_split_dash_separator(self):
        self.assertEqual("['x', 'y'];", self._simplify("'x-y'['split']('-');"))

    def test_split_dot_notation(self):
        self.assertEqual("['a', 'b'];", self._simplify("'a|b'.split('|');"))

    def test_string_slice(self):
        self.assertEqual("'el';", self._simplify("'hello'.slice(1, 3);"))

    def test_string_char_at(self):
        self.assertEqual("'h';", self._simplify("'hello'.charAt(0);"))

    def test_string_to_lower_case(self):
        self.assertEqual("'hello';", self._simplify("'HELLO'.toLowerCase();"))

    def test_string_repeat(self):
        self.assertEqual("'abcabc';", self._simplify("'abc'.repeat(2);"))

    def test_string_replace(self):
        self.assertEqual(
            "'hello there';", self._simplify("'hello world'.replace('world', 'there');"),
        )

    def test_string_substring(self):
        self.assertEqual("'ell';", self._simplify("'hello'.substring(1, 4);"))

    def test_array_index_of(self):
        self.assertEqual("1;", self._simplify("['a', 'b', 'c'].indexOf('b');"))

    def test_array_slice(self):
        self.assertEqual("['b', 'c'];", self._simplify("['a', 'b', 'c'].slice(1);"))

    def test_atob(self):
        self.assertEqual("'Hello';", self._simplify("atob('SGVsbG8=');"))

    def test_btoa(self):
        self.assertEqual("'SGVsbG8=';", self._simplify("btoa('Hello');"))

    def test_unescape(self):
        self.assertEqual("'Hello';", self._simplify("unescape('%48%65%6C%6C%6F');"))

    def test_number_conversion(self):
        self.assertEqual("42;", self._simplify("Number('42');"))

    def test_json_parse_string(self):
        self.assertEqual("'hello';", self._simplify("JSON.parse('\"hello\"');"))

    def test_json_parse_array(self):
        self.assertEqual("[1, 2, 3];", self._simplify("JSON.parse('[1, 2, 3]');"))

    def test_json_parse_object(self):
        self.assertEqual("({ 'a': 1 });", self._simplify("JSON.parse('{\"a\": 1}');"))

    def test_no_fold_variable_receiver(self):
        self.assertEqual("x.slice(1);", self._simplify("x.slice(1);"))

    def test_no_fold_variable_arg(self):
        self.assertEqual("atob(x);", self._simplify("atob(x);"))

    def test_no_fold_unknown_method(self):
        self.assertEqual("'hello'.unknownMethod();", self._simplify("'hello'.unknownMethod();"))

    def test_no_fold_length_as_callable(self):
        self.assertEqual("'hello'.length();", self._simplify("'hello'.length();"))

    def test_no_fold_void_with_side_effect(self):
        self.assertEqual("atob(void f());", self._simplify("atob(void f());"))

    def test_array_index_of_boolean_strict(self):
        self.assertEqual("-1;", self._simplify("[1, 2].indexOf(true);"))

    def test_array_includes_boolean_strict(self):
        self.assertEqual("false;", self._simplify("[1].includes(true);"))

    def test_string_replace_dollar_match(self):
        self.assertEqual("'[a]bc';", self._simplify("'abc'.replace('a', '[$&]');"))

    def test_string_replace_dollar_escape(self):
        self.assertEqual("'$bc';", self._simplify("'abc'.replace('a', '$$');"))

    def test_math_max_with_nan_string(self):
        self.assertEqual("NaN;", self._simplify("Math.max(5, 'abc');"))

    def test_number_empty_array(self):
        self.assertEqual("0;", self._simplify("Number([]);"))

    def test_number_single_element_array(self):
        self.assertEqual("5;", self._simplify("Number([5]);"))

    def test_number_underscore_string_is_nan(self):
        self.assertEqual("NaN;", self._simplify("Number('1_000');"))

    def test_no_fold_json_parse_infinity(self):
        self.assertEqual("JSON.parse('Infinity');", self._simplify("JSON.parse('Infinity');"))


class TestStringArray(TestJsDeobfuscator):

    _DEFAULT_PRESET_BODY = (
        r"(function(_0x13a108,_0x20b5f6){var _0x2bca43=_0x1b07,_0x36965a=_0x13a108();while(!![]){try{var _0x29"
        r"3699=-parseInt(_0x2bca43(0xa7))/0x1+-parseInt(_0x2bca43(0xa1))/0x2*(-parseInt(_0x2bca43(0xab))/0x3)+"
        r"parseInt(_0x2bca43(0xa3))/0x4*(-parseInt(_0x2bca43(0xa9))/0x5)+parseInt(_0x2bca43(0xa6))/0x6+parseIn"
        r"t(_0x2bca43(0xaa))/0x7*(parseInt(_0x2bca43(0xa2))/0x8)+-parseInt(_0x2bca43(0xa4))/0x9*(-parseInt(_0x"
        r"2bca43(0xa5))/0xa)+-parseInt(_0x2bca43(0xa0))/0xb;if(_0x293699===_0x20b5f6)break;else _0x36965a['pus"
        r"h'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift']());}}}(_0x2fc0,0x82"
        r"7c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc00e=_0x2fc0();var _0x"
        r"1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}var msg=_0xe6abe5(0xac);function _0x2fc0(){var _0x581e"
        r"61=['2435007zbgngY','test\x20string','12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','486kcIkKD','"
        r"183450npXmbZ','4067550xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR'];_0x2fc0=function(){r"
        r"eturn _0x581e61;};return _0x2fc0();}console[_0xe6abe5(0xa8)](msg);"
    )

    @classmethod
    def _default_preset(cls, accessor: str = '_0xe6abe5') -> str:
        source = cls._DEFAULT_PRESET_BODY
        if accessor == '_0xe6abe5':
            return F'var _0xe6abe5=_0x1b07;{source}'
        return source.replace('_0xe6abe5', accessor)

    def test_string_array_default_preset(self):
        result = self._deobfuscate(self._default_preset())
        self.assertIn("'test string'", result)
        self.assertIn('console.log', result)
        self.assertNotIn('_0x2fc0', result)

    def test_string_array_rc4_encoding(self):
        source = (
            r"var _0x28eff0=_0x85f7;function _0x138c(){var _0x3144dc=['W4CnWRpcQKn3W7mbW4OU','W67dOZ3dU0hdS8ktzmom"
            r"','w24prCo1WPFdJCosWQ1zWQy','W7FdSCo6W5NdJa','W63dPZZcRrtcV8o+umo2g8krW6BcTW','WRxdHSooB8oIaspcNelcV"
            r"8oo','WP1+W7j1FXFdRNzpW6q/wG/cNCkmtSovrmoexrVdUSkYghRcLvmrW7LflCkw','ySkEW7S','W77cN8oI','jK9/baPXgt"
            r"FcGatcQGpcSG','WQdcUCo+W4tdL1tdJSoh','WPKtWRH4W4WAW6ddQbX1cWVcSa','W4vkpMHqW6dcNSk+W7qgW7Lwl8oYW5fjl"
            r"SkoWRm','vCkGfmoJFmoN','c8khWOJdKqbipgldPSooWOBcQa','pvVdR8kZWPnHuG','wmodW4RcI0O','WO5cBtWeW7frj8oR"
            r"','W6OGbG1sBmolA8ogyxLBuG','mmowW4reW4FdLSoDWR1bdSoPW6u','oSkmWO8X','W4yfWRRcPJ5LW6STW4OHW6O','W4pcU"
            r"KxdH8oC','W4njWPrtrXBcVeVcMWVdUa','ncPvfKyVsSkG','W4ygrSo5avpdKcS','dv1rdWa/WOv8vHi','hMPWqsrtW7agaq"
            r"','cmoKrCkk','WR/dHCk0dSkKE8kLBCkawc0','WR7cQCkIWPVcNH7cHSkJW6OKW593','W5jDohjq','WRDXwLmtna','W4ZcQ"
            r"moQW6tdUa','W6pdICo9W4NcRhmoFSkw','cmkdWO3dKajmnM7dJ8o5WRBcSW','WQddHCk2W6e+WP7dQCoyWPT8C8kzWRy','Cx"
            r"n+n0qrBmkb','WOapWQjVW5idW77cSK8Mzh4','W4pcThtdN8olzuag','W5XxWR8eW5BcUgmICfFcLSkD','v1/cSuxdHJRcQa'"
            r",'WPevW4mqAYlcSe/cLZe','p8ohW6tcO8kDWPhdPmol','WPxdHN/dOW'];_0x138c=function(){return _0x3144dc;};re"
            r"turn _0x138c();}function _0x85f7(_0x4af7e9,_0x789356){_0x4af7e9=_0x4af7e9-0x14c;var _0x7a46f0=_0x138"
            r"c();var _0x5eebe1=_0x7a46f0[_0x4af7e9];if(_0x85f7['Ecnfls']===undefined){var _0x5083fb=function(_0x1"
            r"38cc6){var _0x85f78b='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var _0x4396"
            r"3a='',_0x3e8610='',_0x3e54d4=_0x43963a+_0x5083fb,_0x29f804=(''+function(){return 0x0;})['indexOf']('"
            r"\x0a')!==-0x1;for(var _0x518262=0x0,_0x50edcc,_0x1a6a9b,_0x1b65be=0x0;_0x1a6a9b=_0x138cc6['charAt']("
            r"_0x1b65be++);~_0x1a6a9b&&(_0x50edcc=_0x518262%0x4?_0x50edcc*0x40+_0x1a6a9b:_0x1a6a9b,_0x518262++%0x4"
            r")?_0x43963a+=_0x29f804||_0x3e54d4['charCodeAt'](_0x1b65be+0xa)-0xa!==0x0?String['fromCharCode'](0xff"
            r"&_0x50edcc>>(-0x2*_0x518262&0x6)):_0x518262:0x0){_0x1a6a9b=_0x85f78b['indexOf'](_0x1a6a9b);}for(var "
            r"_0x21a7b2=0x0,_0x2450dc=_0x43963a['length'];_0x21a7b2<_0x2450dc;_0x21a7b2++){_0x3e8610+='%'+('00'+_0"
            r"x43963a['charCodeAt'](_0x21a7b2)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x3e8"
            r"610);};var _0x42cc8d=function(_0x525d21,_0xb4ae49){var _0x5812fb=[],_0x42d0ca=0x0,_0x72b3ac,_0x7cffb"
            r"e='';_0x525d21=_0x5083fb(_0x525d21);var _0x347b99;for(_0x347b99=0x0;_0x347b99<0x100;_0x347b99++){_0x"
            r"5812fb[_0x347b99]=_0x347b99;}for(_0x347b99=0x0;_0x347b99<0x100;_0x347b99++){_0x42d0ca=(_0x42d0ca+_0x"
            r"5812fb[_0x347b99]+_0xb4ae49['charCodeAt'](_0x347b99%_0xb4ae49['length']))%0x100,_0x72b3ac=_0x5812fb["
            r"_0x347b99],_0x5812fb[_0x347b99]=_0x5812fb[_0x42d0ca],_0x5812fb[_0x42d0ca]=_0x72b3ac;}_0x347b99=0x0,_"
            r"0x42d0ca=0x0;for(var _0x55c939=0x0;_0x55c939<_0x525d21['length'];_0x55c939++){_0x347b99=(_0x347b99+0"
            r"x1)%0x100,_0x42d0ca=(_0x42d0ca+_0x5812fb[_0x347b99])%0x100,_0x72b3ac=_0x5812fb[_0x347b99],_0x5812fb["
            r"_0x347b99]=_0x5812fb[_0x42d0ca],_0x5812fb[_0x42d0ca]=_0x72b3ac,_0x7cffbe+=String['fromCharCode'](_0x"
            r"525d21['charCodeAt'](_0x55c939)^_0x5812fb[(_0x5812fb[_0x347b99]+_0x5812fb[_0x42d0ca])%0x100]);}retur"
            r"n _0x7cffbe;};_0x85f7['WMPOrt']=_0x42cc8d,_0x85f7['HNjmjk']={},_0x85f7['Ecnfls']=!![];}var _0x1897c4"
            r"=_0x7a46f0[0x0],_0x55963d=_0x4af7e9+_0x1897c4,_0x7c3c=_0x85f7['HNjmjk'][_0x55963d];if(!_0x7c3c){if(_"
            r"0x85f7['HYiIOj']===undefined){var _0x1c604c=function(_0x39dfaa){this['ekjwSF']=_0x39dfaa,this['thDCz"
            r"d']=[0x1,0x0,0x0],this['MrvPnY']=function(){return'newState';},this['iUjMCk']='\x5cw+\x20*\x5c(\x5c)"
            r"\x20*{\x5cw+\x20*',this['pKSLss']='[\x27|\x22].+[\x27|\x22];?\x20*}';};_0x1c604c['prototype']['rZEHh"
            r"c']=function(){var _0x24be40=new RegExp(this['iUjMCk']+this['pKSLss']),_0x508196=_0x24be40['test'](t"
            r"his['MrvPnY']['toString']())?--this['thDCzd'][0x1]:--this['thDCzd'][0x0];return this['reqeIL'](_0x50"
            r"8196);},_0x1c604c['prototype']['reqeIL']=function(_0x3cea1d){if(!Boolean(~_0x3cea1d))return _0x3cea1"
            r"d;return this['eMIAaD'](this['ekjwSF']);},_0x1c604c['prototype']['eMIAaD']=function(_0x5a4a1f){for(v"
            r"ar _0x404b8a=0x0,_0x2330df=this['thDCzd']['length'];_0x404b8a<_0x2330df;_0x404b8a++){this['thDCzd']["
            r"'push'](Math['round'](Math['random']())),_0x2330df=this['thDCzd']['length'];}return _0x5a4a1f(this['"
            r"thDCzd'][0x0]);},(''+function(){return 0x0;})['indexOf']('\x0a')===-0x1&&new _0x1c604c(_0x85f7)['rZE"
            r"Hhc'](),_0x85f7['HYiIOj']=!![];}_0x5eebe1=_0x85f7['WMPOrt'](_0x5eebe1,_0x789356),_0x85f7['HNjmjk'][_"
            r"0x55963d]=_0x5eebe1;}else _0x5eebe1=_0x7c3c;return _0x5eebe1;}(function(_0x566ec1,_0x397185){var _0x"
            r"1fe482=_0x85f7,_0x50fe64=_0x566ec1();while(!![]){try{var _0xafcaf6=parseInt(_0x1fe482(0x175,'43HA'))"
            r"/0x1*(-parseInt(_0x1fe482(0x150,'cGSY'))/0x2)+-parseInt(_0x1fe482(0x173,'DYhn'))/0x3*(parseInt(_0x1f"
            r"e482(0x15a,'vHRQ'))/0x4)+-parseInt(_0x1fe482(0x162,'cq*e'))/0x5+parseInt(_0x1fe482(0x159,'p]TC'))/0x"
            r"6+parseInt(_0x1fe482(0x174,'q1WL'))/0x7+-parseInt(_0x1fe482(0x161,'Dja*'))/0x8*(-parseInt(_0x1fe482("
            r"0x15e,'DYhn'))/0x9)+parseInt(_0x1fe482(0x14d,'zupi'))/0xa*(parseInt(_0x1fe482(0x16d,'Ot85'))/0xb);if"
            r"(_0xafcaf6===_0x397185)break;else _0x50fe64['push'](_0x50fe64['shift']());}catch(_0x1fe138){_0x50fe6"
            r"4['push'](_0x50fe64['shift']());}}}(_0x138c,0x697ae));var msg=_0x28eff0(0x152,'#Y8%');console[_0x28e"
            r"ff0(0x158,'q1WL')](msg);"
        )
        result = self._deobfuscate(source)
        self.assertIn("'test string'", result)
        self.assertIn('console.log', result)
        self.assertNotIn('_0x138c', result)

    def test_string_array_medium_preset(self):
        source = (
            r"(function(_0x34f09b,_0x2ba2c7){var _0x1511b7=_0x1dce,_0x325c2c=_0x1dce,_0x4ab4b0=_0x34f09b();while(!"
            r"![]){try{var _0x593aa2=-parseInt(_0x1511b7(0x14a))/(-0x996*-0x1+0xdf*0x16+-0x1cbf)*(parseInt(_0x325c"
            r"2c(0x134))/(0x1*-0x192d+0x2*-0x59f+0x246d))+parseInt(_0x325c2c(0x13c))/(0x51*-0x18+-0x5b1+0xd4c)+par"
            r"seInt(_0x325c2c(0x130))/(-0x1*0xb0f+0x166f+-0x2d7*0x4)+-parseInt(_0x325c2c(0x154))/(0x911*0x1+0x195*"
            r"-0x3+-0x44d)+-parseInt(_0x325c2c(0x15b))/(-0xa0a+-0x105+0x1*0xb15)+-parseInt(_0x325c2c(0x12c))/(0x1*"
            r"0x2057+0x14a*0xb+0x16*-0x21d)+-parseInt(_0x1511b7(0x12b))/(-0x5b5+-0x187e+0x1e3b)*(-parseInt(_0x1511"
            r"b7(0x132))/(-0x3*-0x6a3+0x1f3d+-0x331d));if(_0x593aa2===_0x2ba2c7)break;else _0x4ab4b0['push'](_0x4a"
            r"b4b0['shift']());}catch(_0x48377f){_0x4ab4b0['push'](_0x4ab4b0['shift']());}}}(_0x287a,-0x97be7+-0x8"
            r"8066+0x184e33));function _0x1dce(_0x2813b9,_0x23aedc){_0x2813b9=_0x2813b9-(-0x1*0xd49+0x1*-0x335+-0x"
            r"11a1*-0x1);var _0x294c48=_0x287a();var _0x2c6771=_0x294c48[_0x2813b9];if(_0x1dce['mgzOcZ']===undefin"
            r"ed){var _0x1d90f4=function(_0x4924e2){var _0x296904='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU"
            r"VWXYZ0123456789+/=';var _0x5cd014='',_0x353c7b='',_0x5ab9b1=_0x5cd014+_0x1d90f4,_0x7ce0f3=(''+functi"
            r"on(){return-0xfe5+-0x5e8+0x15cd;})['indexOf']('\x0a')!==-(0x10db+-0x26b7+0x15dd);for(var _0x2f3647=-"
            r"0xc8d+-0x3*-0x8e+0xae3,_0x3e3c71,_0x59c6e0,_0x229262=0x6ad*0x3+0x2264+-0x366b;_0x59c6e0=_0x4924e2['c"
            r"harAt'](_0x229262++);~_0x59c6e0&&(_0x3e3c71=_0x2f3647%(0x1de7*-0x1+0x16e2+0x709*0x1)?_0x3e3c71*(0x6e"
            r"5+0x19ec+-0x7*0x4a7)+_0x59c6e0:_0x59c6e0,_0x2f3647++%(-0x1d*-0x4d+-0xd1c*-0x2+-0x22ed))?_0x5cd014+=_"
            r"0x7ce0f3||_0x5ab9b1['charCodeAt'](_0x229262+(-0x2a6*-0x9+-0x23d7+0xc0b))-(0x2*-0x53+-0x1b6b+-0x1c1b*"
            r"-0x1)!==-0x2*-0xce3+0x379+0x1d3f*-0x1?String['fromCharCode'](-0xe7c+-0xbf*0x19+0x2222&_0x3e3c71>>(-("
            r"-0x1ce5+-0x6b*0x8+0x203f)*_0x2f3647&-0x503+-0x1fa1+0x24aa)):_0x2f3647:-0x862+0x8cb*0x2+-0x934){_0x59"
            r"c6e0=_0x296904['indexOf'](_0x59c6e0);}for(var _0x31be37=0x241a+0x423+-0x283d,_0x489aa0=_0x5cd014['le"
            r"ngth'];_0x31be37<_0x489aa0;_0x31be37++){_0x353c7b+='%'+('00'+_0x5cd014['charCodeAt'](_0x31be37)['toS"
            r"tring'](-0x18c3+-0x2422+0x1*0x3cf5))['slice'](-(0x11f8+-0x2579+0xb9*0x1b));}return decodeURIComponen"
            r"t(_0x353c7b);};_0x1dce['YgTpuI']=_0x1d90f4,_0x1dce['BVHmSK']={},_0x1dce['mgzOcZ']=!![];}var _0x4ffdb"
            r"5=_0x294c48[-0xe41+0x474+0x1*0x9cd],_0x2a4583=_0x2813b9+_0x4ffdb5,_0x2f31e4=_0x1dce['BVHmSK'][_0x2a4"
            r"583];if(!_0x2f31e4){var _0x2edc24=function(_0xeb37e){this['deBJNF']=_0xeb37e,this['wasqbd']=[0x1*-0x"
            r"deb+-0xaf2+0x425*0x6,-0x1115*0x1+0x1*0x295+-0x3a0*-0x4,0x228b+0x1946+-0x3bd1*0x1],this['pBqtjK']=fun"
            r"ction(){return'newState';},this['QgsebD']='\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*',this['RVCFCM']='["
            r"\x27|\x22].+[\x27|\x22];?\x20*}';};_0x2edc24['prototype']['qXndiN']=function(){var _0x1cd02a=new Reg"
            r"Exp(this['QgsebD']+this['RVCFCM']),_0x3bf747=_0x1cd02a['test'](this['pBqtjK']['toString']())?--this["
            r"'wasqbd'][-0x15*-0x10a+0x1*0x1ad7+-0x30a8]:--this['wasqbd'][0x890+0x263+0xaf3*-0x1];return this['KDq"
            r"Swv'](_0x3bf747);},_0x2edc24['prototype']['KDqSwv']=function(_0x23a01b){if(!Boolean(~_0x23a01b))retu"
            r"rn _0x23a01b;return this['lltWwG'](this['deBJNF']);},_0x2edc24['prototype']['lltWwG']=function(_0x4d"
            r"1c63){for(var _0x8bc27c=-0x488+0x26e3+-0x225b,_0x2c26e7=this['wasqbd']['length'];_0x8bc27c<_0x2c26e7"
            r";_0x8bc27c++){this['wasqbd']['push'](Math['round'](Math['random']())),_0x2c26e7=this['wasqbd']['leng"
            r"th'];}return _0x4d1c63(this['wasqbd'][0xb3*0xd+0x2*-0x40a+0x25*-0x7]);},(''+function(){return 0x156*"
            r"0x1+0x3b*-0xe+0x79*0x4;})['indexOf']('\x0a')===-(-0xc6*-0x7+-0x71b+0x1b2)&&new _0x2edc24(_0x1dce)['q"
            r"XndiN'](),_0x2c6771=_0x1dce['YgTpuI'](_0x2c6771),_0x1dce['BVHmSK'][_0x2a4583]=_0x2c6771;}else _0x2c6"
            r"771=_0x2f31e4;return _0x2c6771;}function _0x287a(){var _0x49ee2b=['DvrzCha','CKrnrxy','DgfIBgu','D2f"
            r"YBG','yMLUza','Dg9tDhjPBMC','mteYntq2nwjlAKn2rq','Aw5MBW','CM4GDgHPCYiPka','z1nmz3i','uefmtfy','DhjH"
            r"y2u','sgvSBg8','yxLJuNK','tgjHDuu','y29UC29Szq','AvjZsgi','mhWYFdn8nhWX','E30Uy29UC3rYDq','v0fXC1G',"
            r"'mJDLtgTLqMC','Cw15yvm','m3WWFdv8mNW0Fa','yKT2zgC','wNr2veW','BMn0Aw9UkcKG','kcGOlISPkYKRkq','Bg9N',"
            r"'C3bSAxq','Cw52rgS','mJaYodC0mhniALrlrW','zxHJzxb0Aw9U','x19WCM90B19F','zLbeq2i','vM9lEuu','C0TAAui'"
            r",'zxjYB3i','mZe4odCZnLjywKP2vG','yxbWBhK','DgzRB2y','r3vxuLe','B0LVCvu','CMv0DxjUicHMDq','ChjVDg90Ex"
            r"bL','qvL3wMm','D09Qv0O','yMTHrKC','rgjvug8','y29UC3rYDwn0BW','y3jTrvy','mtKWntzsDhvktM8','ndmYmdi1m2"
            r"fPzNPJCG','t3Pkww8','y3rVCIGICMv0Dq','DuXIvLa','mtG1odeXmMLpsuDRAG','C3P2DhC','nJGYmM1lANL0rq','AgzL"
            r"A20','ntaXmJrxrLnuz2q','BNzOEM4'];_0x287a=function(){return _0x49ee2b;};return _0x287a();}function g"
            r"reet(_0x3d7991){var _0x216c1f=_0x1dce,_0x382c03=_0x1dce,_0x5419f8={'tfkof':_0x216c1f(0x147),'qmyaS':"
            r"_0x382c03(0x142),'crmEV':function(_0x5b4e18,_0x25d5ec){return _0x5b4e18+_0x25d5ec;}},_0x27e487=_0x54"
            r"19f8[_0x216c1f(0x15d)][_0x216c1f(0x152)]('|'),_0x26b3cc=0x144+-0x3*-0xae4+-0x21f*0x10;while(!![]){sw"
            r"itch(_0x27e487[_0x26b3cc++]){case'0':var _0x26c605=_0x5419f8[_0x216c1f(0x14b)];continue;case'1':retu"
            r"rn _0x3dde7b+_0x2b506e;case'2':var _0x3567eb=',\x20';continue;case'3':var _0x3dde7b=_0x5419f8[_0x382"
            r"c03(0x12a)](_0x26c605,_0x3567eb)+_0x3d7991;continue;case'4':var _0x2b506e='!';continue;}break;}}"
        )
        result = self._deobfuscate(source)
        self.assertIn('Hello', result)
        self.assertIn("'!'", result)
        self.assertNotIn('_0x1dce(', result)
        self.assertNotIn('function _0x287a', result)

    def test_string_array_with_wrappers(self):
        source = (
            r"function _0xw(_0xa){return _0x1b07(_0xa- -0x0);}"
            + self._default_preset('_0xw')
        )
        result = self._deobfuscate(source)
        self.assertIn("'test string'", result)
        self.assertIn('console.log', result)
        self.assertNotIn('_0xw', result)
        self.assertNotIn('_0x1b07', result)

    def test_string_array_cache_survives_checksum_corruption(self):
        """
        After a successful string array resolution, the resolved array is cached on the AST node.
        If the checksum expression in the rotation IIFE is corrupted (e.g. by the simplifier
        collapsing arithmetic), subsequent passes must still produce correct results from the cache
        rather than re-simulating the rotation and getting garbled strings.
        """
        from refinery.lib.scripts.js.deobfuscation.stringarray import (
            JsStringArrayResolver,
            _CACHE_ATTR,
        )
        source = self._default_preset()
        ast = JsParser(source).parse()
        resolver = JsStringArrayResolver()
        resolver.visit(ast)
        self.assertTrue(resolver.changed)
        cache = getattr(ast, _CACHE_ATTR, None)
        self.assertIsNotNone(cache)
        result = JsSynthesizer().convert(ast)
        self.assertIn("'test string'", result)
        self.assertIn("'log'", result)

    def test_string_array_inside_function_body(self):
        source = 'function wrapper() { var _0xe6abe5=_0x1b07;' + self._DEFAULT_PRESET_BODY + '}'
        result = self._deobfuscate(source)
        self.assertEqual("function wrapper() {\n  console.log('test string');\n}", result)

    def test_string_array_inline_if_checksum(self):
        """
        When the checksum expression is inlined directly into the if-statement condition (no
        intermediate variable), the resolver must extract it from the comparison.
        """
        source = (
            r"var _0xe6abe5=_0x1b07;(function(_0x13a108,_0x20b5f6){var _0x2bca43=_0x1b07,_0x36965a=_0x13a108();whi"
            r"le(!![]){try{if(-parseInt(_0x2bca43(0xa7))/0x1+-parseInt(_0x2bca43(0xa1))/0x2*(-parseInt(_0x2bca43(0"
            r"xab))/0x3)+parseInt(_0x2bca43(0xa3))/0x4*(-parseInt(_0x2bca43(0xa9))/0x5)+parseInt(_0x2bca43(0xa6))/"
            r"0x6+parseInt(_0x2bca43(0xaa))/0x7*(parseInt(_0x2bca43(0xa2))/0x8)+-parseInt(_0x2bca43(0xa4))/0x9*(-p"
            r"arseInt(_0x2bca43(0xa5))/0xa)+-parseInt(_0x2bca43(0xa0))/0xb===_0x20b5f6)break;else _0x36965a['push'"
            r"](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift']());}}}(_0x2fc0,0x827c"
            r"2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc00e=_0x2fc0();var _0x1b"
            r"0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}var msg=_0xe6abe5(0xac);function _0x2fc0(){var _0x581e61"
            r"=['2435007zbgngY','test\x20string','12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','486kcIkKD','18"
            r"3450npXmbZ','4067550xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR'];_0x2fc0=function(){ret"
            r"urn _0x581e61;};return _0x2fc0();}console[_0xe6abe5(0xa8)](msg);"
        )
        result = self._deobfuscate(source)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_constant_folded_checksum(self):
        """
        When other passes constant-fold the checksum expression to a numeric literal equal to the
        rotation target, the array is already in the correct position. The resolver must handle this
        trivially-true comparison in the if-statement without an intermediate variable.
        """
        source = (
            r"(function(_0x13a108,_0x20b5f6){var _0x36965a=_0x13a108();while(!![]){try{if(0x827c2===_0x20b5f6)brea"
            r"k;else _0x36965a['push'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift'"
            r"]());}}}(_0x2fc0,0x827c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc"
            r"00e=_0x2fc0();var _0x1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}var _0xe6abe5=_0x1b07;var msg=_0x"
            r"e6abe5(0xac);function _0x2fc0(){var _0x581e61=['12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','48"
            r"6kcIkKD','183450npXmbZ','4067550xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR','2435007zbg"
            r"ngY','test\x20string'];_0x2fc0=function(){return _0x581e61;};return _0x2fc0();}console[_0xe6abe5(0xa"
            r"8)](msg);"
        )
        result = self._deobfuscate(source)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_multi_accessor(self):
        """
        When multiple accessor functions share the same string array (e.g. one for base64, one for
        plain indexing), the resolver must track encoding per accessor and clean up all of them.
        """
        source = (
            r"var _0xe6abe5=_0x1b07;(function(_0x13a108,_0x20b5f6){var _0x2bca43=_0x1b07,_0x36965a=_0x13a108();whi"
            r"le(!![]){try{var _0x293699=-parseInt(_0x2bca43(0xa7))/0x1+-parseInt(_0x2bca43(0xa1))/0x2*(-parseInt("
            r"_0x2bca43(0xab))/0x3)+parseInt(_0x2bca43(0xa3))/0x4*(-parseInt(_0x2bca43(0xa9))/0x5)+parseInt(_0x2bc"
            r"a43(0xa6))/0x6+parseInt(_0x2bca43(0xaa))/0x7*(parseInt(_0x2bca43(0xa2))/0x8)+-parseInt(_0x2bca43(0xa"
            r"4))/0x9*(-parseInt(_0x2bca43(0xa5))/0xa)+-parseInt(_0x2bca43(0xa0))/0xb;if(_0x293699===_0x20b5f6)bre"
            r"ak;else _0x36965a['push'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift"
            r"']());}}}(_0x2fc0,0x827c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2f"
            r"c00e=_0x2fc0();var _0x1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}function _0x2nd(_0x3a2c1f,_0x271"
            r"b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc00e=_0x2fc0();var _0x1b0775=_0x2fc00e[_0x3a2c1f];return _0x1"
            r"b0775;}var msg=_0xe6abe5(0xac);function _0x2fc0(){var _0x581e61=['2435007zbgngY','test\x20string','1"
            r"2767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','486kcIkKD','183450npXmbZ','4067550xFhrYl','462884ST"
            r"mCds','log','50725EqKMLb','48769HzjsUR'];_0x2fc0=function(){return _0x581e61;};return _0x2fc0();}con"
            r"sole[_0x2nd(0xa8)](msg);"
        )
        result = self._deobfuscate(source)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_transitive_aliases(self):
        """
        When a direct alias of the accessor is itself re-aliased inside nested functions
        (const z = _0x1a where _0x1a = _0xe6abe5 = _0x1b07), the resolver must follow the
        transitive chain and resolve calls through all alias levels.
        """
        source = (
            r"var _0xe6abe5=_0x1b07;(function(_0x13a108,_0x20b5f6){var _0x2bca43=_0x1b07,_0x36965a=_0x13a108();while"
            r"(!![]){try{var _0x293699=-parseInt(_0x2bca43(0xa7))/0x1+-parseInt(_0x2bca43(0xa1))/0x2*(-parseInt(_0x2"
            r"bca43(0xab))/0x3)+parseInt(_0x2bca43(0xa3))/0x4*(-parseInt(_0x2bca43(0xa9))/0x5)+parseInt(_0x2bca43(0x"
            r"a6))/0x6+parseInt(_0x2bca43(0xaa))/0x7*(parseInt(_0x2bca43(0xa2))/0x8)+-parseInt(_0x2bca43(0xa4))/0x9*"
            r"(-parseInt(_0x2bca43(0xa5))/0xa)+-parseInt(_0x2bca43(0xa0))/0xb;if(_0x293699===_0x20b5f6)break;else _0"
            r"x36965a['push'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift']());}}}(_0"
            r"x2fc0,0x827c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc00e=_0x2fc0()"
            r";var _0x1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}function _0x2fc0(){var _0x581e61=['2435007zbgngY"
            r"','test\x20string','12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','486kcIkKD','183450npXmbZ','40675"
            r"50xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR'];_0x2fc0=function(){return _0x581e61;};retu"
            r"rn _0x2fc0();}var _0x1a=_0xe6abe5;function log(){var z=_0x1a,A=_0x1a;console[z(0xa8)](A(0xac));}log();"
        )
        result = self._deobfuscate(source)
        self.assertEqual(
            "function log() {\n  console.log('test string');\n}\nlog();",
            result,
        )

    def test_string_array_self_overwriting_accessor_detected(self):
        """
        The self-overwriting (memoization) accessor variant assigns the inner decoder function back
        to the accessor name on first call. The resolver must recognize this pattern and extract the
        base offset from the inner function's subtraction statement.
        """
        from refinery.lib.scripts.js.deobfuscation.stringarray import (
            _find_array_function,
            _find_all_accessor_functions,
            _detect_encoding,
            Encoding,
        )
        source = (
            r"function V(){var a=['str0','str1','str2'];V=function(){return a;};return V();}"
            r"function N(B,I){const Y=V();N=function(Z,o){Z=Z-(0x1*0xb2e+-0x126+0x1*-0x8eb);"
            r"let R=Y[Z];if(N['\x6f\x76\x46\x70\x6f\x4a']===undefined){"
            r"var u=function(C){const F='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            r"0123456789+/=';return C;};var d=function(s,k){return s;};N['\x63\x61\x74\x55\x4d"
            r"\x4f']=u;N['\x6f\x76\x46\x70\x6f\x4a']=!![];}return R;};return N(B,I);}"
        )
        ast = JsParser(source).parse()
        arr = _find_array_function(ast.body)
        self.assertIsNotNone(arr)
        accs = _find_all_accessor_functions(ast.body, arr.name)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].name, 'N')
        self.assertEqual(accs[0].base_offset, 0xb2e - 0x126 - 0x8eb)
        self.assertEqual(_detect_encoding(accs[0].node), Encoding.RC4)

    def test_string_array_self_overwriting_accessor_b64(self):
        """
        Same self-overwriting pattern with only base64 (one inner function = B64 encoding).
        """
        from refinery.lib.scripts.js.deobfuscation.stringarray import (
            _find_array_function,
            _find_all_accessor_functions,
            _detect_encoding,
            Encoding,
        )
        source = (
            r"function V(){var a=['str0','str1'];V=function(){return a;};return V();}"
            r"function N(B,I){const Y=V();N=function(Z,o){Z=Z-0x14c;"
            r"let R=Y[Z];if(N['init']===undefined){"
            r"var u=function(C){const F='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            r"0123456789+/=';return C;};N['decode']=u;N['init']=!![];}return R;};return N(B,I);}"
        )
        ast = JsParser(source).parse()
        arr = _find_array_function(ast.body)
        self.assertIsNotNone(arr)
        accs = _find_all_accessor_functions(ast.body, arr.name)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].name, 'N')
        self.assertEqual(accs[0].base_offset, 0x14c)
        self.assertEqual(_detect_encoding(accs[0].node), Encoding.B64)

    def test_string_array_prop_map_accessor_calls(self):
        """
        Accessor calls whose index argument is a member expression referencing a local const
        object must be resolved via prop-map lookup. This is the standard obfuscator.io pattern
        where local objects map property names to array indices both inside the rotation IIFE
        checksum and in the main body code.
        """
        source = (
            "function _0x5e03(){var a=['300xyz','800abc','secret_value','another_string','500target'];"
            "_0x5e03=function(){return a;};return _0x5e03();}"
            "function _0x1169(p,q){p=p-0x1f0;var arr=_0x5e03();var r=arr[p];return r;}"
            "(function(a,t){"
            "var _0x221ff1=_0x1169,_0x5f2282={_0x2bb395:0x1f0,_0x56f5b5:0x1f1};"
            "var b=a();"
            "while(true){try{"
            "var c=parseInt(_0x221ff1(_0x5f2282._0x2bb395))/0x1"
            "+parseInt(_0x221ff1(_0x5f2282._0x56f5b5))/0x2;"
            "if(c===t)break;b.push(b.shift());}catch(e){b.push(b.shift());}}}(_0x5e03,0x2bc));"
            "const _0x5d6bea=_0x1169;"
            "var _0x14f979={_0x5b48c6:0x1f2,_0x24ce26:0x1f3};"
            "var x=_0x5d6bea(_0x14f979._0x5b48c6);"
            "var y=_0x5d6bea(_0x14f979._0x24ce26);"
        )
        expected = inspect.cleandoc(
            """
            var x = 'secret_value';
            var y = 'another_string';
            """
        )
        self.assertEqual(self._deobfuscate(source), expected)

    def test_string_array_prop_map_nested_scope(self):
        source = (
            "function _0x5e03(){var a=['300xyz','800abc','secret','nested_val','deep_val'];"
            "_0x5e03=function(){return a;};return _0x5e03();}"
            "function _0x1169(p,q){p=p-0x1f0;var arr=_0x5e03();var r=arr[p];return r;}"
            "(function(a,t){"
            "var _0x221ff1=_0x1169,_0x5f2282={_0x2bb395:0x1f0,_0x56f5b5:0x1f1};"
            "var b=a();"
            "while(true){try{"
            "var c=parseInt(_0x221ff1(_0x5f2282._0x2bb395))/0x1"
            "+parseInt(_0x221ff1(_0x5f2282._0x56f5b5))/0x2;"
            "if(c===t)break;b.push(b.shift());}catch(e){b.push(b.shift());}}}(_0x5e03,0x2bc));"
            "const _0x5d6bea=_0x1169;"
            "function foo(){"
            "var _0xabc123={_0xkey1:0x1f2,_0xkey2:0x1f3};"
            "return _0x5d6bea(_0xabc123._0xkey1)+_0x5d6bea(_0xabc123._0xkey2);}"
            "var r=foo();"
        )
        expected = inspect.cleandoc(
            """
            function foo() {
              var _0xabc123 = { _0xkey1: 0x1f2, _0xkey2: 0x1f3 };
              return 'secret' + 'nested_val';
            }
            var r = foo();
            """
        )
        self.assertEqual(self._run_transformer(source, JsStringArrayResolver), expected)


class TestCallWrapperInliner(TestJsDeobfuscator):

    def test_simple_wrapper_inlining(self):
        source = (
            "function target(a, b) { return a + b; }"
            "function wrapper(x, y, z, w) { return target(w - -10, y); }"
            "var result = wrapper(1, 2, 3, 4);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function target(a, b) {
                  return a + b;
                }
                var result = target(4 - -10, 2);
                """
            ),
        )

    def test_wrapper_preserves_non_wrapper_functions(self):
        source = (
            "function real(x) { console.log(x); return x * 2; }"
            "real(5);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function real(x) {
                  console.log(x);
                  return x * 2;
                }
                real(5);
                """
            ),
        )

    def test_chained_wrappers(self):
        source = (
            "function target(a) { return a; }"
            "function inner(x, y) { return target(y - -5); }"
            "function outer(a, b, c) { return inner(a, c - -10); }"
            "var r = outer(1, 2, 3);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function target(a) {
                  return a;
                }
                function inner(x, y) {
                  return target(y - -5);
                }
                var r = inner(1, 3 - -10);
                """
            ),
        )


class TestStackUnwrapper(TestJsDeobfuscator):

    @staticmethod
    def _wrapper(name: str = 'wr') -> str:
        return F'function {name}() {{ {name} = function() {{}}; }}'

    def test_statement_expansion(self):
        source = self._wrapper() + 'wr(a = 1, b = 2); g(a, b);'
        result = self._deobfuscate(source)
        goal = inspect.cleandoc(
            """
            a = 1;
            b = 2;
            g(a, b);
            """
        )
        self.assertEqual(result, goal)

    def test_single_arg(self):
        source = self._wrapper() + 'wr(x = 42); g(x);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            x = 42;
            g(x);
            """
        ))

    def test_no_args(self):
        source = self._wrapper() + 'wr(); g();'
        self.assertEqual(self._unwrap(source), 'g();')

    def test_wrapper_removed(self):
        source = self._wrapper() + 'wr(a = 1);'
        self.assertEqual(self._unwrap(source), 'a = 1;')

    def test_non_wrapper_not_affected(self):
        source = 'function noop() {} noop(a, b);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            function noop() {}
            noop(a, b);
            """
        ))

    def test_multiple_wrappers(self):
        source = self._wrapper('wr1') + self._wrapper('wr2') + 'wr1(a = 1); wr2(b = 2); g(a, b);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            a = 1;
            b = 2;
            g(a, b);
            """
        ))

    def test_nested_in_function_body(self):
        source = self._wrapper() + 'function outer() { wr(x = 1, y = 2); return x + y; } outer();'
        self.assertEqual(
            self._unwrap(source),
            inspect.cleandoc(
                """
                function outer() {
                  x = 1;
                  y = 2;
                  return x + y;
                }
                outer();
                """
            ),
        )


class TestDeadCodeElimination(TestJsDeobfuscator):

    def test_if_true_keeps_consequent(self):
        self.assertEqual('x();', self._deadcode('if (true) { x(); } else { y(); }'))

    def test_if_false_keeps_alternate(self):
        self.assertEqual('y();', self._deadcode('if (false) { x(); } else { y(); }'))

    def test_if_false_no_else_removed(self):
        self.assertEqual('', self._deadcode('if (false) { x(); }'))

    def test_if_true_splices_block(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 1;
                var b = 2;
                var c = 3;
                var d = 4;
                """
            ),
            self._deadcode('var a = 1; if (true) { var b = 2; var c = 3; } var d = 4;'),
        )

    def test_ternary_true(self):
        self.assertEqual(
            "var x = 'a';",
            self._simplify("var x = true ? 'a' : 'b';"),
        )

    def test_ternary_false(self):
        self.assertEqual(
            "var x = 'b';",
            self._simplify("var x = false ? 'a' : 'b';"),
        )

    def test_dead_code_string_comparison(self):
        self.assertEqual(
            'live();',
            self._deobfuscate("if ('hello' === 'world') { dead(); } else { live(); }"),
        )

    def test_in_empty_function_guard_folded(self):
        source = inspect.cleandoc(
            """
            function __p_sentinel() {}
            if ("xK9mQ" in __p_sentinel) {
              __p_dead_1();
            }
            function __p_dead_1() { var fake = 999; }
            function real(n) {
              if ("abc" in __p_sentinel) {
                __p_dead_2();
              }
              function __p_dead_2() { var junk = 0; }
              return n + 1;
            }
            console.log(real(5));
            """
        )
        self.assertEqual(self._deobfuscate(source), 'console.log(6);')

    def test_in_empty_function_known_property_folds_true(self):
        source = inspect.cleandoc(
            """
            function sentinel() {}
            if ("length" in sentinel) {
              live();
            } else {
              dead();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), 'live();')

    def test_in_empty_class_guard_folded(self):
        source = inspect.cleandoc(
            """
            class Sentinel {}
            if ("randomJunk" in Sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            class Sentinel {}
            live();
            """
        ))

    def test_in_const_empty_object_guard_folded(self):
        source = inspect.cleandoc(
            """
            const sentinel = {};
            if ("randomKey" in sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            const sentinel = {};
            live();
            """
        ))

    def test_in_const_empty_object_known_property_folds_true(self):
        source = inspect.cleandoc(
            """
            const obj = {};
            if ("toString" in obj) {
              live();
            } else {
              dead();
            }
            if ("length" in obj) {
              dead2();
            } else {
              live2();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            const obj = {};
            live();
            live2();
            """
        ))


    def test_in_function_guard_nested_scope(self):
        source = inspect.cleandoc(
            """
            function sentinel() { return 1; }
            function main(n) {
              for (var i = 0; i < n; i++) {
                if ("xK9mQ" in sentinel) {
                  dead();
                }
              }
              return n;
            }
            console.log(main(5));
            """
        )
        self.assertEqual('console.log(5);', self._deobfuscate(source))

    def test_undeclared_dead_write_in_nested_block(self):
        source = inspect.cleandoc(
            """
            function f() {
              for (var i = 0; i < 3; i++) {
                deadVar = function() { return 42; };
              }
              return i;
            }
            f();
            """
        )
        self.assertEqual('3;', self._deobfuscate(source))


class TestExtendedOperatorFolding(TestJsDeobfuscator):

    def test_strict_equality_true(self):
        self.assertEqual('true;', self._simplify("'abc' === 'abc';"))

    def test_strict_equality_false(self):
        self.assertEqual('false;', self._simplify("'abc' === 'xyz';"))

    def test_strict_inequality(self):
        self.assertEqual('true;', self._simplify("'abc' !== 'xyz';"))

    def test_number_strict_equality(self):
        self.assertEqual('true;', self._simplify('42 === 42;'))

    def test_less_than_numbers(self):
        self.assertEqual('true;', self._simplify('3 < 5;'))

    def test_greater_equal_numbers(self):
        self.assertEqual('true;', self._simplify('5 >= 5;'))

    def test_less_than_strings(self):
        self.assertEqual('true;', self._simplify("'abc' < 'abd';"))

    def test_greater_than_numbers_false(self):
        self.assertEqual('false;', self._simplify('3 > 5;'))

    def test_less_equal_numbers(self):
        self.assertEqual('false;', self._simplify('7 <= 3;'))

    def test_loose_equality_same_type(self):
        self.assertEqual('true;', self._simplify('42 == 42;'))

    def test_loose_inequality_same_type(self):
        self.assertEqual('true;', self._simplify("'a' != 'b';"))

    def test_null_equality(self):
        self.assertEqual('true;', self._simplify('null == null;'))

    def test_logical_and_truthy_left(self):
        self.assertEqual("'world';", self._simplify("'hello' && 'world';"))

    def test_logical_and_falsy_left(self):
        self.assertEqual('0;', self._simplify("0 && 'world';"))

    def test_logical_or_truthy_left(self):
        self.assertEqual("'hello';", self._simplify("'hello' || 'world';"))

    def test_logical_or_falsy_left(self):
        self.assertEqual("'fallback';", self._simplify("'' || 'fallback';"))

    def test_nullish_coalescing_null(self):
        self.assertEqual("'default';", self._simplify("null ?? 'default';"))

    def test_nullish_coalescing_value(self):
        self.assertEqual('42;', self._simplify("42 ?? 'default';"))

    def test_bitwise_not_zero(self):
        self.assertEqual('-1;', self._simplify('~0;'))

    def test_bitwise_not_negative_one(self):
        self.assertEqual('0;', self._simplify('~(-1);'))

    def test_logical_not_true(self):
        self.assertEqual('false;', self._simplify('!true;'))

    def test_logical_not_false(self):
        self.assertEqual('true;', self._simplify('!false;'))

    def test_logical_not_null(self):
        self.assertEqual('true;', self._simplify('!null;'))

    def test_logical_not_empty_string(self):
        self.assertEqual('true;', self._simplify("!'';"))

    def test_logical_not_nonempty_string(self):
        self.assertEqual('false;', self._simplify("!'hello';"))

    def test_logical_not_undefined(self):
        self.assertEqual('true;', self._simplify('!undefined;'))

    def test_logical_not_empty_array(self):
        self.assertEqual('false;', self._simplify('![];'))

    def test_double_bang_array(self):
        self.assertEqual('true;', self._simplify('!![];'))

    def test_parseint_fold(self):
        self.assertEqual('3379;', self._simplify("parseInt('3379kkQfix');"))

    def test_parseint_no_leading_digits(self):
        self.assertEqual("parseInt('abc');", self._simplify("parseInt('abc');"))

    def test_parseint_hex_radix_folded(self):
        self.assertEqual('255;', self._simplify("parseInt('0xFF', 16);"))

    def test_parseint_binary_radix(self):
        self.assertEqual('2;', self._simplify("parseInt('10', 2);"))

    def test_parseint_unknown_radix_preserved(self):
        self.assertEqual("parseInt('ff', radix);", self._simplify("parseInt('ff', radix);"))

    def test_from_char_code_direct(self):
        self.assertEqual("'GET';", self._simplify('String.fromCharCode(71, 69, 84);'))

    def test_iife_inline_comparison(self):
        self.assertEqual(
            'false;',
            self._deobfuscate("(function(a, b) { return a === b; })('x', 'y');"),
        )

    def test_iife_inline_nested(self):
        source = (
            "if ((function(a, b) { return a !== b; })('VpDUG', 'ULVFR'))"
            " { live(); } else { dead(); }"
        )
        self.assertEqual('live();', self._deobfuscate(source))

    def test_iife_inline_member_access_arg(self):
        source = "var r = (function(a, b) { return a < b; })(x, y.length);"
        self.assertEqual('var r = x < y.length;', self._simplify(source))

    def test_iife_inline_computed_member_arg(self):
        source = "var r = (function(a, b) { return a <= b; })(arr[0], x);"
        self.assertEqual('var r = arr[0] <= x;', self._simplify(source))

    def test_iife_preserves_conditional_effectful_arg(self):
        source = "var r = (function(a, b) { return a || b; })(x, y.z);"
        expected = 'var r = (function(a, b) {\n  return a || b;\n})(x, y.z);'
        self.assertEqual(expected, self._simplify(source))

    def test_iife_preserves_reordered_effectful_args(self):
        source = "var r = (function(a, b) { return b + a; })(x.y, z.w);"
        expected = 'var r = (function(a, b) {\n  return b + a;\n})(x.y, z.w);'
        self.assertEqual(expected, self._simplify(source))

    def test_nullish_coalescing_undefined(self):
        self.assertEqual("'default';", self._simplify("undefined ?? 'default';"))

    def test_logical_and_undefined(self):
        self.assertEqual('undefined;', self._simplify("undefined && 'world';"))

    def test_logical_or_undefined(self):
        self.assertEqual("'fallback';", self._simplify("undefined || 'fallback';"))


class TestDeadCodeLiteralConditions(TestJsDeobfuscator):

    def test_if_zero_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if (0) { dead(); } else { live(); }'))

    def test_if_empty_string_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if ("") { dead(); } else { live(); }'))

    def test_if_null_eliminates_consequent(self):
        self.assertEqual('live();', self._deadcode('if (null) { dead(); } else { live(); }'))

    def test_if_nonzero_keeps_consequent(self):
        self.assertEqual('live();', self._deadcode('if (1) { live(); } else { dead(); }'))

    def test_if_nonempty_string_keeps_consequent(self):
        self.assertEqual('live();', self._deadcode("if ('x') { live(); } else { dead(); }"))

    def test_ternary_zero(self):
        self.assertEqual("var x = 'b';", self._simplify("var x = 0 ? 'a' : 'b';"))

    def test_ternary_nonempty_string(self):
        self.assertEqual("var x = 'a';", self._simplify("var x = 'yes' ? 'a' : 'b';"))

    def test_if_zero_no_else_removed(self):
        self.assertEqual('', self._deadcode('if (0) { dead(); }'))

    def test_if_undefined_eliminates_consequent(self):
        self.assertEqual(
            'live();',
            self._deadcode('if (undefined) { dead(); } else { live(); }'),
        )

    def test_ternary_undefined(self):
        self.assertEqual("var x = 'b';", self._simplify("var x = undefined ? 'a' : 'b';"))


class TestObjectFold(TestJsDeobfuscator):

    def test_string_property_inlined(self):
        self.assertEqual(
            "x('hello');",
            self._objectfold("var o = {'k': 'hello'}; x(o['k']);"),
        )

    def test_function_wrapper_inlined(self):
        self.assertEqual(
            'var r = 1 + 2;',
            self._objectfold("var o = {'f': function(a, b) { return a + b; }}; var r = o['f'](1, 2);"),
        )

    def test_mutated_object_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { 'k': 'hello' };
                o = other;
                x(o['k']);
                """
            ),
            self._objectfold("var o = {'k': 'hello'}; o = other; x(o['k']);"),
        )

    def test_non_literal_key_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { [expr]: 'hello' };
                x(o[expr]);
                """
            ),
            self._objectfold("var o = {[expr]: 'hello'}; x(o[expr]);"),
        )

    def test_multiple_properties(self):
        source = (
            "var o = {'a': 'hello', 'b': ', ', 'c': function(x, y) { return x + y; }};"
            " var r = o['c'](o['a'], o['b']);"
        )
        self.assertEqual(
            "var r = 'hello' + ', ';",
            self._objectfold(source),
        )

    def test_object_with_method_kind_skipped(self):
        self.assertEqual("'hello';", self._objectfold("var o = {'k': 'hello'}; o.k;"))

    def test_generated_medium_object_fold(self):
        result = self._objectfold(
            r"function classify(_0xc9c876){var _0x159b71={'QUMXw':function(_0x794a00,_0x30c617){return _0x794a00<_"
            r"0x30c617;},'smFRR':function(_0x56d1ff,_0x5094f9){return _0x56d1ff>_0x5094f9;},'KVVfA':'positive','nQ"
            r"fTZ':function(_0x50e61b,_0x19cfc3){return _0x50e61b<_0x19cfc3;},'YFNps':'negative','uvdVt':'zero'};v"
            r"ar _0xc3dbcf=[];for(var _0x254ae8=0x0;_0x159b71['QUMXw'](_0x254ae8,_0xc9c876['length']);_0x254ae8++)"
            r"{var _0xe54f7c=_0xc9c876[_0x254ae8];if(_0x159b71['smFRR'](_0xe54f7c,0x0)){_0xc3dbcf['push'](_0x159b7"
            r"1['KVVfA']);}else if(_0x159b71['nQfTZ'](_0xe54f7c,0x0)){_0xc3dbcf['push'](_0x159b71['YFNps']);}else{"
            r"_0xc3dbcf['push'](_0x159b71['uvdVt']);}}var _0x51ec37=_0xc3dbcf['length'];return{'items':_0xc3dbcf,'"
            r"total':_0x51ec37};}"
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function classify(_0xc9c876) {
                  var _0xc3dbcf = [];
                  for (var _0x254ae8 = 0x0; _0x254ae8 < _0xc9c876['length']; _0x254ae8++) {
                    var _0xe54f7c = _0xc9c876[_0x254ae8];
                    if (_0xe54f7c > 0x0) {
                      _0xc3dbcf['push']('positive');
                    } else {
                      if (_0xe54f7c < 0x0) {
                        _0xc3dbcf['push']('negative');
                      } else {
                        _0xc3dbcf['push']('zero');
                      }
                    }
                  }
                  var _0x51ec37 = _0xc3dbcf['length'];
                  return { 'items': _0xc3dbcf, 'total': _0x51ec37 };
                }
                """
            ),
            result,
        )

    def test_multi_declarator(self):
        source = "var x = 1, o = {'k': 'hello'}, y = 2; z(o['k']);"
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1, y = 2;
                z('hello');
                """
            ),
            self._objectfold(source),
        )

    def test_partial_key_coverage(self):
        source = "var o = {'a': 'hello', 'b': 'world'}; x(o['a']); y(o['missing']);"
        self.assertEqual(
            inspect.cleandoc(
                """
                x('hello');
                y(undefined);
                """
            ),
            self._objectfold(source),
        )

    def test_dynamic_key_preserves_object(self):
        source = "var o = {'a': 'hello', 'b': 'world'}; x(o['a']); y(o[z]);"
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { 'a': 'hello', 'b': 'world' };
                x('hello');
                y(o[z]);
                """
            ),
            self._objectfold(source),
        )

    def test_contextual_keyword_as_parameter(self):
        """
        The contextual keyword `as` is valid as an identifier. Object fold must inline comparison
        functions that use `as` as a parameter name.
        """
        source = "var o = {'f': function(as, at) { return as < at; }}; var r = o['f'](x, 3);"
        self.assertEqual('var r = x < 3;', self._objectfold(source))


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
            var _order = '1|0|2'.slice('|');
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


class TestAntiDebug(TestJsDeobfuscator):

    _DEFENSE_CODE = (
        "var a = (function() {"
        "  var b = true;"
        "  return function(c, d) {"
        "    var e = b ? function() {"
        "      if (d) { var f = d.apply(c, arguments); return d = null, f; }"
        "    } : function() {};"
        "    return b = false, e;"
        "  };"
        "}()), g = a(this, function() {"
        "  return g.toString().search('(((.+)+)+)+$')"
        "    .toString().constructor(g).search('(((.+)+)+)+$');"
        "});"
    )

    def test_remove_self_defending_redos(self):
        source = self._DEFENSE_CODE + (
            "g();"
            "console.log('hello');"
        )
        self.assertEqual(self._deobfuscate(source), "console.log('hello');")

    def test_preserves_code_without_redos(self):
        source = "var x = 1; console.log(x);"
        self.assertEqual(self._deobfuscate(source), 'console.log(1);')

    def test_redos_factory_preserved_when_referenced(self):
        source = self._DEFENSE_CODE + (
            "g();"
            "var other = a(this, function() { return 42; });"
            "console.log(other);"
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = function() {
                  var b = true;
                  return function(c, d) {
                    var e = b ? function() {
                      if (d) {
                        var f = d.apply(c, arguments);
                        return d = null, f;
                      }
                    } : function() {};
                    return b = false, e;
                  };
                }();
                var other = a(this, function() {
                  return 42;
                });
                console.log(other);
                """
            ),
            self._deobfuscate(source),
        )


class TestConstantInlining(TestJsDeobfuscator):

    def test_literal_string_inlined(self):
        self.assertEqual("console.log('hello');", self._inline("var x = 'hello'; console.log(x);"))

    def test_literal_number_inlined(self):
        self.assertEqual('console.log(42);', self._inline('var x = 42; console.log(x);'))

    def test_literal_boolean_inlined(self):
        self.assertEqual('console.log(true);', self._inline('var x = true; console.log(x);'))

    def test_reassigned_variable_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'a';
                x = 'b';
                console.log(x);
                """
            ),
            self._inline("var x = 'a'; x = 'b'; console.log(x);"),
        )

    def test_mutated_variable_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                x++;
                console.log(x);
                """
            ),
            self._inline('var x = 1; x++; console.log(x);'),
        )

    def test_single_use_expression_inlined(self):
        self.assertEqual('return a + b;', self._inline('var x = a + b; return x;'))

    def test_multi_use_expression_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = a + b;
                console.log(x);
                return x;
                """
            ),
            self._inline('var x = a + b; console.log(x); return x;'),
        )

    def test_call_init_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = f();
                return x;
                """
            ),
            self._inline('var x = f(); return x;'),
        )

    def test_member_access_init_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = a.b;
                return x;
                """
            ),
            self._inline('var x = a.b; return x;'),
        )

    def test_does_not_cross_function_boundary(self):
        source = (
            "var x = 'outer';"
            'function f() { return x; }'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'outer';
                function f() {
                  return x;
                }
                """
            ),
            self._inline(source),
        )

    def test_function_body_processed(self):
        source = (
            'function f() {'
            "  var x = 'hello';"
            '  return x;'
            '}'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 'hello';
                }
                """
            ),
            self._inline(source),
        )

    def test_long_string_not_duplicated(self):
        long_str = 'a' * 100
        source = F"var x = '{long_str}'; console.log(x); alert(x);"
        self.assertEqual(
            inspect.cleandoc(
                F"""
                var x = '{long_str}';
                console.log(x);
                alert(x);
                """
            ),
            self._inline(source),
        )

    def test_expression_with_mutated_identifier_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var y = a + b;
                a = 99;
                return y;
                """
            ),
            self._inline('var y = a + b; a = 99; return y;'),
        )

    def test_const_array_element_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                x['push']('a');
                if (y === 0) {}
                """
            ),
            self._inline("const p = [0, 'push']; x[p[1]]('a'); if (y === p[0]) {}"),
        )

    def test_const_array_numeric_element(self):
        self.assertEqual('f(42);', self._inline('const p = [42]; f(p[0]);'))

    def test_const_pool_declaration_removed(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                f(0);
                g('push');
                h(0xff);
                """
            ),
            self._inline("const pool = [0, 'push', 0xff]; f(pool[0]); g(pool[1]); h(pool[2]);"),
        )

    def test_var_array_not_inlined_across_functions(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var p = ['a'];
                function f() {
                  return p[0];
                }
                """
            ),
            self._inline("var p = ['a']; function f() { return p[0]; }"),
        )

    def test_const_array_inlined_across_functions(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 'a';
                }
                """
            ),
            self._inline("const p = ['a']; function f() { return p[0]; }"),
        )

    def test_non_literal_array_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [a, 1];
                f(p[0]);
                """
            ),
            self._inline('const p = [a, 1]; f(p[0]);'),
        )

    def test_out_of_bounds_index_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [1, 2];
                f(p[999]);
                """
            ),
            self._inline('const p = [1, 2]; f(p[999]);'),
        )

    def test_non_numeric_index_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [1, 2];
                f(p[x]);
                """
            ),
            self._inline('const p = [1, 2]; f(p[x]);'),
        )

    def test_forin_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for (x in obj) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for (x in obj) {} console.log(x);"),
        )

    def test_forof_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for (x of arr) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for (x of arr) {} console.log(x);"),
        )

    def test_array_destructuring_marks_mutated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                [x] = getValues();
                console.log(x);
                """
            ),
            self._inline("var x = 'hello'; [x] = getValues(); console.log(x);"),
        )

    def test_object_destructuring_marks_mutated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                ({ y: x } = getValues());
                console.log(x);
                """
            ),
            self._inline("var x = 'hello'; ({y: x} = getValues()); console.log(x);"),
        )

    def test_function_declaration_id_not_replaced(self):
        source = inspect.cleandoc(
            """
            function outer() {
                const x = void 0;
                function inner() {
                    function x() { return 1; }
                    return x();
                }
                return inner();
            }
            """
        )
        result = self._inline(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  const x = void 0;
                  function inner() {
                    function x() {
                      return 1;
                    }
                    return x();
                  }
                  return inner();
                }
                """
            ),
            result,
        )


class TestConstantPoolIntegration(TestJsDeobfuscator):

    def test_individual_duplicateLiteralsRemoval(self):
        source = inspect.cleandoc(
            """
            const q = [0, "push"];
            function fizzbuzz(n) {
              var results = [];
              for (var i = 1; i <= n; i++) {
                if (i % 15 === q[0]) {
                  results[q[1]]('FizzBuzz');
                } else {
                  if (i % 3 === q[0]) {
                    results[q[1]]('Fizz');
                  } else {
                    if (i % 5 === q[0]) {
                      results[q[1]]('Buzz');
                    } else {
                      results[q[1]](i);
                    }
                  }
                }
              }
              return results;
            }
            console["log"](fizzbuzz(20));
            """
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            console.log([1, 2, 'Fizz', 4, 'Buzz', 'Fizz', 7, 8, 'Fizz', 'Buzz', 11, 'Fizz', 13, 14, 'FizzBuzz', 16, 17, 'Fizz', 19, 'Buzz']);
            """
        ))


class TestDispatcherUnwrapping(TestJsDeobfuscator):

    def _make_dispatcher(self, dict_lines: list, tail_lines: list):
        return '\n'.join((
            'var c = Object["create"](null);',
            'var p;',
            'function d(name, flag, rtype, lengths) {',
            '  var output;',
            '  var fns = {',
            *dict_lines,
            '  };',
            '  if (flag === "initF") { p = []; }',
            '  if (flag === "createF") {',
            '    output = c[name] || (c[name] = fns[name]);',
            '  } else {',
            '    output = fns[name]();',
            '  }',
            '  if (rtype === "wrapF") { return { "wk": output }; }',
            '  else { return output; }',
            '}',
            'function stub() {}',
            *tail_lines,
        ))

    def test_single_function_direct_call(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"abc": function() { var [x] = p; return x + 1; }'
            ],
            tail_lines=[
                'console.log((p = [5], d("abc")));'
            ]
        )
        self.assertEqual('console.log(6);', self._deobfuscate(source))

    def test_multi_function_dispatcher(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"f1": function() { var [a, b] = p; return a + b; },',
                '"f2": function() { var [a, b] = p; return a * b; }',
            ],
            tail_lines=[
                'var x = (p = [2, 3], d("f1"));',
                'var y = (p = [x, 4], d("f2"));',
                'console.log(y);',
            ]
        )
        self.assertEqual('console.log(20);', self._deobfuscate(source))

    def test_wrapped_reference(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"id": function() { var [x] = p; return x; }',
            ],
            tail_lines=[
                'var fn = new d("id", "createF", "wrapF")["wk"];',
                'console.log(fn(42));',
            ]
        )
        self.assertEqual('console.log(42);', self._deobfuscate(source))

    def test_boilerplate_removal(self):
        source = self._make_dispatcher(
            dict_lines=[
                '"k": function() { return 42; }',
            ],
            tail_lines=[
                'console.log(d("k"));'
            ]
        )
        result = self._deobfuscate(source)
        self.assertEqual('console.log(42);', result)


class TestRegressions(TestJsDeobfuscator):

    def test_dead_code_spliced_parent_pointers(self):
        """
        After dead code elimination splices statements out of a block, the surviving statements
        must have their parent pointer set to the containing script node, not the removed block.
        """
        ast = JsParser('if (true) { var a = 1; var b = 2; }').parse()
        t = JsDeadCodeElimination()
        t.visit(ast)
        self.assertTrue(t.changed)
        for stmt in ast.body:
            self.assertIs(stmt.parent, ast)

    def test_ternary_resolved_by_simplifications_alone(self):
        self.assertEqual("var x = 'a';", self._simplify("var x = true ? 'a' : 'b';"))

    def test_objectfold_var_in_nested_block_not_removed(self):
        """
        A `var` declaration inside a nested block is function-scoped in JavaScript. If the variable
        is referenced outside the block, the object must not be folded away.
        """
        source = (
            "function f() {"
            "  if (true) { var o = {'k': 'hello'}; x(o['k']); }"
            "  return o['k'];"
            "}")
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  if (true) {
                    var o = { 'k': 'hello' };
                    x(o['k']);
                  }
                  return o['k'];
                }
                """
            ),
            self._objectfold(source),
        )


class TestStringConcealing(TestJsDeobfuscator):

    _ALPHABET = '0,Fz)`Q(lH=j5gK[i8~mJt_b&qr/fW^Y2]?#|@.!$cLZ9BN>A1o7ye+D%IM}O6;pV:P*E3CRnxXSh{wvaTUuk4G"s<d'

    @staticmethod
    def _decode_js(name: str, alphabet: str, indent: int = 4) -> list[str]:
        p = ' ' * indent
        return [
            F'function {name}(str) {{',
            F'{p}var alpha = "{alphabet}";',
            F'{p}var raw = "" + (str || "");',
            F'{p}var len = raw.length;',
            F'{p}var ret = [];',
            F'{p}var b = 0, n = 0, v = -1;',
            F'{p}for (var i = 0; i < len; i++) {{',
            F'{p}    var p = alpha.indexOf(raw[i]);',
            F'{p}    if (p === -1) continue;',
            F'{p}    if (v < 0) {{ v = p; }}',
            F'{p}    else {{',
            F'{p}        v += p * 91;',
            F'{p}        b |= v << n;',
            F'{p}        n += (v & 8191) > 88 ? 13 : 14;',
            F'{p}        do {{ ret.push(b & 0xff); b >>= 8; n -= 8; }} while (n > 7);',
            F'{p}        v = -1;',
            F'{p}    }}',
            F'{p}}}',
            F'{p}if (v > -1) {{ ret.push((b | v << n) & 0xff); }}',
            F'{p}return bufferToString(ret);',
            '}',
        ]

    @staticmethod
    def _access_js(
        name: str,
        cache: str,
        decoder: str,
        table: str = 'table',
        indent: int = 4,
    ) -> list[str]:
        p = ' ' * indent
        q = "'" if indent == 4 else '"'
        return [
            F'function {name}(index) {{',
            F'{p}if (typeof {cache}[index] === {q}undefined{q}) {{',
            F'{p}    return {cache}[index] = {decoder}({table}[index]);',
            F'{p}}}',
            F'{p}return {cache}[index];',
            '}',
        ]

    _ESCAPED_ALPHABET = _ALPHABET.replace('"', '\\"')

    def _minimal_sample(self) -> str:
        return '\n'.join([
            'var cache = {};',
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'var results = [];',
            'results[accessor(10)]("hello");',
            'console[accessor(12)](results);',
        ])

    def test_base91_decode(self):
        self.assertEqual(_decode_base91('fOg=r', self._ALPHABET), 'push')
        self.assertEqual(_decode_base91('lrCD^', self._ALPHABET), 'Fizz')
        self.assertEqual(_decode_base91('#ZlH', self._ALPHABET), 'log')

    def test_accessor_calls_resolved(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache = {};
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            result,
        )

    def test_decoder_and_accessor_removed(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache = {};
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            result,
        )

    def test_property_access_rewritten(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache = {};
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            result,
        )

    def test_full_fizzbuzz_sample(self):
        source = lzma.decompress(base64.b85decode(
            "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3H2DoLvAj9ZCPGVfzyXn;9}d7=bd;P-u|=hS4y!t6q`3iYd7Jn@gb<iH1XeW)Th&veG?%"
            "YwBK2@+d2^J$YeG%M4UKdAGD!4GsZVt`^bppHR_iV0FXK*h#6x)K@pE_d426aHY}ck*@-Z<qci=bK`7R;<|B{jy#q`0RF-r89E<6"
            "0NR8U5LQ4+SMYp0!@U)YE9aZ2<C1H(i)Ja=td{a`jBi3Pw2b`|RxTgt!Zt?T5A+=vwd3}<`A_)<#%0j}rE<Uyze9OMpIYM_yB$8f"
            "lFYLgihO@M;R;Yy*bT@NU~MBn!72xabk|YC97+%~)WLf?Y31`n`4ox#nBkldkM-DO_pL|x_|x!m_#cR+AoS4U(gq!N;y|W&li7Dr"
            "nYt}Xh@0~yU}Ie{%l!DLhXZjK38YEcGr#;06*+dTW*|Z4IzC30a<XYwiSyWmZ}o_yAuFJtrYSq`eeQ43_^zW{lURqRypcD{vD6vs"
            "ZgMB2f5zJhsbiAW`Y#5wMJTkZM>0fs6cOIh^{+7~Ig)3?Djuny%SQBcKsJRv=F7ruU2*G%D#|>zbUHn>Urfsomq_Ow_7nSzY+=QJ"
            "qKGT85z=|d<@mT@WM7Atb3#%oC0z()pmE1X)6i)v^dc4Ul?qPRc8U#lYArH4)y0K*XCKu;;p_0(4S#^zKK$Y@;IeB{ZJpIu(~!;W"
            "8<!)^wVux4hdJf(L_xS$salx~v4bQa(3!!Xy7(&+L-5#k7ikmuP?%8^UQ*yW<nGbs!VC3r>r(wyrB8qJ{Ls2Y6p9Ne%sujz-usGQ"
            "SK`pcyy5RsI;t>-f!$B=F7J#rnKYIh1w+T@kkEH_0*gleI<#_B7||ICyQ=*v580&)bSy0xY@cTsg1Eu1=hVH|U8c6G+-#JiKvY*m"
            "#%7EGFYA~v_;R^tyZ43gYt7<l0t^U7;z)BT6Qq7eMO-NLyn-toN#j%~F23{p40Q$ppFVcrV1feuAN&I=5KB7GF;N3;{mcZHyDdM2"
            "24j$QODP9r|0ic>%L6`AC^ca^_ZQl)Th04=QV>#g4Cu>+P9L?fSp@$hP<eR}RzF|DxYkyb53yuALn<zvvnj5)TbLyz0}F)qH`!@5"
            "L;hN8?f<4@5sx2SSR@zz7L5fTHT!d(p<FLE=*EUw3z-~=H;L&9tqqrZUsZ1O0EfjhA#VWv6@%<<4q%diHkFJRf%U$z2&Yd2wx~}N"
            "8GKlrJ#x1trcK?{NLZ0A0B1TMN6Bk<W3nGrVQT^LI!^)figyO`8+$zJTU!;hd+K;G|1j?R1N8TI4R}vUzL;{_?g_gZacLo_LUM}<"
            "e`RZmxr?u2wsxBptfS5+O+d5;24<1Gv@0?G|3etT#Ww*ks)etI@<$>$Yqw@i9uQY(AY*3W{yRsW4(nMlXKV>i#8_&Ipg8z%o&FZg"
            "nOAfqHNKzTjXbyciwn7sv|i`<r*uv+dgSod5T-hS7*`d2bzXuEF*Ft^1Frk%^HOVh{yusXFXIoZz<Nset6Iyv<K@pR-!Q$&x$kfS"
            "W!Pm^N+dZa^F))r`If9OV>mtcY5WIxKo*R*=E3`#PJ9EL&&6UT7hxR`$XWdc@Ewd2U(xpH<Os^P=<}aa+;Z8H5{B6?&9gC-80`sV"
            "ISjF44et8`pYu>m*(C(A9k`T<O9rQ@7i$=lY=OE^WfCk-)JKEcUn3h+v-|GbcA7a;CWHsB$6eh#o`eY}wl5cja*f|l4)WHRT9`d_"
            "2`gyKRbWSEvL5I!CE?yx?P$n0JbjEfK4lt_<WUW!0mP>*WZy<vF;*zH2MQBr?FSx>S8pMts~UH*f$G+f66qzov+O(Hfp<)TRlz3f"
            "+%K8ebvZ>bNk(tU7f^nW<`xg7HyvS6?jU#a&ZzOrw`FT2)Og@RAy6UO9f+2DpF~6c8Pmf`Ko%a#>15r%4vxTQ_j5G?oFL2n#R1Ua"
            "JWaG+-Q5@^)e;rae;3~G623vIL(=(6ITQuGl;SKodlc_WV}2f(zF>M#_ZlbwEcnwcU~C*$LeJe=*Ni#2l-T^#;I3v5$5};p1Ah=i"
            "tTuAI+&Jjv@ia5(TZsg~6p(dNrLq!h;Y}g-txi}K2mrVZpfUN!UB!J1fW64J>;&gWXo^S;0|2bt2KJc1WMz8q5QNFoEFhYEZSZNx"
            "6HP&s%<fjD^mV5;xOlOgXC`Tn{?#WJvcUvx@ODT+6q)|&@5F&Ya7t>4Y98xnquQe?nd%?lAiiTehcq5A`6O+5w<17tXm6?3k?+i9"
            "G^1advdX4vJ_+s+L2n0n98k@`EW;~(LlSc!Ac}!u64*|C$brcSR|EX@AEk?I?|*(d-2CHZTd<%4U^uq0p{4uZ_9luHcvIpsoJcys"
            "ll{2_al}beNxRr#v*AoDi)SyZVZ}9JgADq^zA$wh+fSOSiPzJF7XS#nZdLXGW#9vR8<d_`_no8nS$Oqeii%>u6$crna8nv9Is;)0"
            "!0<<$?wjkivufO0P5PVwY9nv(oV&7BaUeXk1HY!`uTAiMQ$m=z09cdwbsk^4en8P0i>y`^LS7AXzMZ0=J|c;=36@kEG_XYS4+A<P"
            "ww5j5YLdZ3ZO#E%2OU&N{)CJl<|efQTPn-ZOsG)I$t<-Dv0{)0{!jZB%s4z}-Y|BEFFK&T?SEan;gZZamc&<8-Eq%V%2P}3dBmYc"
            "^yMOS(6p7xu+k!t16w@H>;?jX{WJ|v>qS1y{YbbFl_<<;`=!HHJXduBFRd8-G~=5G<2H*C-$fZ4mqBu4>YOWvzbfS=l&i64`07Qt"
            "QKmyegh4)u2lLW@>!-bM3Nh?4RiiqrmInTCMXWxJk25%ABW>H4tVQ+H3%-;_2=ds>=&DwZl#7}&yHPZRoo=q&*89ut<GlJQ5uesi"
            "!tapVwZ&^nz>Z@*$gaB~FgbV?6J8!&d+(p8(}2q}ccMkaX$5lokEWlWPf$EWT@>OUqPR!2mOGB6!?o#V&(`Y>5QkDBQFTf~Dk|Ns"
            "G$dD3{**Ri^B?9Rm0x<lW#9!cY>=Z4S;QVg4_MJKYDfz^Tx9Clhibw7{sEDYfNkw%w&>C)aKqF&JG+C)mo014pvMD|Y94)SFcg+s"
            "m`mddGz*<{&b3qmCnYed_ZB6UaV=llt|U}6e4I)B8)hK7%0@b%Ld`eS%_3{DU<#!Mk4s&@wHB0t+AB}a;UyAFm)gZ*o6|N0fsc6i"
            "5j3&3a(pklsrt<se!<N37tDXfEcjicg3QCahc^g6WpU<OAugoO^|p(vL*)tk&a(NNe%Z(R)$Rv9Ox0D9aVBL%V6)pRN23qOd=+4U"
            "r8eCWH6GiSpoTN((IV$}_N?el9<+iJ<4T*lZWvh5J9I$7jd`>2xLRua!FtW_b8-}XrDfG?%FJlTpYnvRA((&zmsD{}h1BZCqAj3K"
            "-%|W;7qO40wvE)RPFbr}yS3@l71F?tPz=P^(?RdWf+}GpQ02-X!$Sbh#+dW;C0>@t(yMQ;YC*!7p2P|6F_`Br$~C05*;h^E!HoEW"
            "e11FC{#NUcxG>vMtOtTAFd7FR=~bar+;L7Kg~w%Al4>9oiA7YEEG3$$o0ob#S3NnhP-+Gp1}v+xRr#P^<(3}ew<^vhuB1aZlm(+G"
            "XOXP>gN5afXcDiPyh<BKncp~F&i~lNU&73g1&|6ipi8KU{})>gdwK`738?hqmY8c4w$ILEG~}<I+4|g5;z8A#qQ;SA;;__K3E*rg"
            "2Y5XkANO!X>_A)Z<#gXb@8NMK{<ez69eA)HN$q6}!=hzF7>{q*1wm<}zFDYLGmajv3gP6c{-zcaK<Am>p{}EPz~B~GH<%E-gS#ke"
            "A!ui?mwK7c`!q^WBG>i^PmhfN;Ii~+A4iaN{@)86vM1|YDky>~#ZfpEiq*>ohnP_!hahKphd~@zO#VS_aO2l#5<3pn-4@~Txsqtc"
            "yn98ijRPDB1|}5;cs|D!a}+z44@;i;MXt4!_PIV&lV+ogZJ>8#-0wK?@%I|ieO8XhCLaikzy_IxZD!~fc)E^!sky1$6y-v1m(({|"
            "f-P@Ooe07?CHhOH#&Sj=p6di~z9QJ^WN7LdL&UZbGhHT5#7%|-qky$8+JZ2(Vh8yb%e@`B$jF%Bvv=Wk&5F%DfnBR|IJf0g?$Rat"
            "=o=&VuGQo?rMtGr!H|Jy!9#2Vttb|<CvZ!L+AnfqvnNYdwNioB6NPYn631GWF(3J>U$lrIjDumiUw6j?3b{#dSWe~mulIqibry04"
            "`2c|te*=f7)2X!9v0~`ghbh`NYOM)bxdu7Cg7<+crR{r1!qRhv_S;i;U&01B0KBh3Wf0&4D*_TdK_Z|rr6JG43@!Ru1M-tuYtn0@"
            "|ELS8eH9OJV|y%;!|UF?gn+RGw%@fYl4n;&uIO;jdyY6sWpEwgsQs6q7_|Z^&4NZ}xFHxVxfZJRaK{ZVyxzrY3(WD4FrY{#nBYCe"
            "T0QURTLwvSXW|Cl@NPAOGK+tBjg8(e`LyCYj*7%Y6qWXsf@+{zv=Y+Kwu&t2`Tyq1e48N{zWRN;l(m3T|BNYiVA6|fdriE-4v|?P"
            "{Appfr+r_$ZebnK{ckz+WmPD45=SR?bn@_!X*UQ;O!{q$7S{TTTMc%1^}uHZh00ZCH(RZ16{$*|_u_ppM?aY9yYr<1!TSi7HJ`u|"
            "&822Yz)LIuTag|tC9F%~7J#M37rekRDy_Hx>EBK6wyqj2J}6*v3@E2)87c1NV!B4=Ks^Uz!pvDZ#*CWLyjasxTJ7ihJJn_Z&l_U!"
            "04;Bg)j5#R(yeWP92Ure3n18;2Nlues$t43FU!vE=HSF=%twf;sNfdwq)|4alu`3ryXyl-!8GedmY2adU7B-hFpWQWt-}A;=}xX)"
            "Xb^`%f~m-kYjv9SNuxHAg(MM7ED<>BpKzaO{_ktZ;_Apj@ThO_>Pdn!5i?l9=#N{UfvZ)4US&_8ImIzrgFe-CTk+8Jo}#g+c*NQ2"
            "3uH-2h8S9j5gaW!<R?RCj4%E_aB}Q-$Eu??D2Z4=4y|CnQajE%5OC(rMYvnwLH5j60X{d(4A3|RxXo)1|MsSX4&(hjOIS1221;E)"
            "nb(gf4mErZ;J?VGGcz`5QFp!o{-$Tq8{0!cWR0UeOnMD$s&{9z;Ck)vH_cox7)@1(?vLXN+JV1HV7fJ=AEcU~^Ba0ru@Cvr0=ZBm"
            "%bQGS=ej;30)^>|*f5s$S)&3YOdG{R<Zr|PITBM2o}hXT00Fok&_)0NeGNZ_vBYQl0ssI200dcD"
        )).decode('utf8')
        result = self._deobfuscate(source)
        self.assertIn("'FizzBuzz'", result)
        self.assertIn("'Fizz'", result)
        self.assertIn("'Buzz'", result)
        self.assertIn('console.log', result)

    def test_scope_aware_decoder_pairing(self):
        """
        When the same decoder function name is reused in nested scopes with different alphabets,
        each accessor must pair with its sibling decoder — not a same-named decoder from a
        different scope. This regression test uses two alphabets (original and reversed) so
        cross-decoding fails with UnicodeDecodeError.
        """
        alpha1 = '0,Fz)`Q(lH=j5gK[i8~mJt_b&qr/fW^Y2]?#|@.!$cLZ9BN>A1o7ye+D%IM}O6;pV:P*E3CRnxXSh{wvaTUuk4G"s<d'
        alpha2 = alpha1[::-1]
        # Verify the test fixture is meaningful: cross-decode must NOT produce 'push'
        self.assertNotEqual(_decode_base91('fOg=r', alpha2), 'push')
        esc1 = alpha1.replace('"', '\\"')
        esc2 = alpha2.replace('"', '\\"')
        source = '\n'.join([
            # Shared string table: idx 10="push" (alpha1), idx 11="log" (alpha1)
            # idx 12="push" (alpha2), idx 13="log" (alpha2)
            'var table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","#ZlH",";^{aV","D>UT"];',
            # --- outer scope: decoder with alpha1, accessor pairing ---',
            'var cache1 = {};',
            *self._decode_js('dec', esc1),
            *self._access_js('acc', 'cache1', 'dec'),
            'var results = [];',
            'results[acc(10)]("hello");',
            'console[acc(11)](results);',
            # --- inner scope: same decoder+accessor names, alpha2 ---',
            'function inner() {',
            '    var cache2 = {};',
            *[F'    {line}' for line in self._decode_js('dec', esc2, indent=8)],
            *[F'    {line}' for line in self._access_js('acc', 'cache2', 'dec', indent=8)],
            '    var items = [];',
            '    items[acc(12)]("world");',
            '    console[acc(13)](items);',
            '}',
            'inner();',
        ])
        result = self._deobfuscate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache1 = {};
                var results = [];
                results.push("hello");
                console.log(results);
                function inner() {
                  var items = [];
                  items.push("world");
                  console.log(items);
                }
                inner();
                """
            ),
            result,
        )

    def test_assignment_table_removed_even_if_not_var(self):
        source = '\n'.join([
            'var table;',
            'var cache = {};',
            'table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","lrCD^","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'var results = [];',
            'results[accessor(10)]("hello");',
            'console[accessor(12)](results);',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache = {};
                var results = [];
                results.push("hello");
                console.log(results);
                """
            ),
            self._deobfuscate(source),
        )

    def test_assignment_table_with_shadowing(self):
        source = '\n'.join([
            'var table;',
            'var cache = {};',
            'table = ["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj",'
            '"fOg=r","#ZlH"];',
            *self._decode_js('decode', self._ESCAPED_ALPHABET),
            *self._access_js('accessor', 'cache', 'decode'),
            'console[accessor(11)](accessor(10));',
            'function inner() {',
            '    var table = [1, 2, 3];',
            '    return table;',
            '}',
            'console.log(inner());',
        ])
        self.assertEqual(
            inspect.cleandoc(
                """
                var cache = {};
                console.log('push');
                console.log([1, 2, 3]);
                """
            ),
            self._deobfuscate(source),
        )


class TestUnusedCodeRemoval(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    def test_uncalled_function_removed(self):
        source = inspect.cleandoc(
            """
            function alive() { return 1; }
            function dead() { return 2; }
            console.log(alive());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function alive() {
                  return 1;
                }
                console.log(alive());
                """
            ),
        )

    def test_transitive_reachability(self):
        source = inspect.cleandoc(
            """
            function helper() { return 42; }
            function main() { return helper(); }
            function orphan() { return 99; }
            console.log(main());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function helper() {
                  return 42;
                }
                function main() {
                  return helper();
                }
                console.log(main());
                """
            ),
            self._remove_unused(source),
        )

    def test_identifier_as_value_makes_reachable(self):
        source = inspect.cleandoc(
            """
            function callback() { return 1; }
            function unused() { return 2; }
            var x = callback;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function callback() {
                  return 1;
                }
                var x = callback;
                """
            ),
            self._remove_unused(source),
        )

    def test_all_functions_unreachable_keeps_them(self):
        source = inspect.cleandoc(
            """
            function a() { return 1; }
            function b() { return 2; }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function a() {
                  return 1;
                }
                function b() {
                  return 2;
                }
                """
            ),
        )

    def test_nested_dead_code_in_block(self):
        source = inspect.cleandoc(
            """
            function main(n) {
              if (n > 0) {
                function dead_inside() { return "sha256"; }
                return n * 2;
              }
              return 0;
            }
            console.log(main(5));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function main(n) {
                  if (n > 0) {
                    return n * 2;
                  }
                  return 0;
                }
                console.log(main(5));
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_assignment_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            x = {};
            console.log("hello");
            """
        )
        self.assertEqual(self._remove_unused(source), 'console.log("hello");')

    def test_cascading_dead_variables(self):
        source = inspect.cleandoc(
            """
            var alpha, beta, gamma;
            alpha = {};
            beta = alpha.foo;
            gamma = alpha.bar || beta;
            console.log("live");
            """
        )
        self.assertEqual(self._remove_unused(source), 'console.log("live");')

    def test_shadowed_param_does_not_prevent_removal(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 42;
            function foo(x) { return x + 1; }
            console.log(foo(10));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function foo(x) {
                  return x + 1;
                }
                console.log(foo(10));
                """
            ),
            self._remove_unused(source),
        )

    def test_live_variable_preserved(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 42;
            console.log(x);
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                x = 42;
                console.log(x);
                """
            ),
        )

    def test_side_effect_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            var x;
            x = sideEffect();
            console.log("done");
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                sideEffect();
                console.log("done");
                """
            ),
            self._remove_unused(source),
        )

    def test_forin_target_var_not_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            for (x in obj) { console.log(x); }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                for (x in obj) {
                  console.log(x);
                }
                """
            ),
        )

    def test_forof_target_var_not_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            for (x of arr) { console.log(x); }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                for (x of arr) {
                  console.log(x);
                }
                """
            ),
        )


class TestRegressionBugs(TestJsDeobfuscator):

    def test_shadowed_param_does_not_prevent_table_cleanup(self):
        source = inspect.cleandoc(
            """
            function uses_table_param(table) { return table.length; }
            uses_table_param([1, 2, 3]);
            """
        )
        ast = JsParser(source).parse()
        result = has_remaining_references(ast, 'table', check_shadowing=True)
        self.assertFalse(result,
            'all occurrences of table are shadowed by function parameters')

    def test_expression_not_inlined_across_conditional_boundary(self):
        source = inspect.cleandoc(
            """
            function f(cond) {
              if (cond) {
                var x = a + b;
              }
              return x;
            }
            """
        )
        result = self._inline(source)
        self.assertEqual(result, source)

    def test_dispatcher_sparse_payload_preserves_arity(self):
        source = inspect.cleandoc(
            """
            var c = Object["create"](null);
            var p;
            function d(name, flag, rtype, lengths) {
              var output;
              var fns = {
                "f1": function() { var [a, b, c] = p; return a + b + c; }
              };
              if (flag === "initF") { p = []; }
              if (flag === "createF") {
                output = c[name] || (c[name] = fns[name]);
              } else {
                output = fns[name]();
              }
              if (rtype === "wrapF") { return { "wk": output }; }
              else { return output; }
            }
            console.log((p = [1, , 3], d("f1")));
            """
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            function f1(a, b, c) {
              return a + b + c;
            }
            console.log(f1(1, undefined, 3));
            """
        ))

    def test_argwrap_expression_position_returns_void0(self):
        source = inspect.cleandoc(
            """
            function wr() { wr = function() {}; }
            var y = wr(a = 1, b = 2);
            console.log(y);
            """
        )
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                a = 1;
                b = 2;
                var y = void 0;
                console.log(y);
                """
            ),
        )
        self.assertEqual(
            self._deobfuscate_iterative(source),
            'console.log(void 0);'
        )

    def test_bitwise_ops_use_signed_32bit(self):
        cases = [
            ('0xFFFFFFFF | 0', '-1'),
            ('0x80000000 | 0', '-2147483648'),
            ('0x80000000 ^ 0', '-2147483648'),
            ('       1 << 31', '-2147483648'),
        ]
        for expr, expected in cases:
            source = F'var x = {expr};'
            self.assertEqual(
                self._simplify(source),
                F'var x = {expected};',
                F'{expr} should fold to {expected}',
            )

    def test_modulo_uses_truncated_remainder(self):
        self.assertEqual('var x = -1;', self._simplify('var x = (-7) % 3;'))

    def test_split_empty_separator(self):
        self.assertEqual(
            self._simplify('var x = "hello".split("");'),
            "var x = ['h', 'e', 'l', 'l', 'o'];",
        )

    def test_cff_preserves_labeled_break(self):
        """
        Bug: Trailing break/continue was stripped without checking for labels. A labeled break
        targeting an outer construct must not be removed.
        """
        dummy = JsExpressionStatement()
        unlabeled = JsBreakStatement(label=None)
        labeled = JsBreakStatement(label=JsIdentifier(name='outer'))
        labeled_cont = JsContinueStatement(label=JsIdentifier(name='outer'))
        self.assertEqual(len(_strip_trailing_flow([dummy, unlabeled])), 1)
        self.assertEqual(len(_strip_trailing_flow([dummy, labeled])), 2,
            'labeled break must not be stripped')
        self.assertEqual(len(_strip_trailing_flow([dummy, labeled_cont])), 2,
            'labeled continue must not be stripped')

    def test_void_0_not_replaced_with_undefined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(undefined) {
                  return void 0 === undefined;
                }
                """
            ),
            self._simplify('function f(undefined) { return void 0 === undefined; }'),
        )

    def test_split_empty_sep_emoticon(self):
        self.assertEqual(
            self._simplify("var x = '\U0001f600'.split('');"),
            "var x = ['\\uD83D', '\\uDE00'];",
        )

    def test_negative_zero_literal(self):
        self.assertEqual('var x = -0;', self._simplify('var x = -(0);'))

    def test_cff_preserves_intervening_statements(self):
        source = inspect.cleandoc(
            """
            var _order = ['1', '0'];
            console.log('side effect');
            var _idx = 0;
            while (true) {
              switch (_order[_idx++]) {
                case '0': var b = 2; continue;
                case '1': var a = 1; continue;
              }
              break;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('side effect');
                var a = 1;
                var b = 2;
                """
            ),
            self._deobfuscate(source),
        )

    def test_dead_variable_preserves_external_property_access(self):
        source = inspect.cleandoc(
            """
            var x;
            x = externalObj.prop;
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(result, 'externalObj.prop;')

    def test_free_variable_not_inlined_past_modifying_call(self):
        test = self._deobfuscate_iterative(inspect.cleandoc(
            """
            function modifyGlobal() {
                x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        ))
        self.assertEqual(test, inspect.cleandoc(
            """
            function modifyGlobal() {
              x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        ))

    def test_free_variable_is_inlined_past_harmless_call(self):
        test = self._deobfuscate_iterative(inspect.cleandoc(
            """
            function harmlessCall() {
                if (x == 12) {
                    console.log("good");
                }
            }
            var x = 12;
            harmlessCall();
            console.log(x);
            """
        ))
        self.assertEqual(test, inspect.cleandoc(
            """
            function harmlessCall() {
              console.log("good");
            }
            harmlessCall();
            console.log(12);
            """
        ))

    def test_free_variable_inlined_without_intervening_call(self):
        source = inspect.cleandoc(
            """
            var x = a + b;
            console.log(x);
            """
        )
        self.assertEqual('console.log(a + b);', self._inline(source))

    def test_local_variable_not_inlined_past_modifying_call(self):
        source = inspect.cleandoc(
            """
            function f() {
                x = 9;
            }
            var a = 1;
            var x = a;
            f();
            console.log(x);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  x = 9;
                }
                var x = 1;
                f();
                console.log(x);
                """
            ),
            self._deobfuscate(source),
        )

    def test_deadcode_block_scoped_declarations_not_leaked(self):
        result = self._deadcode(
            'if (true) { let x = 1; f(x); } let x = 2;'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                {
                  let x = 1;
                  f(x);
                }
                let x = 2;
                """
            ),
            result,
        )

    def test_objectfold_no_inline_sideeffect_argument(self):
        source = inspect.cleandoc(
            """
            var o = {fn: function(a) { return a + a; }};
            o.fn(g());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function(a) {
                  return a + a;
                }(g());
                """
            ),
            self._objectfold(source),
        )

    def test_objectfold_getter_not_folded(self):
        source = 'var o = { get x() { return 1; } }; o.x;'
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { get x() {
                  return 1;
                } };
                o.x;
                """
            ),
            self._objectfold(source),
        )

    def test_var_not_inlined_past_call_with_inner_let_shadow(self):
        """
        An inner-block `let x` must not prevent `_function_local_names` from detecting that the
        function modifies the outer `x`. Without the fix, the inner `let x = 3` would be
        collected as function-local, masking the `x = 2` assignment from mod/ref analysis.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              x = 2;
              if (true) {
                let x = 3;
              }
            }
            f();
            console.log(x);
            """
        )
        result = self._inline(source)
        self.assertEqual(source, result)

    def test_delete_expression_not_removed(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            delete x;
            console.log('done');
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(source, result)

    def test_newline_before_paren_does_not_fuse_statements(self):
        source = 'global["VERSION"] = "9.4533"\n\n(async () => {\n  const c = global;\n})()'
        ast = JsParser(source).parse()
        self.assertEqual(len(ast.body), 2)

    def test_newline_before_template_does_not_create_tagged_template(self):
        source = "var x = foo\n`template`"
        ast = JsParser(source).parse()
        self.assertEqual(len(ast.body), 2)


class TestReflectionInlining(TestJsDeobfuscator):

    def _reflect(self, source: str) -> str:
        return self._run_transformer(source, JsReflectionInlining)

    def test_eval_string_literal(self):
        self.assertEqual('var x = 1;', self._reflect("eval('var x = 1;');"))

    def test_eval_non_literal_not_inlined(self):
        self.assertEqual('eval(x);', self._reflect('eval(x);'))

    def test_eval_parenthesized(self):
        self.assertEqual('var x = 1;', self._reflect("(eval)('var x = 1;');"))

    def test_indirect_eval_comma_operator(self):
        self.assertEqual('var x = 1;', self._reflect("(0, eval)('var x = 1;');"))

    def test_indirect_eval_window(self):
        self.assertEqual('var x = 1;', self._reflect("window.eval('var x = 1;');"))

    def test_indirect_eval_globalthis(self):
        self.assertEqual('var x = 1;', self._reflect("globalThis.eval('var x = 1;');"))

    def test_settimeout_string(self):
        self.assertEqual('alert(1);', self._reflect("setTimeout('alert(1)', 0);"))

    def test_setinterval_string(self):
        self.assertEqual('doStuff();', self._reflect("setInterval('doStuff()', 1000);"))

    def test_settimeout_non_string_not_inlined(self):
        self.assertEqual('setTimeout(fn, 0);', self._reflect('setTimeout(fn, 0);'))

    def test_new_function_body_invoked(self):
        self.assertEqual('42;', self._reflect("new Function('return 42')();"))

    def test_function_constructor_body_invoked(self):
        self.assertEqual('42;', self._reflect("Function('return 42')();"))

    def test_constructor_chain_string(self):
        self.assertEqual('1;', self._reflect("''.constructor.constructor('return 1')();"))

    def test_constructor_chain_array(self):
        self.assertEqual('1;', self._reflect("[].constructor.constructor('return 1')();"))

    def test_eval_expression_position_single_expr(self):
        self.assertEqual("var x = 'hello';", self._reflect("var x = eval(\"'hello'\");"))

    def test_eval_multi_statement_expression_position_not_inlined(self):
        self.assertEqual(
            "var x = eval('a = 1; b = 2;');",
            self._reflect("var x = eval('a = 1; b = 2;');"),
        )

    def test_new_function_return_expression_position(self):
        self.assertEqual('var x = 42;', self._reflect("var x = new Function('return 42')();"))

    def test_pack_simple_getter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello');")(
            { get 'a'() { return console; } });
            """
        )
        self.assertEqual("console.log('hello');", self._reflect(source))

    def test_pack_getter_and_setter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello'); o['b'] = 1;")(
            { get 'a'() { return console; },
              set 'b'(v) { return b = v; },
              get 'b'() { return b; } });
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('hello');
                b = 1;
                """
            ),
            self._reflect(source),
        )

    def test_pack_typeof_getter(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['t'];")(
            { get 't'() { return typeof myVar; } });
            """
        )
        self.assertEqual('typeof myVar;', self._reflect(source))

    def test_pack_proxy_mapping_failure_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Function('o', 'o.x;')({ get 'a'() {
                  return something();
                } });
                """
            ),
            self._reflect("Function('o', 'o.x;')({ get 'a'() { return something(); } });"),
        )

    def test_eval_multi_statement_inlined_in_statement_position(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 1;
                var b = 2;
                """
            ),
            self._reflect("eval('var a = 1; var b = 2;');"),
        )

    def test_pack_full_pipeline(self):
        source = inspect.cleandoc(
            """
            Function("o", "o['a'].log('hello');")(
            { get 'a'() { return console; } });
            """
        )
        self.assertEqual("console.log('hello');", self._deobfuscate(source))

    def test_await_eval_inlined(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("var a = 1; var b = 2;");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  var a = 1;
                  var b = 2;
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_await_eval_with_top_level_await(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("await fetch('x'); var a = 1;");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  (async () => {
                    await fetch('x');
                    var a = 1;
                  })();
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_await_eval_nested_async_not_wrapped(self):
        source = inspect.cleandoc(
            """
            async function run() {
              await eval("const g = async () => { await fetch('x'); }; g();");
            }
            run();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                async function run() {
                  const g = async () => {
                    await fetch('x');
                  };
                  g();
                }
                run();
                """
            ),
            self._reflect(source),
        )

    def test_eval_atob(self):
        import base64
        code = base64.b64encode(b'var x = 1;').decode()
        self.assertEqual('var x = 1;', self._reflect(F"eval(atob('{code}'));"))

    def test_new_function_atob_invoked(self):
        import base64
        code = base64.b64encode(b'return 42').decode()
        self.assertEqual('42;', self._reflect(F"new Function(atob('{code}'))();"))

    def test_eval_unescape(self):
        self.assertEqual(
            'var x = 1;',
            self._reflect("eval(unescape('%76%61%72%20%78%20%3d%20%31%3b'));"),
        )

    def test_eval_chained_decode(self):
        import base64
        encoded = base64.b64encode('var x = 1;'.encode()).decode()
        self.assertEqual(
            'var x = 1;',
            self._reflect(F"eval(decodeURIComponent(atob('{encoded}')));"),
        )

    def test_eval_unknown_callee_not_inlined(self):
        self.assertEqual("eval(decode('abc'));", self._reflect("eval(decode('abc'));"))

    def test_constructor_chain_atob(self):
        import base64
        code = base64.b64encode(b'var y = 2;').decode()
        self.assertEqual(
            'var y = 2;',
            self._reflect(F"''.constructor.constructor(atob('{code}'))();"),
        )


class TestGeneratorCFFUnflattening(TestJsDeobfuscator):

    FIZZBUZZ_CFF = inspect.cleandoc(
        """
        function fizzbuzz(n) {
          function* ECU0cy7(eFGm4GL, QmFNlk, AT7hsy7, sYhBnK = {
            ["GrHow6O"]: {}
          }) {
            while (eFGm4GL + QmFNlk + AT7hsy7 !== -182) {
              with (sYhBnK["Pia5Vq"] || sYhBnK) {
                switch (eFGm4GL + QmFNlk + AT7hsy7) {
                  case sYhBnK["GrHow6O"]["_TkmcFL"] + -375:
                  case 210:
                  case 17:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [95, -148];
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 200, QmFNlk += AT7hsy7 - -792, AT7hsy7 += QmFNlk - 183;
                    break;
                  case -125:
                  case QmFNlk - 131:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [99, 225];
                    GrHow6O["QOwuVkJ"] = [];
                    for (GrHow6O["z947WD2"] = 1; GrHow6O["z947WD2"] <= n; GrHow6O["z947WD2"]++) {
                      if (GrHow6O["z947WD2"] % 15 === QmFNlk + -66) {
                        GrHow6O["QOwuVkJ"]["push"]('FizzBuzz');
                      } else {
                        if (GrHow6O["z947WD2"] % (QmFNlk + -63) === 0) {
                          GrHow6O["QOwuVkJ"]["push"]('Fizz');
                        } else {
                          if (GrHow6O["z947WD2"] % (QmFNlk + -61) === eFGm4GL + 46) {
                            GrHow6O["QOwuVkJ"]["push"]('Buzz');
                          } else {
                            GrHow6O["QOwuVkJ"]["push"](GrHow6O["z947WD2"]);
                          }
                        }
                      }
                    }
                    return DL1uIO3 = true, GrHow6O["QOwuVkJ"];
                    eFGm4GL += AT7hsy7 - 326, QmFNlk += AT7hsy7 - -101, AT7hsy7 += QmFNlk - -196;
                    break;
                  case -142:
                  case sYhBnK["GrHow6O"]["_TkmcFL"] + 12:
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += QmFNlk - 193, QmFNlk += eFGm4GL - 563;
                    break;
                  case 29:
                  case 222:
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 205, QmFNlk += AT7hsy7 - -618, AT7hsy7 += QmFNlk - 183;
                    break;
                  default:
                  case -31:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [142, -215];
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 210, QmFNlk += AT7hsy7 - -530, AT7hsy7 += QmFNlk - 445;
                    break;
                  case eFGm4GL - 67:
                    sYhBnK["Pia5Vq"] = sYhBnK["YS6RFB"], eFGm4GL += QmFNlk - 370, QmFNlk += AT7hsy7 - -149, AT7hsy7 += QmFNlk - -79;
                    break;
                }
              }
            }
          }
          var DL1uIO3;
          var WLHepXQ = ECU0cy7(-46, 66, -85)["next"]()["value"];
          if (DL1uIO3) {
            return WLHepXQ;
          }
        }
        console["log"](fizzbuzz(20));
        """
    )

    def test_generator_cff_fizzbuzz(self):
        result = self._deobfuscate(self.FIZZBUZZ_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('while', result)
        self.assertNotIn('switch', result)
        self.assertIn('for', result)
        self.assertIn('FizzBuzz', result)
        self.assertIn('Fizz', result)
        self.assertIn('Buzz', result)
        self.assertIn('% 15', result)
        self.assertIn('% 3', result)
        self.assertIn('% 5', result)
        self.assertIn('return', result)

    def test_generator_cff_return_recovery(self):
        result = self._deobfuscate(self.FIZZBUZZ_CFF)
        self.assertNotIn('DL1uIO3', result)
        self.assertNotIn('WLHepXQ', result)

    def test_generator_cff_state_substitution(self):
        result = self._deobfuscate(self.FIZZBUZZ_CFF)
        self.assertNotIn('eFGm4GL', result)
        self.assertNotIn('QmFNlk', result)
        self.assertNotIn('AT7hsy7', result)
        self.assertIn('=== 0', result)

    WITH_DISSOLUTION_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    x = globalThis;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, x;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_with_statement_dissolved(self):
        """
        The `with(scope)` wrapping the switch is dissolved during CFF recovery: scope-qualified
        member expressions become bare identifiers and no `with` statement remains.
        """
        result = self._run_transformer(self.WITH_DISSOLUTION_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              NS.x = globalThis;
              return NS.x;
            }
            """
        ))

    SHARED_WRAPPER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case -10:
                    scope.R = {};
                    scope.R.k = -10;
                    a = 20, b = 10;
                    break;
                  case scope.R.k + 40:
                    var wrapper = function(...rest) {
                      return gen(25, 10, scope, rest)["next"]()["value"];
                    };
                    a = 80, b = -30;
                    break;
                  case 50:
                    return x = true, wrapper(1, 2);
                    break;
                  case scope.R.k + 45:
                    return x = true, args[0] + args[1];
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, -15)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_shared_wrapper_routing(self):
        """
        Verify that predicate-gated cases referencing scope routing values are resolved when
        the outer execution accumulates routing entries and passes them to wrapper execution.
        """
        result = self._deobfuscate(self.SHARED_WRAPPER_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('while', result)
        self.assertNotIn('switch', result)
        self.assertIn('rest[0] + rest[1]', result)

    GUARDED_PREDICATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {}, args) {
            while (a + b + c !== 200) {
              with (scope) {
                switch (a + b + c) {
                  case 10:
                    scope.R = {};
                    scope.R.k = 50;
                    a = 20, b = 30, c = -10;
                    break;
                  case a != 30 && a + 20:
                    var wrapper = function(...rest) {
                      return gen(10, 20, 20, scope, rest)["next"]()["value"];
                    };
                    a = 60, b = 30, c = 10;
                    break;
                  case 100:
                    return x = true, wrapper(1, 2);
                    break;
                  case scope.R.k + 0:
                    return x = true, "resolved";
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 10, -5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_guarded_predicate(self):
        """
        Test that switch cases using logical AND guards (a != X && expr) evaluate correctly and
        that prefix state variable assignments are accounted for when computing successor edges.
        """
        result = self._deobfuscate(self.GUARDED_PREDICATE_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('while', result)
        self.assertNotIn('switch', result)
        self.assertIn('resolved', result)

    REDIRECT_VAR_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    y = 42;
                    a = 30, b = 20;
                    break;
                  case 50:
                    return x = true, y;
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_redirect_var_removed(self):
        """
        Verify that CFF redirect variable assignments (scope.RV = scope.NS) are removed from
        recovered output after the with statement is dissolved.
        """
        result = self._run_transformer(self.REDIRECT_VAR_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              NS.y = 42;
              return NS.y;
            }
            """
        ))

    REDIRECT_QUALIFY_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {NS: {}}, args) {
            while (a + b + c !== 200) {
              with (scope.RV || scope) {
                switch (a + b + c) {
                  case 30:
                    scope.Sub = {};
                    scope.RV = scope.NS;
                    a = 40, b = 50, c = 10;
                    break;
                  case 100:
                    Sub.arr = args;
                    scope.RV = scope.Sub;
                    a = 20, b = 30, c = 100;
                    break;
                  case 150:
                    return DR = true, scope.NS.extra + val;
                    break;
                }
              }
            }
          }
          var DR;
          var result = gen(10, 10, 10)["next"]()["value"];
          if (DR) { return result; }
        }
"""
    )

    def test_generator_cff_redirect_qualification_levels(self):
        """
        Bare identifiers must be qualified at the redirect level active for their block, while
        explicit scope accesses are qualified at root level. When redirect is set to Sub,
        bare 'val' becomes NS.Sub.val, not NS.val.
        """
        result = self._deobfuscate(self.REDIRECT_QUALIFY_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('scope', result)
        self.assertNotIn('RV', result)
        self.assertIn('Sub.arr', result)
        self.assertIn('Sub.val', result)
        self.assertIn('extra', result)

    COMPUTED_REDIRECT_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {NS: {}}, args) {
            while (a + b + c !== 200) {
              with (scope["RV"] || scope) {
                switch (a + b + c) {
                  case 30:
                    scope["RV"] = scope["NS"];
                    a = 40, b = 50, c = 10;
                    break;
                  case 100:
                    data = args;
                    a = 20, b = 30, c = 100;
                    break;
                  case 150:
                    return DR = true, val;
                    break;
                }
              }
            }
          }
          var DR;
          var result = gen(10, 10, 10)["next"]()["value"];
          if (DR) { return result; }
        }
"""
    )

    def test_generator_cff_computed_redirect_resolved(self):
        """
        CFF using bracket notation for redirect variable assignments. The redirect mechanism
        must work identically to the dot-notation variant.
        """
        result = self._deobfuscate(self.COMPUTED_REDIRECT_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('scope', result)
        self.assertNotIn('RV', result)
        self.assertIn('val', result)

    LOOPING_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.i < 3) {
                      a = 20, b = 10;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    console.log(scope.i);
                    scope.i = scope.i + 1;
                    a = 20, b = 0;
                    break;
                  case 50:
                    return x = true, "done";
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_loop_body_not_duplicated(self):
        """
        A CFF pattern with a looping state machine (state 30 → state 20 back-edge). Loop body
        statements must appear exactly once inside a while loop, not duplicated at the outer level.
        """
        result = self._deobfuscate(self.LOOPING_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertEqual(result.count('console.log'), 1)

    CONTINUE_IN_LOOP_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.i < 5) {
                      a = 30, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    if (scope.i % 2 === 0) {
                      scope.i = scope.i + 1;
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 10;
                    }
                    break;
                  case 40:
                    console.log(scope.i);
                    scope.i = scope.i + 1;
                    a = 20, b = 0;
                    break;
                  case 50:
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_continue_in_loop(self):
        """
        A CFF loop where a body node conditionally loops back to the header (simulating continue)
        while the other branch continues to a forward body node. The forward body (console.log)
        must appear in the output and not be dropped.
        """
        result = self._deobfuscate(self.CONTINUE_IN_LOOP_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertIn('console.log', result)
        self.assertNotIn('scope', result)

    HEADER_PAYLOAD_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope.i = scope.i + 1;
                    if (scope.i < 4) {
                      a = 20, b = 10;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    console.log(scope.i);
                    a = 20, b = 0;
                    break;
                  case 50:
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_header_payload_before_condition(self):
        """
        A CFF loop where the header block has payload (scope.i++) before its conditional
        transition. The payload must execute before the condition check — structured as
        while(true) { payload; if(!cond) break; body; }, not while(cond) { payload; body; }.
        """
        result = self._deobfuscate(self.HEADER_PAYLOAD_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertIn('console.log', result)
        self.assertEqual(result.count('console.log'), 1)
        self.assertNotIn('scope', result)

    COMPUTED_MEMBER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope["counter"] = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope["counter"] = scope["counter"] + 1;
                    if (scope["counter"] < 3) {
                      a = 20, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    console.log(scope["counter"]);
                    return done = true, scope["counter"];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_computed_member_scope(self):
        """
        A CFF sample using bracket notation (scope["x"]) instead of dot notation (scope.x).
        The scope prefix must still be stripped, producing bare identifiers in output.
        """
        result = self._deobfuscate(self.COMPUTED_MEMBER_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertNotIn('scope', result)
        self.assertIn('counter', result)
        self.assertIn('console.log', result)

    SEQUENCE_STATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.items = [], scope.i = 0, a = 20, b = 0;
                    break;
                  case 20:
                    scope.items.push(scope.i), scope.i = scope.i + 1, a = 30, b = 0;
                    break;
                  case 30:
                    if (scope.i < 4) {
                      a = 20, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    console.log(scope.items);
                    return done = true, scope.items;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_sequence_state_assignments(self):
        """
        A CFF sample where state variable transitions are embedded in sequence expressions
        alongside payload expressions (e.g., `scope.x = foo(), a = 20, b = 0;`). State vars
        must be stripped from the sequence while preserving the payload expressions.
        """
        result = self._deobfuscate(self.SEQUENCE_STATE_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertNotIn('scope', result)
        self.assertIn('items.push', result)
        self.assertIn('console.log', result)

    NESTED_CONDITIONAL_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.x = 7;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.x > 5) {
                      a = 30, b = 0;
                    } else {
                      a = 40, b = 0;
                    }
                    break;
                  case 30:
                    if (scope.x > 10) {
                      a = 50, b = 0;
                    } else {
                      a = 60, b = 0;
                    }
                    break;
                  case 40:
                    console.log("alpha");
                    a = 50, b = 0;
                    break;
                  case 50:
                    console.log("beta");
                    return done = true, "end";
                    break;
                  case 60:
                    console.log("gamma");
                    return done = true, "end";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_nested_conditional_join(self):
        """
        A CFF sample where a conditional's true branch leads to another conditional, creating
        a non-diamond CFG. One inner branch and the outer false branch both target the same
        node (case 50). The join point must be computed correctly (post-dominator) so that the
        shared node is not claimed exclusively by one branch.
        """
        result = self._deobfuscate(self.NESTED_CONDITIONAL_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertIn('alpha', result)
        self.assertIn('beta', result)
        self.assertIn('gamma', result)
        self.assertNotIn('scope', result)

    COMPUTED_ROUTING_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope["count"] = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope["count"] = scope["count"] + 1;
                    console.log("tick");
                    if (scope["count"] < 3) {
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 0;
                    }
                    break;
                  case 30:
                    console.log("done");
                    return done = true, scope["count"];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_computed_routing_member(self):
        """
        A CFF sample using bracket notation (scope["count"]) for routing state and value access.
        The scope routing tracker must resolve computed string-literal members so that
        discriminant-based transition analysis and scope stripping work correctly.
        """
        result = self._deobfuscate(self.COMPUTED_ROUTING_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertNotIn('scope[', result)
        self.assertIn('count', result)
        self.assertIn('tick', result)
        self.assertIn('done', result)

    BOOKKEEPING_LEAK_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.pred = 1;
                    console.log("start");
                    a = 20, b = 0;
                    break;
                  case 20:
                    console.log("end");
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_bookkeeping_suppressed(self):
        """
        A CFF sample with scope routing bookkeeping (scope.pred = 1) alongside real payload.
        The bookkeeping filter must run before scope stripping so that it can recognize and
        suppress the scope-member routing assignment, while preserving actual payload statements.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  console.log("start");
                  console.log("end");
                  return "result";
                }
                """
            ),
            self._deobfuscate(self.BOOKKEEPING_LEAK_CFF),
        )

    SHARED_INTERMEDIATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.x = 0;
                    if (scope.x === 0) {
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 0;
                    }
                    break;
                  case 20:
                    console.log("path-a");
                    a = 40, b = 0;
                    break;
                  case 30:
                    console.log("path-b");
                    a = 40, b = 0;
                    break;
                  case 40:
                    console.log("shared");
                    return done = true, "done";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_shared_intermediate_node(self):
        """
        A CFF sample where both branches of a conditional lead to the same intermediate node
        (case 40) before the exit. The ipdom computation must correctly identify the shared node
        as the join point so its payload is emitted once after the if/else, not duplicated in
        both branches.
        """
        result = self._deobfuscate(self.SHARED_INTERMEDIATE_CFF)
        self.assertNotIn('function*', result)
        self.assertNotIn('switch', result)
        self.assertNotIn('scope', result)
        self.assertIn('path-a', result)
        self.assertIn('path-b', result)
        self.assertIn('shared', result)
        self.assertEqual(result.count('shared'), 1)

    BARE_SCOPE_CONDITION_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.ready = 1;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.ready) {
                      console.log("go");
                      a = 50, b = 0;
                    } else {
                      console.log("wait");
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    return done = true, "ok";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_bare_scope_condition_stripped(self):
        """
        A CFF sample where the conditional test is a bare scope member expression (scope.ready).
        The condition must be stripped to a bare identifier even when it is the root expression
        node, not nested inside a larger expression.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  if (ready) {
                    console.log("go");
                  } else {
                    console.log("wait");
                  }
                  return "ok";
                }
                """
            ),
            self._deobfuscate(self.BARE_SCOPE_CONDITION_CFF),
        )

    MIXED_SEQUENCE_BRANCH_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (scope.x) {
                      console.log("mixed"), a = 40, b = 0;
                    } else {
                      console.log("other"), a = 40, b = 0;
                    }
                    break;
                  case 40:
                    console.log("end");
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_mixed_sequence_branch_preserved(self):
        """
        A CFF sample where conditional branch endings mix non-state payload expressions with
        state transitions in a single sequence expression. The non-state expressions must be
        preserved in the output.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  if (x) {
                    console.log("mixed");
                  } else {
                    console.log("other");
                  }
                  console.log("end");
                  return "result";
                }
                """
            ),
            self._deobfuscate(self.MIXED_SEQUENCE_BRANCH_CFF),
        )

    NAMESPACE_DECL_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    x = 1;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, x + y;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_scope_namespace_declared(self):
        """
        After flattening a generator CFF with `with(scope.RV || scope)` and a scope default
        containing a namespace object, the namespace is emitted and then flattened to bare vars.
        """
        result = self._run_transformer(self.NAMESPACE_DECL_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              NS.x = 1;
              return NS.x + NS.y;
            }
            """
        ))

    LABELED_CONTINUE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    LBL: for (var i = 0; i < 3; i++) {
                      if (i === 1) continue LBL;
                    }
                    return done = true, i;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_labeled_continue_preserved(self):
        """
        Labels and `continue <label>` inside the CFF body must remain simple identifiers after
        qualification — they must not be turned into member expressions.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var NS = {};
                  LBL: for (var i = 0; i < 3; i++) {
                    if (i === 1) {
                      continue LBL;
                    }
                  }
                  return i;
                }
                """
            ),
            self._deobfuscate(self.LABELED_CONTINUE_CFF),
        )


class TestVariableDemasking(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_simple_two_params(self):
        """
        Basic variableMasking with 2 parameters: rest param slots 0 and 1 become named params.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1) {
                  return p0 + p1;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 2; return s[0] + s[1]; }'),
        )

    def test_simple_zero_params_with_locals(self):
        """
        Zero-param function where all stack keys are local variables.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function() {
                  var v0;
                  v0 = 10;
                  return v0;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 0; s.a = 10; return s.a; }'),
        )

    def test_simple_negative_keys(self):
        """
        Negative integer keys from variableMasking (random keys in [-250, 250] range).
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  var v0;
                  v0 = p0 + 1;
                  return v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) { s.length = 1; s[-42] = s[0] + 1; return s[-42]; }'
            ),
        )

    def test_frame_qualified(self):
        """
        Frame-qualified pattern where the stack is a nested property on a frame object.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.fn = function(p0) {
                  return p0 * 2;
                };
                """
            ),
            self._demask(
                'var NS = {}; NS.fn = function(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }'
            ),
        )

    def test_skips_unresolvable_access(self):
        """
        Functions with dynamic (non-static) stack access keys are left unchanged.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  return s[x];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; return s[x]; }'),
        )

    def test_skips_rest_param_aliased(self):
        """
        Functions where the rest param is used as a value (not just indexed) are left unchanged.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  foo(s);
                  return s[0];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; foo(s); return s[0]; }'),
        )

    def test_nested_function_not_processed(self):
        """
        Inner function expressions are not recursed into during the outer function's collection.
        The inner function is processed independently in its own pass.
        """
        source = inspect.cleandoc(
            """
            var outer = function(...s) {
              s.length = 1;
              s.x = function(...t) { t.length = 0; t.a = 5; return t.a; };
              return s[0] + s.x();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var outer = function(p0) {
                  var v0;
                  v0 = function() {
                    var v0;
                    v0 = 5;
                    return v0;
                  };
                  return p0 + v0();
                };
                """
            ),
            self._demask(source),
        )

    def test_frame_qualified_missing_accesses_skipped(self):
        """
        If param_count > 0 but no matching accesses found (chain mismatch), skip the function.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...r) {
                  A.B.C.length = 2;
                  return A.X.C[0];
                };
                """
            ),
            self._demask('var f = function(...r) { A.B.C.length = 2; return A.X.C[0]; }'),
        )


class TestNamespaceFlattening(TestJsDeobfuscator):

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def test_basic_namespace_flatten(self):
        """
        A simple namespace with only member-access usage is fully flattened to bare variables.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x + 2;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = NS.x + 2;'),
        )

    def test_computed_string_access(self):
        """
        Computed access with a string literal key is equivalent to dot access for flattening.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x;
                """
            ),
            self._flatten('var NS = {}; NS["x"] = 1; NS["y"] = NS["x"];'),
        )

    def test_reject_bare_reference(self):
        """
        If the namespace object is used as a bare value (not just property access), do not flatten.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 1;
                f(NS);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; f(NS);'),
        )

    def test_reject_computed_dynamic_key(self):
        """
        Computed access with a non-literal key blocks flattening (key cannot be statically resolved).
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS[key] = 1;
                """
            ),
            self._flatten('var NS = {}; NS[key] = 1;'),
        )

    def test_conflict_skips_conflicting_property(self):
        """
        A property whose name conflicts with an existing variable is left on the namespace while
        other properties are flattened.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var y;
                var NS = {};
                NS.x = 1;
                y = 2;
                var x = 10;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = 2; var x = 10;'),
        )

    def test_shadowing_nested_function_untouched(self):
        """
        A nested function that re-declares `var NS` shadows the outer namespace. References to
        `NS` inside that function must not be rewritten.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var a;
                a = 1;
                function f() {
                  var NS;
                  return NS.b;
                }
                """
            ),
            self._flatten('var NS = {}; NS.a = 1; function f() { var NS; return NS.b; }'),
        )

    def test_non_shadowing_nested_function_rewritten(self):
        """
        A nested function that does NOT shadow the namespace name accesses the outer namespace
        via closure; those accesses are flattened.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                function f() {
                  return x;
                }
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; function f() { return NS.x; }'),
        )


class TestArrayUnshuffle(TestJsDeobfuscator):

    def _unshuffle(self, source: str) -> str:
        return self._run_transformer(source, JsArrayUnshuffle)

    def test_direct_callee_in_rotation_names(self):
        """
        A direct call to a structurally-verified rotation function is unshuffled.
        """
        source = inspect.cleandoc(
            """
            function rot(arr, n) {
              for (var i = 0; i < n; i++) arr.push(arr.shift());
              return arr;
            }
            var x = rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        result = self._unshuffle(source)
        self.assertIn('"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"', result)

    def test_namespace_qualified_callee_with_empty_object(self):
        """
        A namespace-qualified rotation call `NS.rot(array, shift)` where the rotation function is
        assigned to a namespace object is resolved: namespace flattening promotes the function to a
        declaration, then unshuffle matches the now-direct callee.
        """
        source = inspect.cleandoc(
            """
            var NS = {};
            NS.rot = function(arr, n) {
              for (var i = 0; i < n; i++) arr.push(arr.shift());
              return arr;
            };
            var x = NS.rot(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        ast = JsParser(source).parse()
        JsNamespaceFlattening().visit(ast)
        JsArrayUnshuffle().visit(ast)
        result = JsSynthesizer().convert(ast)
        self.assertIn('"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"', result)

    def test_namespace_qualified_callee_without_empty_object_rejected(self):
        """
        A member-expression call `utils.process(array, number)` where the object is NOT declared
        as an empty object literal must NOT be treated as a rotation.
        """
        source = inspect.cleandoc(
            """
            var utils = require("utils");
            var x = utils.process(["b", "c", "d", "e", "f", "g", "h", "i", "j", "a"], 9);
            """
        )
        result = self._unshuffle(source)
        self.assertIn('utils.process(', result)


class TestCFFArgParamDeclarations(TestJsDeobfuscator):

    def test_undeclared_assignment_not_removed_when_read_in_outer_scope(self):
        """
        An assignment to a variable declared in an enclosing scope must not be treated as a dead
        local write, even if the variable is not declared in the function body itself.
        """
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

    def test_truly_undeclared_dead_write_removed(self):
        """
        An assignment to a variable that is not declared anywhere and is never read should be
        removed as dead code.
        """
        source = inspect.cleandoc(
            """
            function f() {
              for (var i = 0; i < 3; i++) {
                deadVar = function() { return 42; };
              }
              return i;
            }
            f();
            """
        )
        result = self._deobfuscate_iterative(source)
        self.assertNotIn('deadVar', result)


class TestGlobalAliasStripping(TestJsDeobfuscator):

    def test_global_alias_stripped_when_not_shadowed(self):
        self.assertEqual('y = X;', self._simplify('y = globalThis.X;'))

    def test_global_alias_preserved_when_locally_shadowed(self):
        source = inspect.cleandoc(
            """
            var X = 1;
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var X = 1;
                y = globalThis.X;
                """
            ),
            self._simplify(source),
        )

    def test_window_alias_stripped_when_not_shadowed(self):
        self.assertEqual('y = console;', self._simplify('y = window.console;'))

    def test_global_alias_preserved_when_shadowed_by_param(self):
        source = inspect.cleandoc(
            """
            function f(X) {
                return globalThis.X;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(X) {
                  return globalThis.X;
                }
                """
            ),
            self._simplify(source),
        )

    def test_const_alias_to_global_preserves_property_assignment(self):
        source = inspect.cleandoc(
            """
            global['_V'] = "7-4111";
            (async () => {
                const c = global;
                console.log(c._V);
            })()
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                global._V = "7-4111";
                (async () => {
                  const c = global;
                  console.log(_V);
                })();
                """
            ),
            self._deobfuscate(source),
        )

    def test_dead_global_property_is_removed(self):
        source = inspect.cleandoc(
            """
            global['_V'] = "7-4111";
            global['_W'] = "dead";
            (async () => {
                const c = global;
                console.log(c._V);
            })()
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                global._V = "7-4111";
                (async () => {
                  const c = global;
                  console.log(_V);
                })();
                """
            ),
            self._deobfuscate(source),
        )


class TestOpaquePredicate(TestJsDeobfuscator):

    def test_in_predicate_pruned_without_property_store(self):
        source = inspect.cleandoc(
            """
            function f() {}
            if ("xyz" in f) {
                dead();
            }
            live();
            """
        )
        self.assertEqual(
            'live();',
            self._deobfuscate(source),
        )

    def test_in_predicate_true_when_property_exists(self):
        source = inspect.cleandoc(
            """
            function f() {}
            f.xyz = 1;
            if ("xyz" in f) {
                console.log("Hello World!");
            }
            """
        )
        self.assertEqual(
            'console.log("Hello World!");',
            self._deobfuscate(source),
        )

    def test_in_predicate_builtin_on_nonempty_function(self):
        source = inspect.cleandoc(
            """
            function handler(x) { return x + 1; }
            if ("hasOwnProperty" in handler) {
                live();
            } else {
                dead();
            }
            """
        )
        self.assertEqual(
            'live();',
            self._deobfuscate(source),
        )


class TestParenthesizedExpressionStripping(TestJsDeobfuscator):

    def test_iife_parens_preserved(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                (function() {
                  var x = 1;
                  console.log(x);
                })();
                """
            ),
            self._simplify('(function(){ var x = 1; console.log(x); })();'),
        )

    def test_bare_identifier_parens_stripped(self):
        self.assertEqual('var x = y;', self._simplify('var x = (y);'))


class TestFunctionEvaluator(TestJsDeobfuscator):

    def _evaluate(self, source: str) -> str:
        from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator
        return self._run_transformer(source, JsFunctionEvaluator)

    def test_simple_arithmetic(self):
        source = inspect.cleandoc(
            """
            function calc(op, a, b) {
                switch (op) {
                    case 'add': return a + b;
                    case 'sub': return a - b;
                    case 'mul': return a * b;
                }
            }
            var x = calc('add', 10, 20);
            var y = calc('sub', 100, 42);
            var z = calc('mul', 3, 7);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 30;', result)
        self.assertIn('var y = 58;', result)
        self.assertIn('var z = 21;', result)
        self.assertNotIn('function calc', result)

    def test_string_decoder_xor(self):
        source = inspect.cleandoc(
            """
            function decode(encoded, key) {
                var result = '';
                for (var i = 0; i < encoded.length; i++) {
                    result += String.fromCharCode(encoded.charCodeAt(i) ^ key);
                }
                return result;
            }
            var msg = decode('Kfool', 3);
            """
        )
        result = self._evaluate(source)
        self.assertIn("'Hello'", result)
        self.assertNotIn('function decode', result)

    def test_switch_lookup_single_arg(self):
        source = inspect.cleandoc(
            """
            function lookup(key) {
                switch (key) {
                    case 'a': return 'alpha';
                    case 'b': return 'beta';
                    case 'c': return 'gamma';
                }
            }
            var x = lookup('b');
            var y = lookup('a');
            """
        )
        result = self._evaluate(source)
        self.assertIn("var x = 'beta';", result)
        self.assertIn("var y = 'alpha';", result)
        self.assertNotIn('function lookup', result)

    def test_irreducible_expression_member_access(self):
        source = inspect.cleandoc(
            """
            function getGlobal(mapping) {
                switch (mapping) {
                    case 'a': return globalVar['console'];
                    case 'b': return globalVar['Object'];
                }
            }
            var x = getGlobal('a');
            """
        )
        result = self._evaluate(source)
        self.assertIn("globalVar['console']", result)
        self.assertNotIn('function getGlobal', result)

    def test_iife_evaluation(self):
        source = inspect.cleandoc(
            """
            var x = (function(a, b) { return a + b; })(10, 20);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var x = 30;', result)

    def test_iife_arrow_function(self):
        source = inspect.cleandoc(
            """
            var x = ((a, b) => a * b)(6, 7);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var x = 42;', result)

    def test_impure_function_not_evaluated(self):
        source = inspect.cleandoc(
            """
            function impure(x) {
                console.log(x);
                return x + 1;
            }
            var y = impure(5);
            """
        )
        result = self._evaluate(source)
        self.assertIn('function impure', result)
        self.assertIn('impure(5)', result)

    def test_non_literal_args_skipped(self):
        source = inspect.cleandoc(
            """
            function add(a, b) { return a + b; }
            var x = add(1, y);
            """
        )
        result = self._evaluate(source)
        self.assertIn('add(1, y)', result)

    def test_function_preserved_when_partial_resolution(self):
        source = inspect.cleandoc(
            """
            function add(a, b) { return a + b; }
            var x = add(1, 2);
            var y = add(3, z);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 3;', result)
        self.assertIn('add(3, z)', result)
        self.assertIn('function add', result)

    def test_nested_function_calls(self):
        source = inspect.cleandoc(
            """
            function double(x) { return x * 2; }
            function addDoubles(a, b) { return double(a) + double(b); }
            var result = addDoubles(3, 4);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var result = 14;', result)

    def test_string_methods(self):
        source = inspect.cleandoc(
            """
            function upper(s) { return s.toUpperCase(); }
            var x = upper('hello');
            """
        )
        result = self._evaluate(source)
        self.assertIn("'HELLO'", result)

    def test_array_operations(self):
        source = inspect.cleandoc(
            """
            function buildAndJoin(a, b, c) {
                var arr = [a, b, c];
                return arr.join('-');
            }
            var x = buildAndJoin('x', 'y', 'z');
            """
        )
        result = self._evaluate(source)
        self.assertIn("'x-y-z'", result)

    def test_dead_function_chain_removal(self):
        source = inspect.cleandoc(
            """
            function helper(x) { return x + 1; }
            function wrapper(x) { return helper(x) * 2; }
            var result = wrapper(5);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var result = 12;', result)
        self.assertNotIn('function helper', result)
        self.assertNotIn('function wrapper', result)

    def test_loop_safety_limit(self):
        source = inspect.cleandoc(
            """
            function infinite(x) {
                while (true) { x++; }
                return x;
            }
            var y = infinite(0);
            """
        )
        result = self._evaluate(source)
        self.assertIn('infinite(0)', result)

    def test_from_char_code(self):
        source = inspect.cleandoc(
            """
            function decode(a, b, c) {
                return String.fromCharCode(a, b, c);
            }
            var x = decode(72, 105, 33);
            """
        )
        result = self._evaluate(source)
        self.assertIn("'Hi!'", result)

    def test_array_map(self):
        source = inspect.cleandoc(
            """
            function transform(arr) {
                return arr.map(function(x) { return x * 2; });
            }
            var x = transform([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = [2, 4, 6];', result)

    def test_array_filter(self):
        source = inspect.cleandoc(
            """
            function evens(arr) {
                return arr.filter(function(x) { return x % 2 === 0; });
            }
            var x = evens([1, 2, 3, 4, 5, 6]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = [2, 4, 6];', result)

    def test_array_every(self):
        source = inspect.cleandoc(
            """
            function allPositive(arr) {
                return arr.every(function(x) { return x > 0; });
            }
            var a = allPositive([1, 2, 3]);
            var b = allPositive([1, -1, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var a = true;', result)
        self.assertIn('var b = false;', result)

    def test_array_some(self):
        source = inspect.cleandoc(
            """
            function hasNegative(arr) {
                return arr.some(function(x) { return x < 0; });
            }
            var a = hasNegative([1, -1, 3]);
            var b = hasNegative([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var a = true;', result)
        self.assertIn('var b = false;', result)

    def test_array_find(self):
        source = inspect.cleandoc(
            """
            function firstBig(arr) {
                return arr.find(function(x) { return x > 10; });
            }
            var x = firstBig([3, 7, 15, 20]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 15;', result)

    def test_array_find_index(self):
        source = inspect.cleandoc(
            """
            function indexOfBig(arr) {
                return arr.findIndex(function(x) { return x > 10; });
            }
            var x = indexOfBig([3, 7, 15, 20]);
            var y = indexOfBig([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 2;', result)
        self.assertIn('var y = -1;', result)

    def test_array_reduce(self):
        source = inspect.cleandoc(
            """
            function sum(arr) {
                return arr.reduce(function(acc, x) { return acc + x; }, 0);
            }
            var x = sum([1, 2, 3, 4]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 10;', result)

    def test_array_reduce_no_initial(self):
        source = inspect.cleandoc(
            """
            function product(arr) {
                return arr.reduce(function(acc, x) { return acc * x; });
            }
            var x = product([2, 3, 4]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = 24;', result)

    def test_array_map_with_arrow(self):
        source = inspect.cleandoc(
            """
            function encode(arr) {
                return arr.map(x => x + 1);
            }
            var x = encode([10, 20, 30]);
            """
        )
        result = self._evaluate(source)
        self.assertIn('var x = [11, 21, 31];', result)

    def test_atob_in_function(self):
        source = inspect.cleandoc(
            """
            function d(s) { return atob(s); }
            var x = d('SGVsbG8=');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

    def test_object_literal_parens_preserved(self):
        self.assertEqual('var x = ({ a: 1 });', self._simplify('var x = ({a: 1});'))


class TestIIFEAccessorPromoter(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        from refinery.lib.scripts.js.deobfuscation.iifeaccessor import JsIIFEAccessorPromoter
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def test_promotes_simple_accessor(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105], [66, 121, 101]];
                return function (i) { return data[i]; };
            }();
            """
        )
        result = self._promote(source)
        self.assertIn('function get(i)', result)
        self.assertNotIn('var get =', result)

    def test_fold_xor_accessor_pattern_end_to_end(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105], [66, 121, 101]];
                var shift = 28;
                var mask = 42;
                return function (i) {
                    var a = data[i];
                    if (!a) return "";
                    var r = "";
                    for (var j = 0; j < a.length; j++) {
                        var k = j >> shift & j << mask & (shift ^ shift) & 2047;
                        r += String.fromCharCode(a[j] ^ k);
                    }
                    return r;
                };
            }();
            document.write(get(0));
            document.write(get(1));
            """
        )
        result = self._deobfuscate_iterative(source)
        self.assertIn("'Hi'", result)
        self.assertIn("'Bye'", result)
        self.assertNotIn('function get', result)
        self.assertNotIn('var get', result)

    def test_does_not_promote_when_closure_is_mutated(self):
        source = inspect.cleandoc(
            """
            var counter = function () {
                var n = 0;
                return function () { n++; return n; };
            }();
            """
        )
        result = self._promote(source)
        self.assertNotIn('function counter(', result)
        self.assertIn('var counter =', result)

    def test_does_not_promote_when_param_collides_with_closure(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [1, 2, 3];
                return function (data) { return data; };
            }();
            """
        )
        result = self._promote(source)
        self.assertNotIn('function get(', result)

    def test_does_not_promote_non_literal_closure(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = computeData();
                return function (i) { return data[i]; };
            }();
            """
        )
        result = self._promote(source)
        self.assertNotIn('function get(', result)

    def test_promotes_through_parenthesised_iife(self):
        source = inspect.cleandoc(
            """
            var get = (function () {
                var data = [1, 2, 3];
                return function (i) { return data[i]; };
            })();
            """
        )
        result = self._promote(source)
        self.assertIn('function get(i)', result)

    def test_does_not_promote_self_referencing_named_function(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [1, 2, 3];
                return function rec(i) { return i <= 0 ? data[0] : rec(i - 1); };
            }();
            """
        )
        result = self._promote(source)
        self.assertNotIn('function get(', result)
        self.assertIn('var get =', result)


class TestParenthesisPreservation(TestJsDeobfuscator):

    def test_paren_preserved_when_inner_has_lower_precedence(self):
        self.assertEqual('var x = (a | b) & c;', self._simplify('var x = (a | b) & c;'))

    def test_paren_preserved_when_inner_is_ternary_inside_binop(self):
        self.assertEqual(
            'var x = (a ? b : c) + d;',
            self._simplify('var x = (a ? b : c) + d;'),
        )

    def test_paren_dropped_when_inner_has_higher_precedence(self):
        self.assertEqual('var x = a + b * c;', self._simplify('var x = a + (b * c);'))

    def test_paren_dropped_around_primary(self):
        self.assertEqual('var x = a + b;', self._simplify('var x = (a) + (b);'))

    def test_paren_preserved_for_right_side_of_same_precedence(self):
        self.assertEqual('var x = a - (b - c);', self._simplify('var x = a - (b - c);'))

    def test_paren_dropped_for_left_side_of_same_precedence(self):
        self.assertEqual('var x = a - b - c;', self._simplify('var x = (a - b) - c;'))

    def test_paren_preserved_for_conditional_as_ternary_test(self):
        self.assertEqual(
            'var x = (a ? b : c) ? d : e;',
            self._simplify('var x = (a ? b : c) ? d : e;'),
        )

    def test_paren_preserved_for_assignment_as_ternary_test(self):
        self.assertEqual(
            'var x = (a = b) ? c : d;',
            self._simplify('var x = (a = b) ? c : d;'),
        )

    def test_paren_preserved_for_numeric_literal_member_object(self):
        self.assertEqual(
            'var x = (5).toString();',
            self._simplify('var x = (5).toString();'),
        )

    def test_paren_dropped_for_numeric_literal_computed_member(self):
        self.assertEqual('var x = 5[k];', self._simplify('var x = (5)[k];'))

    def test_paren_preserved_for_nested_negation(self):
        self.assertEqual('var x = -(-a);', self._simplify('var x = -(-a);'))

    def test_paren_preserved_for_nested_unary_plus(self):
        self.assertEqual('var x = +(+a);', self._simplify('var x = +(+a);'))

    def test_paren_dropped_for_double_logical_not(self):
        self.assertEqual('var x = !!a;', self._simplify('var x = !(!a);'))

    def test_paren_preserved_for_unary_base_of_exponentiation(self):
        self.assertEqual('var x = (-a) ** b;', self._simplify('var x = (-a) ** b;'))

    def test_paren_preserved_for_call_as_new_callee(self):
        self.assertEqual('var x = new (f())();', self._simplify('var x = new (f())();'))

    def test_paren_preserved_for_logical_as_new_callee(self):
        self.assertEqual('var x = new (a || b)();', self._simplify('var x = new (a || b)();'))

    def test_paren_preserved_for_call_in_new_callee_spine(self):
        self.assertEqual('var x = new (a().b)();', self._simplify('var x = new (a().b)();'))

    def test_paren_dropped_for_member_chain_new_callee(self):
        self.assertEqual('var x = new a.b.c();', self._simplify('var x = new (a.b.c)();'))


class TestScrambleStringDecoder(TestJsDeobfuscator):

    def test_cipher_decode_known_values(self):
        from refinery.lib.scripts.js.deobfuscation.scramble import ScrambleCipher
        cipher = ScrambleCipher(
            '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6',
            'fec5863b88643968ecff0c2c8afecbaf',
        )
        self.assertEqual(
            cipher.decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg='),
            'https://api.github.com',
        )
        self.assertEqual(
            cipher.decode('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s='),
            'python-requests/2.31.0',
        )

    def test_decode_substitution(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var ua = decode('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            var ua = 'python-requests/2.31.0';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_non_scramble_class_not_touched(self):
        source = inspect.cleandoc(
            """
            class Foo {
              constructor(x) { this.value = x; }
              decode(y) { return y + this.value; }
            }
            var f = new Foo('hello');
            var r = f.decode('world');
            """
        )
        expected = inspect.cleandoc(
            """
            class Foo {
              constructor(x) {
                this.value = x;
              }
              decode(y) {
                return y + this.value;
              }
            }
            var f = new Foo('hello');
            var r = f.decode('world');
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_global_this_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            var exportName = 'fc2edea72';
            globalThis[exportName] = decode;
            var url = fc2edea72('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            var ua = fc2edea72('PdaZMbIlb6aDIHKgEhD+FRU4eXKoDLt3WpefwvGwKH2ZARsbP7s=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            var ua = 'python-requests/2.31.0';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_global_dot_access_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            global.decode = decode;
            var url = decode('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)

    def test_global_string_key_alias(self):
        source = inspect.cleandoc(
            """
            class Scramble {
              constructor(pw, salt) {
                this.masterKey = pb(pw, salt, 200000, 32, 'sha256');
                this.rounds = 3;
              }
              decode(input) { return decrypt(input, this.masterKey, this.rounds); }
            }
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var instance = new Scramble(key, salt);
            function decode(x) { return instance.decode(x); }
            globalThis['fc2edea72'] = decode;
            var url = fc2edea72('hJQxp9Pvj3X2QId3C4RuMOe1C4EpuSg2b/8JyqzSWjrQm+VgNNg=');
            """
        )
        expected = inspect.cleandoc(
            """
            var key = '2aaa9053353088d4d49b5bf32f403f2d85b3df97c9a9beedfcdbb1ecc27ba9c6';
            var salt = 'fec5863b88643968ecff0c2c8afecbaf';
            var url = 'https://api.github.com';
            """
        )
        self.assertEqual(self._run_transformer(source, JsScrambleStringDecoder), expected)
