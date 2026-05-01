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
from refinery.lib.scripts.js.deobfuscation.cff import _strip_trailing_flow
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
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
        self.assertEqual("'a', 'b', 'c';", self._simplify("'a', 'b', 'c';"))

    def test_tuple_non_literal_unchanged(self):
        self.assertEqual("'a', x, 'c';", self._simplify("'a', x, 'c';"))

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
        result = self._simplify("'\\u4f60\\u597d';")
        self.assertNotIn('\\u', result)

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
        self.assertEqual(
            self._deobfuscate(source),
            inspect.cleandoc(
                """
                function real(n) {
                  return n + 1;
                }
                console.log(real(5));
                """
            ),
        )

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
        self.assertNotIn('QUMXw', result)
        self.assertNotIn('smFRR', result)
        self.assertIn("'positive'", result)
        self.assertIn("'negative'", result)
        self.assertIn("'zero'", result)

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
        result = self._deobfuscate(source)
        self.assertNotIn('(((.+)+)+)+$', result)
        self.assertIn('var a', result)
        self.assertIn('console.log', result)


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
        result = self._inline(source)
        self.assertIn('var x', result)

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
            function fizzbuzz(n) {
              var results = [];
              for (var i = 1; i <= n; i++) {
                if (i % 15 === 0) {
                  results.push('FizzBuzz');
                } else {
                  if (i % 3 === 0) {
                    results.push('Fizz');
                  } else {
                    if (i % 5 === 0) {
                      results.push('Buzz');
                    } else {
                      results.push(i);
                    }
                  }
                }
              }
              return results;
            }
            console.log(fizzbuzz(20));
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
        result = self._deobfuscate(source)
        self.assertNotIn('function d(', result)
        self.assertNotIn('var p', result)
        self.assertIn('abc(5)', result)
        self.assertIn('return x + 1', result)

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
        result = self._deobfuscate(source)
        self.assertNotIn('function d(', result)
        self.assertIn('f1(2, 3)', result)
        self.assertIn('f2(', result)
        self.assertIn('return a + b', result)
        self.assertIn('return a * b', result)

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
        result = self._deobfuscate(source)
        self.assertNotIn('function d(', result)
        self.assertNotIn('new d(', result)
        self.assertNotIn('"wk"', result)

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
        result = self._objectfold(source)
        self.assertIn('var o', result)


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
        self.assertIn('.push', result)
        self.assertIn('.log', result)

    def test_decoder_and_accessor_removed(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertNotIn('function decode', result)
        self.assertNotIn('function accessor', result)

    def test_property_access_rewritten(self):
        result = self._deobfuscate(self._minimal_sample())
        self.assertIn('results.push', result)
        self.assertIn('console.log', result)

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
        self.assertIn('results.push', result)
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
        self.assertIn("results.push", result)
        self.assertIn("console.log", result)
        self.assertIn("items.push", result)

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
        result = self._deobfuscate(source)
        self.assertIn('results.push', result)
        self.assertIn('console.log', result)
        self.assertNotIn('table', result)
        self.assertNotIn('function decode', result)
        self.assertNotIn('function accessor', result)

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
            'inner();',
        ])
        result = self._deobfuscate(source)
        self.assertIn('console.log', result)
        self.assertNotIn("'aa'", result)
        self.assertIn('function inner', result)
        self.assertIn('table', result)


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
        result = self._remove_unused(source)
        self.assertIn('function helper', result)
        self.assertIn('function main', result)
        self.assertNotIn('function orphan', result)

    def test_identifier_as_value_makes_reachable(self):
        source = inspect.cleandoc(
            """
            function callback() { return 1; }
            function unused() { return 2; }
            var x = callback;
            """
        )
        result = self._remove_unused(source)
        self.assertIn('function callback', result)
        self.assertNotIn('function unused', result)

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
        result = self._remove_unused(source)
        self.assertIn('function main', result)
        self.assertNotIn('dead_inside', result)

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
        result = self._remove_unused(source)
        self.assertNotIn('x = 42', result)
        self.assertIn('function foo', result)
        self.assertIn('console.log', result)

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
        result = self._remove_unused(source)
        self.assertNotIn('x =', result)
        self.assertIn('sideEffect()', result)

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
            console.log((f1(1, undefined, 3)));
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
        result = self._deobfuscate(source)
        self.assertIn("console.log('side effect');", result)

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
        result = self._inline(source)
        self.assertIn('console.log(a + b)', result)

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
        result = self._deobfuscate(source)
        self.assertIn('console.log(x)', result)

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
        result = self._objectfold(source)
        self.assertIn('g()', result)
        self.assertEqual(result.count('g()'), 1)

    def test_objectfold_getter_not_folded(self):
        source = 'var o = { get x() { return 1; } }; o.x;'
        result = self._objectfold(source)
        self.assertIn('get x', result)

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
        self.assertIn('console.log(x)', result)
        self.assertNotIn('console.log(1)', result)

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
