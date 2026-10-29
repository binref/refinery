from __future__ import annotations

import inspect
import re

from test import TestBase
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
    wontfix,
)

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.stringarray import (
    Encoding,
    JsStringArrayResolver,
    _CACHE_ATTR,
    _detect_encoding,
    _find_all_accessor_functions,
    _find_array_function,
)
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


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
        self.assertEqual("console.log('test string');", result)

    def test_string_array_without_rotation(self):
        """
        The obfuscator leaves the array unrotated, so there is no rotation IIFE to simulate and the
        array literal already holds the strings in the order the accessor reads them.
        """
        result = self._deobfuscate(_UNROTATED_SOURCE)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_indices_spelled_as_strings(self):
        preset = self._default_preset()
        source = preset.replace(
            '_0xe6abe5(0xac)', "_0xe6abe5('0xac')"
        ).replace(
            '_0xe6abe5(0xa8)', "_0xe6abe5('0xa8')"
        )
        self.assertEqual(preset.count('_0xe6abe5('), source.count("_0xe6abe5('0x"))
        self.assertEqual("console.log('test string');", self._deobfuscate(source))

    def test_string_array_checksum_indices_spelled_as_strings(self):
        preset = self._default_preset()
        source = re.sub(r'_0x2bca43\((0x[0-9a-f]+)\)', r"_0x2bca43('\1')", preset)
        self.assertEqual(preset.count('_0x2bca43(0x'), source.count("_0x2bca43('0x"))
        self.assertEqual("console.log('test string');", self._deobfuscate(source))

    def test_string_array_index_string_that_is_no_number_keeps_its_call(self):
        """
        Python's `int` reads `'1_72'` as 172, the position `0xac` names; the decoder's subtraction
        reads it as `NaN`, and the array holds nothing there.
        """
        source = self._default_preset().replace('_0xe6abe5(0xac)', "_0xe6abe5('1_72')")
        self.assertIn("var msg = _0x1b07('1_72');", self._deobfuscate(source).splitlines())

    def test_string_array_parameter_named_like_the_decoder_keeps_its_call(self):
        source = self._default_preset() + 'function g(_0x1b07){return _0x1b07(0xac);}unknown(g);'
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('test string');
                function g(_0x1b07) {
                  return _0x1b07(0xac);
                }
                unknown(g);
                """
            ),
            self._deobfuscate(source),
        )

    def test_string_array_local_named_like_an_alias_keeps_its_call(self):
        source = self._default_preset() + (
            'function g(){var _0xe6abe5=unknown();return _0xe6abe5(0xac);}unknown(g);'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('test string');
                function g() {
                  var _0xe6abe5 = unknown();
                  return _0xe6abe5(0xac);
                }
                unknown(g);
                """
            ),
            self._deobfuscate(source),
        )

    def test_string_array_index_read_from_an_object_stored_to_after_its_literal(self):
        """
        The call reads `0xa8`, the index the store wrote, which names `'log'` in this preset. The
        call either stays or becomes that string; the literal's `0xac` names the other one.
        """
        source = self._default_preset() + 'var o={k:0xac};o.k=0xa8;console.log(_0xe6abe5(o.k));'
        result = self._deobfuscate(source)
        self.assertIn(result.splitlines()[-1], {
            'console.log(_0x1b07(o.k));',
            "console.log('log');",
        })

    def test_string_array_decoder_that_changes_its_index_before_subtracting_is_not_read(self):
        """
        The decoder swaps positions 0 and 1 before it subtracts its offset, and the array lists the
        two strings the other way around, so the program still logs the string. Reading the decoder
        as if the subtraction came first swaps the two strings.
        """
        source = _UNROTATED_SOURCE.replace(
            '_0x3a2c1f=_0x3a2c1f-0x0;',
            '_0x3a2c1f=0x1-_0x3a2c1f;_0x3a2c1f=_0x3a2c1f-0x0;',
        ).replace(
            r"['log','test\x20string']",
            r"['test\x20string','log']",
        )
        self.assertEqual(_UNROTATED_SOURCE.count('_0x3a2c1f=') + 1, source.count('_0x3a2c1f='))
        self.assertIn(r"['test\x20string','log']", source)
        result = self._deobfuscate(source)
        self.assertIn(result.splitlines()[-1], {
            'console[_0x1b07(0x0)](msg);',
            "console.log('test string');",
        })

    def test_string_array_decoder_with_a_fractional_offset_is_not_read(self):
        """
        The decoder reads positions `0.5` and `-0.5`, which name no element, so both calls answer
        `undefined`. Truncating the offset to zero reads the two strings instead.
        """
        source = _UNROTATED_SOURCE.replace('_0x3a2c1f-0x0;', '_0x3a2c1f-0.5;')
        self.assertNotEqual(_UNROTATED_SOURCE, source)
        self.assertEqual('console[_0x1b07(0x0)](msg);', self._deobfuscate(source).splitlines()[-1])

    def test_string_array_self_overwriting_decoder_reusing_its_parameter_names(self):
        source = (
            "function V(){var a=['str0','str1','str2'];V=function(){return a;};return V();}"
            'function N(t,n){const Y=V();N=function(t,n){t=t-0x10;let R=Y[t];return R;};return N(t,n);}'
            'console.log(N(0x11));'
        )
        self.assertEqual("console.log('str1');", self._deobfuscate(source))

    def test_string_array_self_overwriting_decoder_that_changes_its_index_before_forwarding(self):
        """
        The outer function adds one to the index before it hands it on, so `N(0x10)` reads `'str1'`.
        Reading the call as if the index went on untouched reads `'str0'`.
        """
        source = (
            "function V(){var a=['str0','str1','str2'];V=function(){return a;};return V();}"
            'function N(t,n){const Y=V();t=t+0x1;N=function(Z,o){Z=Z-0x10;let R=Y[Z];return R;};'
            'return N(t,n);}'
            'console.log(N(0x10));'
        )
        self.assertIn(self._deobfuscate(source).splitlines()[-1], {
            'console.log(N(0x10));',
            "console.log('str1');",
        })

    def test_string_array_decoder_declared_again_later_keeps_its_calls(self):
        """
        The later declaration is the function the name holds, so every call answers `'evil'`.
        """
        source = _UNROTATED_SOURCE + "function _0x1b07(a,b){return 'evil';}"
        self.assertEqual("console.evil('evil');", self._deobfuscate(source))

    def test_string_array_decoder_replaced_by_a_var_of_its_name_keeps_its_calls(self):
        """
        The `var` replaces the decoder before any call runs, so every call answers `'evil'`.
        """
        source = "var _0x1b07=function(a,b){return 'evil';};" + _UNROTATED_SOURCE
        self.assertEqual("console.evil('evil');", self._deobfuscate(source))

    def test_string_array_alias_a_module_exports_keeps_its_export(self):
        ast = JsParser(_UNROTATED_SOURCE + 'export const dec = _0x1b07;').parse()
        deobfuscate(ast, execution=ExecutionModel.module)
        result = JsSynthesizer().convert(ast).splitlines()
        self.assertIn("console.log('test string');", result)
        self.assertIn('export const dec = _0x1b07;', result)

    def test_string_array_rotation_that_stays_keeps_reading_the_array(self):
        """
        A call the pass cannot answer keeps the rotation, and the rotation has to keep turning the
        array that call reads. Answering the checksum's reads with the strings the turning ends on
        makes the loop stop before it turns.
        """
        source = self._default_preset() + 'function g(x){return _0xe6abe5(x);}unknown(g);'
        result = self._deobfuscate(source)
        self.assertIn('parseInt(_0x2bca43(0xa7))', result)
        self.assertIn("console.log('test string');", result.splitlines())

    def test_string_array_without_rotation_and_an_offset(self):
        source = _FOLDED_CHECKSUM_SOURCE.partition('}(_0x2fc0,0x827c2));')[2]
        self.assertTrue(source)
        result = self._deobfuscate(source)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_preset_beside_non_finite_object_property_values(self):
        """
        Each property value denotes `Infinity` or `NaN`, and neither names a position in a string
        array. Refusing such an expression is this pattern's own business; handing it to `int`
        instead ends the run before the rotation is ever resolved.
        """
        source = self._default_preset() + (
            'var cfg = { limit: 1e400 + 0, ratio: 1e400 * 0, span: 1e308 * 10 };'
        )
        self.assertEqual("console.log('test string');", self._deobfuscate(source))

    def test_string_array_preset_beside_non_finite_accessor_call_indices(self):
        """
        The same three values as the argument of an accessor call, which is the other place a
        resolved constant is read as an index into the string array. No folding turns one into a
        position, so those calls stand and the machinery stands with them while the function holding
        them does. Nothing calls that function, and once it is gone, nothing reads the machinery.
        """
        result = self._deobfuscate(A_PRESET_BESIDE_AN_ACCESSOR_CALL_NOTHING_CAN_ANSWER)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_rotation_iife_with_parenthesised_callee(self):
        preset = self._default_preset()
        variant = preset.replace(
            "}(_0x2fc0,0x827c2));",
            "})(_0x2fc0,0x827c2);",
            1,
        )
        self.assertNotEqual(preset, variant)
        result = self._deobfuscate(variant)
        self.assertEqual("console.log('test string');", result)

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
        self.assertEqual("console.log('test string');", result)

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
        self.assertEqual(
            inspect.cleandoc(
                """
                function greet(_0x3d7991) {
                  return 'Hello, ' + _0x3d7991 + '!';
                }
                """
            ),
            result,
        )

    def test_string_array_with_wrappers(self):
        source = (
            r"function _0xw(_0xa){return _0x1b07(_0xa- -0x0);}"
            + self._default_preset('_0xw')
        )
        result = self._deobfuscate(source)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_resolution_populates_cache(self):
        """
        A successful resolution stores the simulated array on the scope node so a later pipeline pass
        can reuse it if the simplifier rewrites the checksum expression in between; this checks the
        cache is populated after resolution.
        """
        source = self._default_preset()
        ast = JsParser(source).parse()
        resolver = JsStringArrayResolver()
        resolver.visit(ast)
        self.assertTrue(resolver.changed)
        cache = getattr(ast, _CACHE_ATTR, None)
        self.assertIsNotNone(cache)
        result = JsSynthesizer().convert(ast)
        self.assertEqual(
            inspect.cleandoc(
                """
                var msg = 'test string';
                console['log'](msg);
                """
            ),
            result,
        )

    def test_string_array_inside_function_body(self):
        source = 'function wrapper() { var _0xe6abe5=_0x1b07;' + self._DEFAULT_PRESET_BODY + '}'
        result = self._deobfuscate(source)
        expected = inspect.cleandoc(
            """
            function wrapper() {
              console.log('test string');
            }
            """
        )
        self.assertEqual(expected, result)

    def test_string_array_inline_if_checksum(self):
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
        result = self._deobfuscate(_FOLDED_CHECKSUM_SOURCE)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_multi_accessor(self):
        result = self._deobfuscate(_TWO_ACCESSOR_SOURCE)
        self.assertEqual("console.log('test string');", result)

    def test_string_array_accessors_with_different_offsets(self):
        """
        The second accessor subtracts one more than the first, and its call asks for one more, so
        both read the same strings as before. Reading the second call with the first accessor's
        offset reads the string after `'log'`.
        """
        second = 'function _0x2nd(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-'
        source = _TWO_ACCESSOR_SOURCE.replace(
            F'{second}0xa0;', F'{second}0xa1;'
        ).replace(
            '_0x2nd(0xa8)', '_0x2nd(0xa9)'
        )
        self.assertIn(F'{second}0xa1;', source)
        self.assertIn('_0x2nd(0xa9)', source)
        self.assertEqual("console.log('test string');", self._deobfuscate(source))

    def test_string_array_transitive_aliases(self):
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
        self.assertEqual("console.log('test string');", result)

    def test_string_array_self_overwriting_accessor_detected(self):
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
        accs = _find_all_accessor_functions(build_semantic_model(ast), ast.body, arr.name)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].name, 'N')
        self.assertEqual(accs[0].base_offset, 0xb2e - 0x126 - 0x8eb)
        self.assertEqual(_detect_encoding(accs[0].node), Encoding.RC4)

    def test_string_array_self_overwriting_accessor_b64(self):
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
        accs = _find_all_accessor_functions(build_semantic_model(ast), ast.body, arr.name)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].name, 'N')
        self.assertEqual(accs[0].base_offset, 0x14c)
        self.assertEqual(_detect_encoding(accs[0].node), Encoding.B64)

    def test_string_array_prop_map_accessor_calls(self):
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
            "console.log(x, y);"
        )
        expected = inspect.cleandoc(
            """
            console.log('secret_value', 'another_string');
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
            "console.log(foo());"
        )
        self.assertEqual("console.log('secretnested_val');", self._deobfuscate(source))


#: The default preset beside a function whose accessor calls read a non-finite index. No constant
#: folding turns one into a position in the string array, so the pass can answer none of the calls
#: and the accessor keeps the name each of them stands on.
A_PRESET_BESIDE_AN_ACCESSOR_CALL_NOTHING_CAN_ANSWER = TestStringArray._default_preset() + (
    'function unused() {'
    ' return _0xe6abe5(1e400 + 0) + _0xe6abe5(1e400 * 0) + _0xe6abe5(1e308 * 10); }'
)

#: The obfuscator's output with the string array left unrotated.
_UNROTATED_SOURCE = (
    r"function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0x0;var _0x2fc00e=_0x2fc0();var _0x"
    r"1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}var msg=_0x1b07(0x1);function _0x2fc0(){var _0x581e"
    r"61=['log','test\x20string'];_0x2fc0=function(){return _0x581e61;};return _0x2fc0();}console[_0x"
    r"1b07(0x0)](msg);"
)

#: The default preset with a second accessor beside the first, reading the same array.
_TWO_ACCESSOR_SOURCE = (
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

#: The default preset with the rotation loop left holding nothing but a constant-folded checksum,
#: so the array literal already spells the strings in the order the accessor reads them.
_FOLDED_CHECKSUM_SOURCE = (
    r"(function(_0x13a108,_0x20b5f6){var _0x36965a=_0x13a108();while(!![]){try{if(0x827c2===_0x20b5f6)brea"
    r"k;else _0x36965a['push'](_0x36965a['shift']());}catch(_0x35acf4){_0x36965a['push'](_0x36965a['shift'"
    r"]());}}}(_0x2fc0,0x827c2));function _0x1b07(_0x3a2c1f,_0x271b5b){_0x3a2c1f=_0x3a2c1f-0xa0;var _0x2fc"
    r"00e=_0x2fc0();var _0x1b0775=_0x2fc00e[_0x3a2c1f];return _0x1b0775;}var _0xe6abe5=_0x1b07;var msg=_0x"
    r"e6abe5(0xac);function _0x2fc0(){var _0x581e61=['12767458FlCTYp','2BveYOA','96VHQLDe','160CSMRCB','48"
    r"6kcIkKD','183450npXmbZ','4067550xFhrYl','462884STmCds','log','50725EqKMLb','48769HzjsUR','2435007zbg"
    r"ngY','test\x20string'];_0x2fc0=function(){return _0x581e61;};return _0x2fc0();}console[_0xe6abe5(0xa"
    r"8)](msg);"
)

#: A string array written out by hand: a holder that replaces itself on its first call and an
#: accessor that reads it by index, with no rotation, so the strings stand in the order written.
_A_HAND_WRITTEN_STRING_ARRAY = (
    "function A() { var s = ['hello', 'world']; A = function () { return s; }; return A(); }\n"
    'function ACC(i, k) { i = i - 0; var a = A(); var r = a[i]; return r; }\n'
)


class TestStringArrayShapesNoObfuscationEmits(TestBase):
    """
    Programs on which the resolver answers a decoder call that the program does not make, where
    only a shape made up for the defect reaches it.
    """

    @wontfix('the obfuscation declares each alias of the decoder first in the scope that calls it')
    def test_an_alias_called_before_its_declaration_runs(self):
        rows = {
            _A_HAND_WRITTEN_STRING_ARRAY + a_program(
                """
                function f() { return D(1); }
                try { console.log(f()); } catch (e) { console.log(e.constructor.name); }
                var D = ACC;
                """
            ): 'TypeError\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix('the obfuscation passes a decoder only literals: the index and, for RC4, the key')
    def test_a_decoder_call_passing_an_argument_with_an_effect(self):
        rows = {
            _A_HAND_WRITTEN_STRING_ARRAY + a_program(
                """
                var n = 0;
                console.log(ACC(1, n++), n);
                """
            ): 'world 1\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @wontfix('the decoder is named by the obfuscation, so no evaluated string assigns to its name')
    def test_a_decoder_rebound_by_an_unreadable_eval(self):
        rows = {
            a_program(
                """
                function main() {
                  function A() { var s = ['hello', 'world']; A = function () { return s; }; return A(); }
                  function ACC(i, k) { i = i - 0; var a = A(); var r = a[i]; return r; }
                  eval(Math.random() < 2 ? 'ACC = function () { return "evil"; };' : '');
                  console.log(ACC(1));
                }
                main();
                """
            ): 'evil\n',
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
