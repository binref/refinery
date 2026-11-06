from __future__ import annotations

import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable

from refinery.units.scripting.djs import djs
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

_ASTRAL = chr(0x1F600)

_ASTRAL_LITERAL = F"'a{_ASTRAL}b'"

_ASTRAL_PRODUCED = "decodeURIComponent('a%F0%9F%98%80b')"

_DECIDED: dict[str, tuple[str, str]] = {
    "'abc'.length"                     : ('3', '3'),
    "'abc'['length']"                  : ('3', '3'),
    "'abc'['leng' + 'th']"             : ('3', '3'),
    "''.length"                        : ('0', '0'),
    "'abc'[0]"                         : ("'a'", 'S[97]'),
    "'abc'[2]"                         : ("'c'", 'S[99]'),
    "'abc'['1']"                       : ("'b'", 'S[98]'),
    "'abc'[1.0]"                       : ("'b'", 'S[98]'),
    "'abc'[0x1]"                       : ("'b'", 'S[98]'),
    "'abc'[-0]"                        : ("'a'", 'S[97]'),
    "'abc'[2 - 1]"                     : ("'b'", 'S[98]'),
    "'abc'[true ? 1 : 2]"              : ("'b'", 'S[98]'),
    "atob('SGVsbG8=').length"          : ('5', '5'),
    "atob('SGVsbG8=')[1]"              : ("'e'", 'S[101]'),
    "unescape('%48%65')[1]"            : ("'e'", 'S[101]'),
    """JSON.parse('"hi"').length"""    : ('2', '2'),
    "'ABC'.toLowerCase()[1]"           : ("'b'", 'S[98]'),
    "'ab'.repeat(5000).length"         : ('10000', '10000'),
    F'{_ASTRAL_LITERAL}.length'        : ('4', '4'),
    F'{_ASTRAL_LITERAL}[1]'            : (R"'\uD83D'", 'S[55357]'),
    F'{_ASTRAL_LITERAL}[2]'            : (R"'\uDE00'", 'S[56832]'),
    F'{_ASTRAL_LITERAL}[3]'            : ("'b'", 'S[98]'),
    F'{_ASTRAL_PRODUCED}.length'       : ('4', '4'),
    F'{_ASTRAL_PRODUCED}[1]'           : (R"'\uD83D'", 'S[55357]'),
    F'{_ASTRAL_PRODUCED}[2]'           : (R"'\uDE00'", 'S[56832]'),
    F'{_ASTRAL_PRODUCED}[3]'           : ("'b'", 'S[98]'),
}

#: A key is an index only in its canonical spelling: the strings `'01'`, `'-0'`, `'1.0'` and `' 1'`
#: name no character, while the numbers `-0` and `1.0` convert to the keys `'0'` and `'1'`.
_NO_PROTOTYPE_HOLDS = [
    "'abc'[3]",
    "'abc'[9]",
    "'abc'[4294967295]",
    "'abc'[-1]",
    "''[0]",
    "'abc'['-0']",
    "'abc'['01']",
    "'abc'['00']",
    "'abc'['1.0']",
    "'abc'[0.5]",
    "'abc'[' 1']",
    "'abc'.nope",
    "'abc'['nope']",
    "'abc'[NaN]",
    "'abc'[void 0]",
    F'{_ASTRAL_LITERAL}[4]',
]

_LEFT_STANDING: dict[str, str] = {
    "'abc'.charAt"            : "'abc'.charAt",
    "'abc'['charAt']"         : "'abc'.charAt",
    "'abc'.toUpperCase"       : "'abc'.toUpperCase",
    "'abc'.constructor"       : "'abc'.constructor",
    "'abc'.__proto__"         : "'abc'.__proto__",
}

_A_KEY_AN_UNTOUCHED_METHOD_CONVERTS: dict[str, tuple[str, str]] = {
    "'abc'[[1]]"    : ("'b'", 'S[98]'),
    "'abc'[['1']]"  : ("'b'", 'S[98]'),
    "'abc'[[1, 2]]" : ('void 0', 'undefined'),
}

_A_KEY_A_PROTOTYPE_METHOD_CONVERTS: dict[str, tuple[str, str]] = {
    "'abc'[{}]"     : ("'abc'[{}]", 'undefined'),
}

_A_REPLACED_CONVERSION_DECIDES_THE_KEY: dict[str, str] = {
    "Array.prototype.join = function () { return '2'; }; console.log('abc'[[1]]);": 'c\n',
    "Array.prototype.toString = function () { return '2'; }; console.log('abc'[[1]]);": 'c\n',
    "Object.prototype.toString = function () { return '1'; }; console.log('abc'[{}]);": 'b\n',
}

_CALLING_WHAT_THE_STRING_DECIDES: dict[str, tuple[str, str]] = {
    "'abc'.length()"     : ("'abc'.length()", '"abc".length is not a function'),
    "'abc'['length']()"  : ("'abc'.length()", '"abc".length is not a function'),
    "'abc'[0]()"         : ("'abc'[0]()", '"abc"[0] is not a function'),
    "'abc'['1']()"       : ("'abc'['1']()", '"abc".1 is not a function'),
    "'abc'.length?.()"   : ("'abc'.length?.()", '"abc".length is not a function'),
    "'abc'.length`x`"    : ("'abc'.length`x`", '"abc".length is not a function'),
    "new ('abc'.length)()": ("new ('abc'.length)()", '"abc".length is not a constructor'),
    "new ('abc'[0])()"   : ("new ('abc'[0])()", '"abc"[0] is not a constructor'),
    "new ('abc'.length)" : ("new ('abc'.length)()", '"abc".length is not a constructor'),
}

#: Folding one of these reads would put a string literal at the top of the body, which continues the
#: Directive Prologue: a `'use strict'` right below it would then make the code strict.
_A_READ_AT_THE_TOP_OF_A_BODY: dict[str, str] = {
    "'abc'[0];"                     : "'abc'[0];",
    "'abc'['0'];"                   : "'abc'['0'];",
    "'abc'[1 - 1];"                 : "'abc'[0];",
    "atob('YQ==')[0];"              : "'a'[0];",
    "decodeURIComponent('%61')[0];" : "'a'[0];",
    "'ABC'.toLowerCase()[0];"       : "'abc'[0];",
}

_REPORTS_ITS_MODE = 'function probe() { return this; } console.log(probe() === undefined);'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _simplified(source: str) -> str:
    ast = JsParser(source).parse()
    instance = JsSimplifications()
    instance.options = None
    instance.visit(ast)
    return JsSynthesizer().convert(ast)


def _fold(expression: str) -> str:
    printed = _deobfuscated(F'console.log({expression});')
    return printed.removeprefix('console.log(').removesuffix(');')


def _caught_message(call: str) -> str:
    return F'try {{ {call}; }} catch (e) {{ console.log(e.message); }}'


def _a_script_whose_directive_stands_below(head: str) -> str:
    return F"{head}\n'use strict';\n{_REPORTS_ITS_MODE}"


def _the_head_it_is_left_as(head: str) -> str:
    return _simplified(_a_script_whose_directive_stands_below(head)).splitlines()[0]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class _NodeDecides(TestBase):

    def _preserves(self, source: str):
        deobfuscated = source.encode('utf8') | djs(strict=True) | str
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )


class TestAReadTheStringDecides(TestBase):

    def test_length_and_an_index_in_range_fold_to_a_constant(self):
        for expression, (folded, _) in _DECIDED.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_the_folded_constant_from_the_access_it_replaced(self):
        expressions = list(_DECIDED)
        answers = code_units(expressions)
        replacements = code_units([_DECIDED[e][0] for e in expressions])
        for expression, answer, replacement in zip(expressions, answers, replacements):
            with self.subTest(expression=expression):
                expected = _DECIDED[expression][1]
                self.assertEqual((answer, replacement), (expected, expected))


class TestAReadNoPrototypeAnswers(TestBase):

    def test_a_key_no_prototype_holds_folds_to_undefined(self):
        for expression in _NO_PROTOTYPE_HOLDS:
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), 'void 0')

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_undefined_for_each_of_them(self):
        self.assertEqual(code_units(_NO_PROTOTYPE_HOLDS), ['undefined'] * len(_NO_PROTOTYPE_HOLDS))


class TestAReadTheStringDoesNotDecide(TestBase):

    def test_a_key_no_string_owns_is_left_standing(self):
        for expression, standing in _LEFT_STANDING.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), standing)

    def test_a_length_off_a_number_or_a_boolean_is_left_standing_or_folds_to_undefined(self):
        for expression in ['(1).length', 'true.length']:
            with self.subTest(expression=expression):
                self.assertIn(_fold(expression), (expression, 'void 0'))

    def test_a_method_that_is_only_a_name_when_read_still_folds_when_called(self):
        self.assertEqual(_fold("'abc'['charAt'](1)"), "'b'")
        self.assertEqual(_fold("'abc'.toUpperCase()"), "'ABC'")


class TestAKeyThatIsNotAPrimitive(TestBase):

    def test_a_key_an_untouched_method_converts_folds_to_what_it_names(self):
        for expression, (folded, _) in _A_KEY_AN_UNTOUCHED_METHOD_CONVERTS.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_the_folded_value_from_the_access_it_replaced(self):
        reads = _A_KEY_AN_UNTOUCHED_METHOD_CONVERTS
        expressions = list(reads)
        answers = code_units(expressions)
        replacements = code_units([reads[e][0] for e in expressions])
        for expression, answer, replacement in zip(expressions, answers, replacements):
            with self.subTest(expression=expression):
                expected = reads[expression][1]
                self.assertEqual((answer, replacement), (expected, expected))

    def test_a_key_a_prototype_method_converts_is_left_standing_or_folds_to_undefined(self):
        for expression, (standing, _) in _A_KEY_A_PROTOTYPE_METHOD_CONVERTS.items():
            with self.subTest(expression=expression):
                self.assertIn(_fold(expression), (standing, 'void 0'))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_answers_each_read_with_what_the_untouched_conversion_names(self):
        reads = _A_KEY_A_PROTOTYPE_METHOD_CONVERTS
        self.assertEqual(
            code_units(list(reads)),
            [answer for _, answer in reads.values()],
        )


class TestAReplacedConversionDecidesWhichPropertyIsNamed(_NodeDecides):

    def test_node_reads_the_property_the_replaced_conversion_names(self):
        for source, printed in _A_REPLACED_CONVERSION_DECIDES_THE_KEY.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (printed, None))

    def test_a_replaced_conversion_still_decides_after_deobfuscation(self):
        for source in _A_REPLACED_CONVERSION_DECIDES_THE_KEY:
            with self.subTest(source=source):
                self._preserves(source)


class TestNoPrototypeCanShadowAnOwnProperty(_NodeDecides):

    def test_a_prototype_length_does_not_reach_a_string_that_has_its_own(self):
        self._preserves("String.prototype.length = 99; console.log('abc'.length);")

    def test_a_prototype_index_does_not_reach_an_index_the_string_holds(self):
        self._preserves("String.prototype[0] = 'X'; console.log('abc'[0]);")

    def test_length_cannot_even_be_redefined_on_the_prototype(self):
        self._preserves(
            "Object.defineProperty(String.prototype, 'length', "
            '{get: function () { return 99; }});'
            " console.log('abc'.length);"
        )


class TestTheReadsThatAreLeftToTheEngine(_NodeDecides):

    def test_a_prototype_index_past_the_end_is_still_found(self):
        for source in [
            "String.prototype[3] = 'X'; console.log('abc'[3]);",
            "String.prototype[9] = 'X'; console.log('abc'[9]);",
            "Object.defineProperty(String.prototype, '5', {value: 'Q'}); console.log('abc'[5]);",
            F"String.prototype[4] = 'X'; console.log({_ASTRAL_PRODUCED}[4]);",
            F"String.prototype[4] = 'X'; console.log({_ASTRAL_LITERAL}[4]);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_a_prototype_name_that_is_not_an_index_is_still_found(self):
        for source in [
            "String.prototype.nope = 'Y'; console.log('abc'.nope);",
            "String.prototype['01'] = 'Z'; console.log('abc'['01']);",
            "String.prototype['-0'] = 'Z'; console.log('abc'['-0']);",
            "String.prototype[' 1'] = 'Z'; console.log('abc'[' 1']);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_a_method_name_is_a_function_and_not_what_calling_it_would_answer(self):
        for source in [
            "console.log(typeof 'abc'.charAt, typeof 'abc'['charAt']);",
            "console.log(typeof 'abc'.constructor, typeof 'abc'.toUpperCase);",
            "console.log('abc'.charAt.length, 'abc'.charAt.name);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_a_receiver_that_is_no_live_string_keeps_what_it_did(self):
        for source in [
            'console.log(undefined.length);',
            'console.log(null[0]);',
            'console.log((void 0).length);',
            'console.log((1).length, true.length, (0 / 0).length);',
            "console.log(new String('abc').length);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)


class TestAnAccessThatIsNotARead(_NodeDecides):

    def test_a_destructuring_target_survives_as_a_target(self):
        for source in [
            "['abc'[0]] = ['z']; console.log('abc'[0]);",
            "({k: 'abc'[0]} = {k: 'z'}); console.log('abc'[0]);",
            "[decodeURIComponent('abc')[0]] = ['z']; console.log('abc'[0]);",
            "[{}.x, 'abc'.length] = [1, 2]; console.log('abc'.length);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_a_for_of_target_survives_as_a_target(self):
        for source in [
            "for ('abc'[0] of ['z']) ; console.log('abc'[0]);",
            "for ('abc'.length of [9]) ; console.log('abc'.length);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_an_assignment_that_a_strict_file_refuses_still_throws(self):
        for source in [
            "'use strict'; 'abc'.length = 9; console.log('not reached');",
            "'use strict'; 'abc'[0] = 'z'; console.log('not reached');",
            "'use strict'; console.log(delete 'abc'[0]);",
            "'use strict'; console.log(delete 'abc'.length);",
            "'use strict'; console.log('abc'.length++);",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_a_produced_string_is_a_target_the_same_way_a_literal_is(self):
        for source in [
            "console.log(decodeURIComponent('abc').length = 9);",
            """console.log(JSON.parse('"abc"')[0]++);""",
            "console.log(delete 'ABC'.toLowerCase()[0]);",
            "console.log(decodeURIComponent('abc')[0] += 'q');",
        ]:
            with self.subTest(source=source):
                self._preserves(source)

    def test_calling_what_an_own_property_answers_throws_either_way(self):
        for source in [
            "console.log('abc'.length());",
            "console.log('abc'[0]());",
            "console.log('abc'.length?.());",
            "console.log(new ('abc'.length)());",
            "console.log('abc'.length`x`);",
            "'use strict'; console.log('abc'[1]());",
        ]:
            with self.subTest(source=source):
                self._preserves(source)


class TestACalleeIsReadForItsReceiverToo(TestBase):

    def test_a_callee_survives_deobfuscation_as_an_access(self):
        for call, (standing, _) in _CALLING_WHAT_THE_STRING_DECIDES.items():
            with self.subTest(call=call):
                self.assertEqual(_fold(call), standing)

    def test_a_read_inside_a_callee_is_folded(self):
        self.assertIn(_fold("'abc'.length.toFixed()"), ('(3).toFixed()', "'3'"))
        self.assertEqual(_fold("'abc'[0].toUpperCase()"), "'A'")

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_type_error_names_the_access_and_not_the_value_it_reads(self):
        for call, (_, message) in _CALLING_WHAT_THE_STRING_DECIDES.items():
            source = _caught_message(call)
            said = (F'{message}\n', None)
            with self.subTest(call=call):
                self.assertEqual((behavior(source), behavior(_deobfuscated(source))), (said, said))


class TestAReadThatWouldOpenADirectivePrologue(TestBase):

    def test_a_read_standing_at_the_top_of_a_script_is_left_standing(self):
        for head, standing in _A_READ_AT_THE_TOP_OF_A_BODY.items():
            with self.subTest(head=head):
                self.assertEqual(_the_head_it_is_left_as(head), standing)

    def test_a_read_below_a_statement_that_is_no_directive_still_folds(self):
        self.assertEqual(
            _simplified("console.log(1);\n'abc'[0];"),
            "console.log(1);\n'a';",
        )

    @opportunity
    def test_a_read_below_a_statement_that_is_no_directive_is_removed_with_its_statement(self):
        self.assertEqual(
            _deobfuscated("console.log(1);\n'abc'[0];"),
            'console.log(1);',
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_use_strict_below_the_read_is_no_directive_before_or_after(self):
        for head in _A_READ_AT_THE_TOP_OF_A_BODY:
            source = _a_script_whose_directive_stands_below(head)
            sloppy = ('false\n', None)
            with self.subTest(head=head):
                self.assertEqual(
                    (behavior(source), behavior(_deobfuscated(source))),
                    (sloppy, sloppy),
                )
