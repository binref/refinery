"""
Programs that read a constant inside recursive code: a function that calls itself, two that call
each other, and a function only such code calls. A function on a call cycle is invoked first
through a read of it from outside the cycle, so the constant reaches every invocation exactly when
it is defined before every such read. Also the three names `undefined`, `NaN` and `Infinity` as
constant values, and a long string read many times inside recursive code.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
)

#: Programs that define an array before the first call into recursive code reading it, mapped to
#: what Node prints for them.
AN_ARRAY_DEFINED_BEFORE_RECURSIVE_CODE_RUNS = {
    a_program("""
        const a = [7, 8, 9];
        function f(n) { return n > 0 ? f(n - 1) + a[1] : a[0]; }
        console.log(f(2));
        """): '23\n',
    a_program("""
        const a = [7, 8];
        function g() { return a[1]; }
        function f(n) { return n > 0 ? f(n - 1) + g() : a[0]; }
        console.log(f(2));
        """): '23\n',
    a_program("""
        var a = [7, 8];
        function f(n) { return n > 0 ? f(n - 1) : a[0]; }
        console.log(f(3));
        """): '7\n',
    a_program("""
        const a = [7, 8];
        function f(n) { return n > 0 ? g(n - 1) : a[0]; }
        function g(n) { return f(n) + a[1]; }
        console.log(f(2));
        """): '23\n',
}

#: Programs that call into recursive code reading an array before the array is defined, mapped to
#: the error Node ends them with.
AN_ARRAY_DEFINED_AFTER_RECURSIVE_CODE_RUNS = {
    a_program("""
        function f(n) { return n > 0 ? f(n - 1) : a[0]; }
        console.log(f(1));
        const a = [7, 8];
        """): 'ReferenceError',
    a_program("""
        function f(n) { return n > 0 ? f(n - 1) : a[0]; }
        console.log(f(1));
        var a = [7, 8];
        """): 'TypeError',
    a_program("""
        function f(n) { return n > 0 ? g(n - 1) : a[0]; }
        function g(n) { return f(n); }
        console.log(g(1));
        const a = [7, 8];
        """): 'ReferenceError',
}

#: Programs holding `undefined`, `NaN` and `Infinity` in constants and reading them inside a function
#: whose own parameters carry those names, mapped to what Node prints for them.
A_GLOBAL_VALUE_READ_WHERE_ITS_NAME_MEANS_A_PARAMETER = {
    a_program("""
        const u = [undefined, NaN, Infinity];
        function f(undefined, NaN, Infinity) { return [u[0], u[1], u[2]]; }
        console.log(f(1, 2, 3));
        """): '[ undefined, NaN, Infinity ]\n',
    a_program("""
        const x = undefined, y = NaN, z = Infinity;
        function f(undefined, NaN, Infinity) { return [x, y, z]; }
        console.log(f(1, 2, 3));
        """): '[ undefined, NaN, Infinity ]\n',
}

#: A program whose array holds a parameter named `undefined`, which is no constant, mapped to what
#: Node prints for it.
AN_ELEMENT_NAMING_A_PARAMETER_CALLED_UNDEFINED = {
    a_program("""
        function g(undefined) {
          const b = [undefined, 2];
          function h() { return b[0]; }
          return h();
        }
        console.log(g(5));
        """): '5\n',
}

#: A program reading a string longer than the inliner pastes five times inside a recursive
#: function, mapped to what Node prints for it.
A_LONG_STRING_READ_OFTEN_IN_RECURSIVE_CODE = {
    a_program("""
        const s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_';
        function f(n) {
          return n > 0 ? f(n - 1) + s.charAt(n) + s[n] + s.length + s.indexOf('z') + s.slice(0, 1) : '';
        }
        console.log(f(2));
        """): 'bb6625acc6625a\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAConstantReadInRecursiveCode(TestBase):

    def test_an_array_defined_first_still_prints_the_same(self):
        rows = AN_ARRAY_DEFINED_BEFORE_RECURSIVE_CODE_RUNS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_an_array_defined_after_the_first_call_still_throws(self):
        rows = AN_ARRAY_DEFINED_AFTER_RECURSIVE_CODE_RUNS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (('', error), ('', error)) for source, error in rows.items()},
        )

    def test_a_global_value_still_prints_the_same(self):
        rows = {
            **A_GLOBAL_VALUE_READ_WHERE_ITS_NAME_MEANS_A_PARAMETER,
            **AN_ELEMENT_NAMING_A_PARAMETER_CALLED_UNDEFINED,
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_long_string_still_prints_the_same(self):
        rows = A_LONG_STRING_READ_OFTEN_IN_RECURSIVE_CODE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAConstantReadInRecursiveCodeIsFolded(TestBase):

    def test_an_array_defined_first_is_folded(self):
        rows = AN_ARRAY_DEFINED_BEFORE_RECURSIVE_CODE_RUNS
        self.assertEqual(
            {source: 'a[' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )

    def test_an_array_defined_after_the_first_call_is_not_folded(self):
        rows = AN_ARRAY_DEFINED_AFTER_RECURSIVE_CODE_RUNS
        self.assertEqual(
            {source: 'a[0]' in deobfuscate_source(source, module=True) for source in rows},
            {source: True for source in rows},
        )

    def test_a_global_value_is_written_as_its_value(self):
        rows = A_GLOBAL_VALUE_READ_WHERE_ITS_NAME_MEANS_A_PARAMETER
        written = '[void 0, 0 / 0, 1e999]'
        self.assertEqual(
            {source: written in deobfuscate_source(source, module=True) for source in rows},
            {source: True for source in rows},
        )

    def test_an_element_naming_a_parameter_is_not_a_constant(self):
        source, = AN_ELEMENT_NAMING_A_PARAMETER_CALLED_UNDEFINED
        self.assertNotIn('void 0', deobfuscate_source(source, module=True))

    def test_a_long_string_is_written_once(self):
        source, = A_LONG_STRING_READ_OFTEN_IN_RECURSIVE_CODE
        self.assertEqual(deobfuscate_source(source, module=True).count('abcdefghijklmnop'), 1)
