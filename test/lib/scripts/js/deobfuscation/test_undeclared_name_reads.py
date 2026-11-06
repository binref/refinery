from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


class _Program(NamedTuple):
    source: str
    printed: str
    error: str | None = None


class _Rewrite(NamedTuple):
    """
    A program, the text the deobfuscator reduces it to, and the partial reductions it may stop at
    instead, each of which behaves as the program does.
    """
    source: str
    result: str
    short_of_it: tuple[str, ...] = ()


_ONLY_THE_UNREAD_RANDOM_LEFT = inspect.cleandoc(
    """
    var unfoldable = Math.random();
    console.log('after');
    """
)


_A_READ_WHOSE_NAME_MAY_NOT_EXIST: dict[str, _Program] = {
    'a bare expression statement': _Program(
        inspect.cleandoc(
            """
            function f() {
              missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a returned value': _Program(
        inspect.cleandoc(
            """
            function f() {
              return missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'an argument to another call': _Program(
        inspect.cleandoc(
            """
            function g(a) {
              return 1;
            }
            function f() {
              return g(missing);
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a shorthand object key': _Program(
        inspect.cleandoc(
            """
            function f() {
              var o = { missing };
              return o;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'an object property value': _Program(
        inspect.cleandoc(
            """
            function f() {
              return { held: missing };
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'an array element': _Program(
        inspect.cleandoc(
            """
            function f() {
              return [missing];
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a template placeholder': _Program(
        inspect.cleandoc(
            """
            function f() {
              return `${missing}`;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a computed property key': _Program(
        inspect.cleandoc(
            """
            function f() {
              return { x: 1 }[missing];
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'the condition of a branch': _Program(
        inspect.cleandoc(
            """
            function f() {
              if (missing) {
                return 1;
              }
              return 2;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a name only a function nothing calls assigns': _Program(
        inspect.cleandoc(
            """
            function never() {
              later = 1;
            }
            function f() {
              return later;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a name an assignment creates only after the call': _Program(
        inspect.cleandoc(
            """
            function f() {
              return boot;
            }
            var q = f();
            boot = 1;
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a host name the specification does not mandate': _Program(
        inspect.cleandoc(
            """
            function f() {
              return document;
            }
            var q = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
}
"""
Programs in which one name decides what happens, mapped to what Node makes of each. Every row is a
program the deobfuscator takes away entirely — function, call and read — the moment that read counts
as harmless, and what comes back then runs to the end and prints a line the original never reached.
"""

_REDUCED: dict[str, _Rewrite] = {
    'a name that spells the global object': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              return unfoldable === globalThis;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a global the specification mandates': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              return Math.max(unfoldable, 1);
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a declared global': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              return unfoldable;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a local declaration of the name': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              var missing = unfoldable;
              return missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a catch parameter': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              try {
                return unfoldable;
              } catch (missing) {
                return missing;
              }
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'an object key read back as a property name': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              return { missing: unfoldable }.missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a parameter': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f(missing) {
              return missing + 1;
            }
            var q = f(unfoldable);
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a label': _Rewrite(
        inspect.cleandoc(
            """
            var unfoldable = Math.random();
            function f() {
              missing: {
                break missing;
              }
              return unfoldable;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
        (_ONLY_THE_UNREAD_RANDOM_LEFT,),
    ),
    'a typeof of a name nothing binds': _Rewrite(
        inspect.cleandoc(
            """
            function f() {
              return typeof missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
    ),
    'a delete of a name nothing binds': _Rewrite(
        inspect.cleandoc(
            """
            function f() {
              return delete missing;
            }
            var q = f();
            console.log('after');
            """
        ),
        "console.log('after');",
    ),
    'the function nothing calls that holds the only assignment': _Rewrite(
        inspect.cleandoc(
            """
            function never() {
              later = 1;
            }
            function guarded() {
              return typeof later;
            }
            var q = guarded();
            console.log(later);
            """
        ),
        'console.log(later);',
    ),
}
"""
A program the deobfuscator must still reduce, mapped to the text it reduces it to and the texts
short of that it may leave instead. Each function returns a value no folder can compute, so removing
its discarded call is the only rewrite that can take the program away and the answer turns entirely
on what the read inside it is worth: a gate that refused every read would hand back every row with
its function and its call in place. The last row asks for both directions at once: the function
nothing calls goes, and the read that outlives it is not answered with the value that function would
have stored.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReadOfANameThatMayNotDenoteABinding(TestJsDeobfuscator):

    def test_node_does_what_each_row_records(self):
        for name, program in _A_READ_WHOSE_NAME_MAY_NOT_EXIST.items():
            with self.subTest(name=name):
                self.assertEqual(behavior(program.source), (program.printed, program.error))

    def test_the_deobfuscated_program_does_the_same(self):
        for name, program in _A_READ_WHOSE_NAME_MAY_NOT_EXIST.items():
            with self.subTest(name=name):
                deobfuscated = self._deobfuscate(program.source)
                self.assertEqual(
                    behavior(deobfuscated),
                    (program.printed, program.error),
                    F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
                )


class TestAReadThatCannotThrowIsStillReduced(TestJsDeobfuscator):

    def test_each_program_is_reduced_to_the_row_text_or_left_short_of_it(self):
        for name, rewrite in _REDUCED.items():
            with self.subTest(name=name):
                self.assertIn(self._deobfuscate(rewrite.source), (rewrite.result, *rewrite.short_of_it))

    @opportunity
    def test_each_program_with_a_text_short_of_it_is_reduced_to_the_row_text(self):
        rows = _REDUCED.items()
        for name, rewrite in ((name, rewrite) for name, rewrite in rows if rewrite.short_of_it):
            with self.subTest(name=name):
                self.assertEqual(self._deobfuscate(rewrite.source), rewrite.result)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_does_the_same_for_each_program_and_each_text_it_may_be_left_as(self):
        for name, rewrite in _REDUCED.items():
            for text in (rewrite.result, *rewrite.short_of_it):
                with self.subTest(name=name, text=text):
                    self.assertEqual(behavior(rewrite.source), behavior(text))


_A_PARAMETER_DEFAULT_THAT_DECIDES_THE_CALL: dict[str, _Program] = {
    'a plain parameter default': _Program(
        inspect.cleandoc(
            """
            function f(a = missing) {
              return 1;
            }
            var y = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a function expression parameter default': _Program(
        inspect.cleandoc(
            """
            var f = function (a = missing) {
              return 1;
            };
            var y = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'an arrow parameter default': _Program(
        inspect.cleandoc(
            """
            var f = (a = missing) => 1;
            var y = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a default inside an object pattern': _Program(
        inspect.cleandoc(
            """
            function f({ a = missing } = {}) {
              return 1;
            }
            var y = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a default inside an array pattern': _Program(
        inspect.cleandoc(
            """
            function f([a = missing] = []) {
              return 1;
            }
            var y = f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a second default the call passes nothing for': _Program(
        inspect.cleandoc(
            """
            function f(a, b = missing) {
              return 1;
            }
            var y = f(1);
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a default in front of a body that prints': _Program(
        inspect.cleandoc(
            """
            function f(a = missing) {
              console.log('body');
            }
            f();
            console.log('after');
            """
        ),
        '',
        'ReferenceError',
    ),
    'a default the call passes an argument for': _Program(
        inspect.cleandoc(
            """
            function f(a = missing) {
              return a;
            }
            console.log(f(4));
            console.log('after');
            """
        ),
        '4\nafter\n',
    ),
}
"""
Programs in which a parameter default decides what happens, mapped to what Node makes of each. A
default is evaluated by every call that omits its argument, before the body is entered, so a default
reading a name nothing binds ends such a call in a `ReferenceError` and the body never runs. Most
rows put the call's result in a variable nothing reads, which is the shape a deobfuscator deletes a
call in, so what the default does is what decides whether the deletion is allowed. The last row is
the control a blanket refusal of parameter lists cannot pass: the call passes an argument, the
default is never evaluated, and the program prints.
"""

_A_PARAMETER_DEFAULT_THAT_CANNOT_THROW: dict[str, _Rewrite] = {
    'a default reading a declared global': _Rewrite(
        inspect.cleandoc(
            """
            var ok = 5;
            function f(a = ok) {
              return a;
            }
            console.log(f());
            """
        ),
        'console.log(5);',
    ),
    'a default inside an object pattern reading a declared global': _Rewrite(
        inspect.cleandoc(
            """
            var ok = 5;
            function f({ a = ok } = {}) {
              return a;
            }
            console.log(f());
            """
        ),
        'console.log(5);',
        (
            inspect.cleandoc(
                """
                function f({ a = 5 } = {}) {
                  return a;
                }
                console.log(f());
                """
            ),
        ),
    ),
    'an arrow default the folder can compute': _Rewrite(
        inspect.cleandoc(
            """
            var g = (a = 'x' + 'y') => a;
            console.log(g());
            """
        ),
        "console.log('xy');",
    ),
}
"""
A program whose parameter default reads only what is bound, mapped to the text the deobfuscator
reduces it to and the texts short of that it may leave instead. Reducing inside a default is what a
refusal to look at parameter lists at all would cost, so these rows are what keeps the rows above
from being passed by refusing everything.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterDefaultDecidesWhetherACallThrows(TestJsDeobfuscator):

    def test_node_does_what_each_row_records(self):
        for name, program in _A_PARAMETER_DEFAULT_THAT_DECIDES_THE_CALL.items():
            with self.subTest(name=name):
                self.assertEqual(behavior(program.source), (program.printed, program.error))

    def test_the_deobfuscated_program_does_the_same(self):
        for name, program in _A_PARAMETER_DEFAULT_THAT_DECIDES_THE_CALL.items():
            with self.subTest(name=name):
                deobfuscated = self._deobfuscate(program.source)
                self.assertEqual(
                    behavior(deobfuscated),
                    (program.printed, program.error),
                    F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
                )


class TestAParameterDefaultThatCannotThrowIsStillReduced(TestJsDeobfuscator):

    def test_each_program_is_reduced_to_the_row_text_or_left_short_of_it(self):
        for name, rewrite in _A_PARAMETER_DEFAULT_THAT_CANNOT_THROW.items():
            with self.subTest(name=name):
                self.assertIn(self._deobfuscate(rewrite.source), (rewrite.result, *rewrite.short_of_it))

    @opportunity
    def test_each_program_with_a_text_short_of_it_is_reduced_to_the_row_text(self):
        rows = _A_PARAMETER_DEFAULT_THAT_CANNOT_THROW.items()
        for name, rewrite in ((name, rewrite) for name, rewrite in rows if rewrite.short_of_it):
            with self.subTest(name=name):
                self.assertEqual(self._deobfuscate(rewrite.source), rewrite.result)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_does_the_same_for_each_program_and_each_text_it_may_be_left_as(self):
        for name, rewrite in _A_PARAMETER_DEFAULT_THAT_CANNOT_THROW.items():
            for text in (rewrite.result, *rewrite.short_of_it):
                with self.subTest(name=name, text=text):
                    self.assertEqual(behavior(rewrite.source), behavior(text))
