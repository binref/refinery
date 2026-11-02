"""
A call under a key the write scan cannot read.

The key of `Array.prototype[k](5)` may be `push`, which stores into every array, the key of
`Math[k]('floor', g)` may be `__defineGetter__`, which installs on `Math`, the key of
`Object[k](JSON, 'parse', d)` may be `defineProperty`, which installs on `JSON`, and the key of
`Object[k]([])` may be `getPrototypeOf`, which hands out a prototype under no name. An install on
the global object under a key the scan cannot read may replace any global. Each program writes such
a call with a key a later pass reads, or never reads, and then reads what the call wrote; each
deobfuscation leaves that read standing, and Node prints the same for the program and for every
deobfuscation of it.

An install throws where its function cannot be called or its descriptor is no object, so such a call
installs nothing, and a fold it would block still folds.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import a_program, before_and_after, each_program_still_prints

from refinery.units.scripting.djs import djs

_GETTER_OF_SEVEN = 'function () { return function () { return 7; }; }'
_GETTER_OF_X = "function () { return function () { return 'X'; }; }"
_GETTER_OF_A_MATH = 'function () { return {floor: function () { return 7; }}; }'

#: A program writing through a call under a key the scan cannot read, mapped to what it prints and to
#: the read the write decides.
_A_WRITE_UNDER_A_KEY_NOT_READ: dict[str, tuple[str, str]] = {
    "var k = ['push'][0]; Array.prototype[k](5); console.log([][0]);": ('5\n', '[][0]'),
    "var o = {k: 'push'}; Array.prototype[o.k](5); console.log([][0]);": ('5\n', '[][0]'),
    "function k() { return 'push'; } Array.prototype[k()](5); console.log([][0]);": ('5\n', '[][0]'),
    "var P = Array.prototype; P[['push']](5); console.log([][0]);": ('5\n', '[][0]'),
    F"var k = ['__defineGetter__'][0]; Math[k]('floor', {_GETTER_OF_SEVEN}); console.log(Math.floor(1.5));": (
        '7\n',
        'Math.floor(1.5)',
    ),
    F"var k = ['__defineGetter__'][0]; Math[k](...['floor', {_GETTER_OF_SEVEN}]); console.log(Math.floor(1.5));": (
        '7\n',
        'Math.floor(1.5)',
    ),
    "var k = ['getPrototypeOf'][0]; var P = Object[k]([]); P.x = 5; console.log([].x);": ('5\n', '[].x'),
    "var k = ['defineProperty'][0]; Object[k](JSON, 'parse', {value: function () { return 'X'; }}); console.log(JSON.parse('1'));": (
        'X\n',
        "JSON.parse('1')",
    ),
    "var k = ['defineProperty'][0]; Object[k](Object, 'keys', {value: function () { return 'X'; }}); console.log(Object.keys({a: 1}));": (
        'X\n',
        'Object.keys(',
    ),
    F"globalThis.__defineGetter__(String.fromCharCode(101, 115, 99, 97, 112, 101), {_GETTER_OF_X}); console.log(escape('a b'));": (
        'X\n',
        "escape('a b')",
    ),
    F"var k = Math.random() < 2 ? 'escape' : 'x'; globalThis.__defineGetter__(k, {_GETTER_OF_X}); console.log(escape('a b'));": (
        'X\n',
        "escape('a b')",
    ),
    F"(function (a) {{ return globalThis.__defineGetter__(a, {_GETTER_OF_A_MATH}); }})('Math'); console.log(Math.floor(1.5));": (
        '7\n',
        'Math.floor(1.5)',
    ),
}

#: A program whose call installs nothing, mapped to what it prints and to the text every deobfuscation
#: writes for the read after it.
_A_CALL_THAT_INSTALLS_NOTHING: dict[str, tuple[str, str]] = {
    "console.log(String[['fromCharCode']](104, 105));": ('hi\n', "console.log('hi');"),
    "try { Math.__defineGetter__('floor', 5); } catch (e) {} console.log(Math.floor(1.5));": (
        '1\n',
        'console.log(1);',
    ),
    "try { JSON.__defineGetter__('parse', 5); } catch (e) {} console.log(JSON.parse('1'));": (
        '1\n',
        'console.log(1);',
    ),
    "try { Object.defineProperty(JSON, 'parse', 5); } catch (e) {} console.log(JSON.parse('1'));": (
        '1\n',
        'console.log(1);',
    ),
    "var k = ['defineProperty'][0]; try { Object[k](JSON, 'parse', 5); } catch (e) {} console.log(JSON.parse('1'));": (
        '1\n',
        'console.log(1);',
    ),
}

#: Programs that install a key on every object through a method whose name an object holds, and read
#: that key off an object of their own, mapped to what Node prints: the reading object declared
#: before the one holding the name, and declared in a function nested in its scope. An obfuscator
#: stores the names a program spells in such objects, and the program itself is arbitrary.
_A_KEY_ANOTHER_OBJECT_READS_AFTER_A_COPY_INSTALLED_IT = {
    a_program("""
        var B = {x: 1};
        var A = {k: "defineProperty"};
        Object[A.k](Object.prototype, "q", {value: 1});
        console.log(B.q);
        """): '1\n',
    a_program("""
        var A = {k: "defineProperty"};
        Object[A.k](Object.prototype, "q", {value: 1});
        function t() { var B = {y: 1}; return B.q; }
        console.log(t());
        """): '1\n',
}

#: Each model and host a deobfuscation below is asked under.
_EVERY_MODE = [
    (False, 'universal'),
    (True, 'universal'),
    (False, 'node'),
]


def _deobfuscated(source: str, strict: bool, environment: str) -> str:
    return source.encode('utf8') | djs(strict=strict, environment=environment) | str


class TestAWriteUnderAKeyTheScanCannotReadIsSeen(TestBase):

    def test_each_deobfuscation_leaves_standing_the_read_the_write_decides(self):
        for source, (_, read) in _A_WRITE_UNDER_A_KEY_NOT_READ.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertIn(read, _deobfuscated(source, strict, environment))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records(self):
        for source, (prints, _) in _A_WRITE_UNDER_A_KEY_NOT_READ.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_prints_what_the_program_prints(self):
        for source, (prints, _) in _A_WRITE_UNDER_A_KEY_NOT_READ.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_key_another_object_reads_after_a_copy_installed_it_is_found(self):
        rows = _A_KEY_ANOTHER_OBJECT_READS_AFTER_A_COPY_INSTALLED_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestACallThatInstallsNothingBlocksNoFold(TestBase):

    def test_each_deobfuscation_folds_the_read(self):
        for source, (_, folded) in _A_CALL_THAT_INSTALLS_NOTHING.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertTrue(_deobfuscated(source, strict, environment).endswith(folded))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records(self):
        for source, (prints, _) in _A_CALL_THAT_INSTALLS_NOTHING.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_prints_what_the_program_prints(self):
        for source, (prints, _) in _A_CALL_THAT_INSTALLS_NOTHING.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))

