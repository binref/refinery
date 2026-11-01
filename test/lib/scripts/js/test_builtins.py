"""
The table of functions the language installs on the prototypes, checked against Node.
"""
from __future__ import annotations

import inspect
import json
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.lib.scripts.js.builtins import ALIASED_METHODS, PROTOTYPE_METHODS

#: A program printing, for each constructor of `PROTOTYPE_METHODS`, every function-valued own
#: property of its prototype but `constructor`, each with the `name` of the function it holds and
#: the other keys holding the same function.
_THE_PROTOTYPES_OF_NODE = inspect.cleandoc("""
    var owners = {Object: Object, Function: Function, Array: Array, String: String, Number: Number, Boolean: Boolean, RegExp: RegExp};
    var table = {};
    Object.keys(owners).forEach(function (owner) {
      var prototype = owners[owner].prototype;
      var methods = {};
      Object.getOwnPropertyNames(prototype).forEach(function (key) {
        var value = Object.getOwnPropertyDescriptor(prototype, key).value;
        if (key === 'constructor' || typeof value !== 'function') return;
        methods[key] = {
          name: value.name,
          same: Object.getOwnPropertyNames(prototype).filter(function (other) {
            return other !== key && Object.getOwnPropertyDescriptor(prototype, other).value === value;
          }).sort()
        };
      });
      table[owner] = methods;
    });
    console.log(JSON.stringify(table));
""")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestThePrototypeMethodsAreNodes(TestBase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        stdout, error = behavior(_THE_PROTOTYPES_OF_NODE)
        if error is not None:
            raise AssertionError(F'node refused the program: {error}')
        cls.node = json.loads(stdout)

    def test_each_prototype_holds_the_methods_the_table_lists(self):
        for owner, methods in PROTOTYPE_METHODS.items():
            with self.subTest(owner=owner):
                self.assertEqual(methods, frozenset(self.node[owner]))

    def test_each_method_is_named_by_its_key_or_by_the_key_it_is_an_alias_of(self):
        for owner, methods in PROTOTYPE_METHODS.items():
            for key in methods:
                with self.subTest(owner=owner, key=key):
                    self.assertEqual(self.node[owner][key]['name'], ALIASED_METHODS.get((owner, key), key))

    def test_two_keys_hold_one_function_exactly_where_the_table_says_so(self):
        for owner, methods in PROTOTYPE_METHODS.items():
            for key in methods:
                canonical = ALIASED_METHODS.get((owner, key), key)
                aliases = {alias for (o, alias), name in ALIASED_METHODS.items() if o == owner and name == canonical}
                expected = sorted(({canonical} | aliases) - {key})
                with self.subTest(owner=owner, key=key):
                    self.assertEqual(self.node[owner][key]['same'], expected)
