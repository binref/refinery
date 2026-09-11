"""
A call handed the global object may read and write any global.

A classic script's top-level declarations are properties of the global object, so a call the object
is passed to reaches every one of them under its own name — `a(globalThis, 'q')` lets `a` write the
`q` the file declares. No identifier in the file names that reference, so a walk over the text finds
none, and a remover that reads only what the text spells folds a value across the write and deletes a
declaration the callee still reads.

`refinery.lib.scripts.js.analysis.model.SemanticModel._record_global_object_alias_references` records
those references, the way the references a mapped `arguments` object makes are recorded against the
parameters it aliases. The cost rows below are the other half: what the object is not, and which
bindings it does not carry, both of which must still fold.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import a_program, before_and_after_in_a_host, folded


#: A classic script handing the global object to a call, mapped to what a host prints for it.
A_CALL_IS_HANDED_THE_GLOBAL_OBJECT = {
    'a write through it reaches a declaration': a_program("""
        var q = 1;
        function a(g, k) { g[k] = 2; }
        a(globalThis, 'q');
        console.log(q);
        """),
    'the top level hands over its own this': a_program("""
        var q = 1;
        function a(g, k) { g[k] = 2; }
        a(this, 'q');
        console.log(q);
        """),
    'a read through it is a read of the declaration': a_program("""
        var q = 1;
        function a(g, k) { console.log(g[k]); }
        a(this, 'q');
        """),
    'a call through it is a call of the declaration': a_program("""
        var q = function () { console.log('q'); };
        function a(g, k) { g[k](); }
        a(globalThis, 'q');
        """),
    'a function declaration is a property too': a_program("""
        function q() { console.log('q'); }
        function a(g, k) { g[k](); }
        a(globalThis, 'q');
        """),
    'a new expression receives it as well': a_program("""
        var q = 1;
        function C(g) { g.q = 2; }
        new C(globalThis);
        console.log(q);
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallHandedTheGlobalObjectReachesEveryGlobal(TestBase):
    """
    Read under the script execution model, which is the one the unit runs by default and the only one
    in which a top-level declaration is a property of the global object at all.
    """

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_CALL_IS_HANDED_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


#: Cost-side programs whose fold must not admit one reference too many, mapped to the text the fold
#: must produce. A local spelled like the object is not the object, and a binding the object does not
#: carry is not reached through it, so each must still fold across the hand-over.
_WHAT_IS_NOT_THE_GLOBAL_OBJECT = {
    'a local spelled like the object is not it': (
        a_program("""
            var q = 1;
            function f(window) { console.log(window); }
            f(0);
            console.log(q);
            """),
        a_program("""
            function f(window) {
              console.log(window);
            }
            f(0);
            console.log(1);
            """).rstrip(chr(10)),
    ),
    'the object carries no local of the callee': (
        a_program("""
            function a(g) { return g; }
            function m() { var t = 3; a(globalThis); return t; }
            console.log(m());
            """),
        a_program("""
            function a(g) {
              return g;
            }
            function m() {
              a(globalThis);
              return 3;
            }
            console.log(m());
            """).rstrip(chr(10)),
    ),
}


class TestWhatIsNotTheGlobalObjectStillFolds(TestBase):
    """
    The cost side. A reference is recorded for every global the file declares at each hand-over, so
    the two ways of admitting one too many are asked here: a local spelled like the object, and a
    binding the object does not carry.
    """

    def test_each_cost_row_folds_to_the_pinned_text(self):
        for label, (source, expected) in _WHAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatIsNotTheGlobalObjectFoldsWithoutChangingBehaviour(TestBase):
    """
    The pinned text a cost row folds to says nothing on its own about whether the fold kept the
    program's behavior: a reduction to the wrong value is text too. Read each under the script model
    the fold is written for, so a fold that dropped a real read or moved a value fails here.
    """

    def test_each_cost_row_behaves_the_way_the_host_does(self):
        for label, (source, _) in _WHAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


#: A wrapper that reads the global object it is handed only as the `thisArg` of an `apply`/`call` to
#: a payload never reads a property of the object, unless the payload reads its own `this` — the one
#: way the receiver reaches the payload. The obfuscator's self-defending wrapper is this shape.
_APPLIES_A_THIS_FREE_PAYLOAD = a_program("""
    var q = 1;
    var wrap = (function () {
      var once = true;
      return function (self, payload) {
        var run = once ? function () { return payload.apply(self, []); } : function () {};
        return once = false, run;
      };
    })();
    wrap(this, function () { console.log('hi'); })();
    """)

_APPLIES_A_PAYLOAD_THAT_READS_THIS = a_program("""
    var q = 1;
    function a(g, b) { console.log(b.apply(g)); }
    a(this, function () { return this.q; });
    """)

#: The apply target held a `this`-reader when the apply ran and was reassigned to a `this`-free
#: function only afterwards. A receiver gate that answers from the reassigned value alone deems the
#: hand-over unobserved and deletes the global the payload read through its `this`.
_APPLY_TARGET_REASSIGNED_AFTER_THE_APPLY_RAN = a_program("""
    var secret = 'S';
    function inner(host) { return host.secret; }
    function wrap(recv) {
      var t = function () { return inner(this); };
      var r = t.apply(recv, []);
      t = function () { return 'plain'; };
      return r;
    }
    console.log(wrap(globalThis));
    """)

#: The apply target is a parameter of the call that hands the object over, reassigned to a
#: `this`-reader before the apply runs. The set of values the parameter can hold at that call
#: contains the handed argument and the reassignment both, and one of them reads the receiver, so a
#: gate that judges the call-site argument alone hands the payload a receiver it then deems unread.
_APPLY_TARGET_PARAMETER_REASSIGNED_BEFORE_THE_APPLY = a_program("""
    var secret = 'S';
    function inner(host) { return host.secret; }
    function wrap(recv, payload) {
      payload = function () { return inner(this); };
      return payload.apply(recv, []);
    }
    console.log(wrap(this, function () {}));
    """)

#: Nothing assigns over the target parameter, but the `apply` dispatched at the call is not the
#: intrinsic: an own `apply` property — written directly, installed with `Object.defineProperty`,
#: copied on by `Object.assign`, written through a second name for the same object or by a helper
#: the object is handed to — or an inherited one, from a swapped prototype or a `Function`
#: prototype poisoned under any spelling — receives the handed object as a plain argument and
#: forwards it. The `arguments` row rebinds the parameter itself through the mapped object
#: instead.
_A_DISPLACED_APPLY_FORWARDS_THE_RECEIVER = {
    'an own apply property forwards the receiver': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          payload.apply = function (r) { return inner(r); };
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a defineProperty install forwards the receiver': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          Object.defineProperty(payload, 'apply', { value: function (r) { return inner(r); } });
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'an alias writes the own apply property': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          var other = payload;
          other.apply = function (r) { return inner(r); };
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a two-valued alias writes the own apply property': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload, flag) {
          var other = flag ? payload : payload;
          other.apply = function (r) { return inner(r); };
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}, 1));
        """),
    'a helper handed the target installs the forwarder': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function install(x) { x.apply = function (r) { return inner(r); }; }
        function wrap(recv, payload) {
          install(payload);
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'an assign copies the forwarder onto the target': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          Object.assign(payload, { apply: function (r) { return inner(r); } });
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a prototype swap makes the forwarder inherited': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          Object.setPrototypeOf(payload, { apply: function (r) { return inner(r); } });
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a chain write through the target poisons the prototype': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          payload.__proto__.apply = function (r) { return inner(r); };
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a constructor-reached prototype forwards the receiver': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        (function () {}).constructor.prototype.apply = function (r) { return inner(r); };
        function wrap(recv, payload) {
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'the arguments object rebinds the target parameter': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        function wrap(recv, payload) {
          arguments[1] = function () { return inner(this); };
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
    'a poisoned prototype apply forwards the receiver': a_program("""
        var secret = 'S';
        function inner(host) { return host.secret; }
        Function.prototype.apply = function (r) { return inner(r); };
        function wrap(recv, payload) {
          return payload.apply(recv, []);
        }
        console.log(wrap(this, function () {}));
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWrapperApplyingAPayloadBehavesTheWayTheHostDoes(TestBase):
    """
    Read under the script execution model. Whether the wrapper's payload reads the global object it
    is applied to or not, the deobfuscation prints what the host prints.
    """

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in {
            'a this-free payload never reads the object': _APPLIES_A_THIS_FREE_PAYLOAD,
            'a payload reads the object through its this': _APPLIES_A_PAYLOAD_THAT_READS_THIS,
            'a reassigned target held a this-reader at the apply': _APPLY_TARGET_REASSIGNED_AFTER_THE_APPLY_RAN,
            'a parameter reassigned before the apply held both values': _APPLY_TARGET_PARAMETER_REASSIGNED_BEFORE_THE_APPLY,
            **_A_DISPLACED_APPLY_FORWARDS_THE_RECEIVER,
        }.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


class TestAnUnobservedHandOverFreesWhatAnObservedOneKeeps(TestBase):
    """
    A global reached by nothing the text spells is removed when the only call handed the global
    object cannot read a property through it, and kept when it can. This is the cost of the whole
    admission narrowed to the hand-over that observes: a payload applied without reading its `this`
    frees the object, a payload that reads its `this` keeps what it reads.
    """

    def test_an_apply_thisarg_only_hand_over_frees_an_unreferenced_global(self):
        self.assertEqual(folded(_APPLIES_A_THIS_FREE_PAYLOAD), a_program("""
            var wrap = (function() {
              var once = true;
              return function(self, payload) {
                var run = once ? function() {
                  return payload.apply(self, []);
                } : function() {};
                return once = false, run;
              };
            })();
            wrap(this, function() {
              console.log('hi');
            })();
            """).rstrip(chr(10)))

    def test_a_payload_reading_this_keeps_the_global_it_reads(self):
        self.assertEqual(folded(_APPLIES_A_PAYLOAD_THAT_READS_THIS), a_program("""
            var q = 1;
            function a(g, b) {
              console.log(b.apply(g));
            }
            a(this, function() {
              return this.q;
            });
            """).rstrip(chr(10)))

    def test_a_truth_guarded_apply_still_frees_an_unreferenced_global(self):
        source = a_program("""
            var q = 1;
            function wrap(recv, payload) {
              if (payload) {
                return payload.apply(recv, []);
              }
            }
            console.log(wrap(this, function () { return 'hi'; }));
            """)
        self.assertEqual(folded(source), a_program("""
            function wrap(recv, payload) {
              if (payload) {
                return payload.apply(recv, []);
              }
            }
            console.log(wrap(this, function() {
              return 'hi';
            }));
            """).rstrip(chr(10)))
