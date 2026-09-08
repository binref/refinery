from __future__ import annotations

import unittest

from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.deobfuscation.protospelling import JsPrototypeSpellingNormalization

#: Expressions that reach an intrinsic prototype without naming it, mapped to the statement each is
#: written back out as. The three object spellings name `Object.prototype` and the array one names
#: `Array.prototype`, which is the prototype an array literal actually inherits.
A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT = {
    '({}).__proto__.z = 9;':
        'Object.prototype.z = 9;',
    'Object.getPrototypeOf({}).z = 9;':
        'Object.prototype.z = 9;',
    '({}).constructor.prototype.z = 9;':
        'Object.prototype.z = 9;',
    '[].__proto__.z = 9;':
        'Array.prototype.z = 9;',
    'Object.getPrototypeOf([]).z = 9;':
        'Array.prototype.z = 9;',
    '[].constructor.prototype.z = 9;':
        'Array.prototype.z = 9;',
}

#: Programs whose spelling reaches something other than the intrinsic prototype, mapped to what
#: Node prints for each. Three replace the mechanism the spelling goes through — the `constructor`
#: a receiver inherits, `Object.getPrototypeOf`, and the `__proto__` accessor — and one binds the
#: name `Object` to an object of its own. Four more give an object literal a `__proto__` of its own,
#: which every spelling of that key does: written with a colon it sets the prototype, and written
#: as a shorthand or a computed key it installs an own property that shadows the accessor.
A_SPELLING_THAT_REACHES_SOMETHING_ELSE = {
    'Object.getPrototypeOf = function () { return {q: 5}; };'
    ' console.log(Object.getPrototypeOf({}).q);':
        '5\n',
    "Object.defineProperty(Object.prototype, '__proto__', {get: function () { return {q: 5}; }});"
    ' console.log(({}).__proto__.q);':
        '5\n',
    'var Object = {prototype: {q: 1}, getPrototypeOf: function () { return {q: 5}; }};'
    ' console.log(Object.getPrototypeOf({}).q);':
        '5\n',
    'console.log(({__proto__: {q: 5}}).__proto__.q);':
        '5\n',
    "console.log(({'__proto__': {q: 5}}).__proto__.q);":
        '5\n',
    "console.log(({['__proto__']: {q: 5}}).__proto__.q);":
        '5\n',
    'var __proto__ = {q: 5}; console.log(({__proto__}).__proto__.q);':
        '5\n',
    'console.log(({...{a: 1}}).__proto__ === Object.prototype);':
        'true\n',
}


class TestAPrototypeSpellingIsWrittenAsTheNameItReaches(TestJsDeobfuscator):
    """
    The pass alone, with nothing else in front of it, so that what it rewrites is its own answer
    rather than one another pass reached first.
    """

    def test_each_spelling_is_written_as_the_prototype_it_names(self):
        self.assertEqual(
            {
                source: self._run_transformer(source, JsPrototypeSpellingNormalization)
                for source in A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT
            },
            A_PROTOTYPE_SPELLING_AND_WHAT_NAMES_IT,
        )

    def test_a_receiver_the_syntax_does_not_decide_is_left_alone(self):
        """
        A receiver held in a binding reaches the same prototype, and reaching it needs the value the
        binding holds rather than the syntax at the write. It is left as it stands until it does.
        """
        source = 'var a = {};\na.__proto__.z = 9;'
        self.assertEqual(self._run_transformer(source, JsPrototypeSpellingNormalization), source)

    def test_a_name_the_file_binds_is_not_the_intrinsic(self):
        source = 'var Object = { prototype: {} };\nObject.getPrototypeOf({}).z = 9;'
        self.assertEqual(self._run_transformer(source, JsPrototypeSpellingNormalization), source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASpellingThatReachesSomethingElseIsNotRewritten(TestJsDeobfuscator):
    """
    The identity each rewrite rests on is the mechanism the language installs, so a file that
    replaces that mechanism means something else by the same spelling. Every answer below was
    established by running Node.
    """

    def test_a_spelling_that_reaches_something_else_still_answers_it(self):
        rows = A_SPELLING_THAT_REACHES_SOMETHING_ELSE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_reassigned_constructor_is_not_the_intrinsic(self):
        """
        Node throws a `ReferenceError` for this program, because `C` is a function expression the
        assignment names nothing outside itself. What the rewrite must not do is answer the read
        from `Object.prototype`, which is the one thing that would make it stop throwing.
        """
        source = (
            'Object.prototype.constructor = function C() { };'
            ' C.prototype.q = 5;'
            ' console.log(({}).constructor.prototype.q);'
        )
        self.assertEqual(before_and_after(source), (('', 'ReferenceError'), ('', 'ReferenceError')))


#: Spellings standing where the language wants a reference rather than a value, mapped to what Node
#: prints for each read as a module. The object each spelling reaches is the same one either way,
#: but the reference is not: an object literal's prototype slot is writable and deletable where
#: `Object.prototype` and `Array.prototype` are neither, so writing the identity out here answers
#: with a `TypeError` where the original answered with nothing.
A_SPELLING_STANDING_WHERE_A_REFERENCE_GOES = {
    '({}).__proto__ = {q: 1};\nconsole.log(1);':
        '1\n',
    '[].__proto__ = null;\nconsole.log("ok");':
        'ok\n',
    'console.log(delete ({}).__proto__);':
        'true\n',
}


#: Spellings whose receiver the rewrite would drop unevaluated, mapped to what Node prints for each.
#: The receiver is the one part of the spelling `Owner.prototype` does not keep, so an element that
#: runs code and a spread that iterates its argument both have to be kept.
A_RECEIVER_THE_REWRITE_MAY_NOT_DROP = {
    'var n = 0;\nfunction f() { n++; return 1; }\nvar p = [f()].__proto__;\nconsole.log(n);':
        '1\n',
    'try { var p = [...null].__proto__; console.log("none"); }'
    ' catch (e) { console.log(e.constructor.name); }':
        'TypeError\n',
}


#: Programs that replace one of the mechanisms a spelling goes through, by a route that names the
#: mechanism under a name other than the one the spelling is gated on, mapped to what Node prints
#: for each. An own `__proto__` on `Array.prototype` shadows the accessor for arrays alone, and a
#: prototype handed to a call, bound to a parameter, or written through a pattern is written by a
#: name the write target does not spell.
A_MECHANISM_WRITTEN_UNDER_ANOTHER_NAME = {
    'Object.defineProperty(Array.prototype, "__proto__",'
    ' {get: function () { return {q: 5}; }});\nconsole.log([].__proto__.q);':
        '5\n',
    'Object.setPrototypeOf(Array.prototype, null);\nconsole.log([].__proto__);':
        'undefined\n',
    'function patch(A) { A.prototype.constructor = function C() {}; }\npatch(Array);'
    '\n[].constructor.prototype.q = 5;\nconsole.log([].q);':
        'undefined\n',
    'var G = Object;\nfunction patch(o) { o.getPrototypeOf = function () { return {q: 7}; }; }'
    '\npatch(G);\nconsole.log(Object.getPrototypeOf({}).q);':
        '7\n',
    '(function (Object) { Object.prototype.constructor = function C() {}; })(Object);'
    '\nconsole.log(({}).constructor.prototype === Object.prototype);':
        'false\n',
    'function C() {}\nC.prototype.q = 5;\n[Object.prototype.constructor] = [C];'
    '\nconsole.log(({}).constructor.prototype.q);':
        '5\n',
    'function C() {}\nC.prototype.q = 5;\nglobalThis.Object.prototype.constructor = C;'
    '\nconsole.log(({}).constructor.prototype.q);':
        '5\n',
    'globalThis.Object.getPrototypeOf = function () { return {q: 5}; };'
    '\nconsole.log(Object.getPrototypeOf({}).q);':
        '5\n',
}


#: Programs where a scope can give the name the rewrite would introduce a meaning of its own, mapped
#: to what Node prints for each. A `with` object carrying an `Object` property answers a read of the
#: bare name from itself, so a spelling rewritten inside one reaches that object rather than the
#: prototype the spelling reached.
A_NAME_A_SCOPE_CAN_ANSWER = {
    'var o = {Object: {prototype: {q: 3}}};\nwith (o) { console.log(({}).__proto__.q); }':
        'undefined\n',
    'var o = {Object: {prototype: {q: 3}, getPrototypeOf: function () { return {q: 7}; }}};'
    '\nwith (o) { console.log(Object.getPrototypeOf({}).q); }':
        '7\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASpellingIsOnlyRewrittenWhereItIsRead(TestJsDeobfuscator):
    """
    `({}).__proto__` and `Object.prototype` denote one object, which settles a spelling read as a
    value and settles nothing about one the language reads as a reference. The deobfuscation writes
    modules, and a module is strict: a write or a delete the original performed on a throwaway's own
    slot becomes one performed on a property the language made neither writable nor configurable.
    """

    def test_a_spelling_standing_where_a_reference_goes_is_left_alone(self):
        rows = A_SPELLING_STANDING_WHERE_A_REFERENCE_GOES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverTheRewriteDropsIsFirstAskedWhatItRuns(TestJsDeobfuscator):
    """
    The rewrite keeps no part of the receiver it reads the owner from, so whatever that receiver
    would have done is gone with it. Which prototype an array literal inherits is settled by its
    being one, and that says nothing about what filling it costs.
    """

    def test_a_receiver_that_runs_something_is_left_alone(self):
        rows = A_RECEIVER_THE_REWRITE_MAY_NOT_DROP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs whose array-literal receiver reads a name whose evaluation throws — a free name, and a
#: `let` read before its declaration — mapped to the `ReferenceError` Node ends each with. The
#: rewrite drops the receiver, so folding `[name].__proto__` to `Array.prototype` would drop the
#: throw; the third would then also mutate `Array.prototype`.
A_RECEIVER_WHOSE_ELEMENT_THROWS = {
    '[zzz].__proto__;\nconsole.log(1);\n': ('', 'ReferenceError'),
    '[q].__proto__;\nlet q = 1;\nconsole.log(1);\n': ('', 'ReferenceError'),
    '[q].__proto__.foo = function () {};\nlet q = 1;\n': ('', 'ReferenceError'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverWhoseElementThrowsIsLeftAlone(TestJsDeobfuscator):
    """
    An element read that throws is part of what dropping the receiver would lose. Node ends each
    program with a `ReferenceError` — `zzz is not defined` for the free name,
    `Cannot access 'q' before initialization` for the dead-zone read — and folding `[name].__proto__`
    to `Array.prototype` would drop it, the third program then mutating `Array.prototype` as well.
    The rewrite is refused and the throw kept.
    """

    def test_a_receiver_whose_element_throws_is_left_alone(self):
        rows = A_RECEIVER_WHOSE_ELEMENT_THROWS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMechanismWrittenUnderAnotherNameStillRefusesTheRewrite(TestJsDeobfuscator):
    """
    Each identity rests on the mechanism the language installs, and the gate asks the effect model
    whether the file replaced it. The question has to be asked of every name the mechanism can be
    reached under: the receiver's own prototype shadows the one `Object` holds, a value handed to a
    call is written by a name the call spells, a parameter shadowing the intrinsic is a name of its
    own, and a destructuring target writes a property while naming no member target at the top.
    """

    def test_a_mechanism_written_under_another_name_is_still_written(self):
        rows = A_MECHANISM_WRITTEN_UNDER_ANOTHER_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAScopeCanAnswerIsNotTheIntrinsic(TestJsDeobfuscator):
    """
    The rewrite introduces a bare name where the file had none, so the name has to still reach the
    host at that position. A declaration is one way it does not, and a `with` body is another: the
    lookup consults the object first, which a file can give a property of that name.
    """

    def test_a_name_a_scope_can_answer_is_left_alone(self):
        rows = A_NAME_A_SCOPE_CAN_ANSWER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs whose own rewrite makes the write that the gate on a second rewrite asks about, mapped
#: to what Node prints for each. `({}).__proto__.constructor = C` writes `Object.prototype` through
#: a chain rooted at no name, which no gate can see; rewritten it becomes a write of `constructor`
#: on `Object`, which every gate can. The read is written where the walk reaches it after the
#: write, so the facts the second gate needs exist by the time it is asked and only a model held
#: across the rewrite can miss them.
A_MECHANISM_THIS_PASS_ITSELF_MAKES_VISIBLE = {
    'function C() {}\nC.prototype.q = 5;\n'
    'function r() { return ({}).constructor.prototype.q; }\n'
    '({}).__proto__.constructor = C;\nconsole.log(r());':
        '5\n',
    'function C() {}\nC.prototype.q = 5;\n'
    'function r() { return [].constructor.prototype.q; }\n'
    '[].__proto__.constructor = C;\nconsole.log(r());':
        '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteThisPassSpellsOutIsAskedAboutByTheNextGate(TestJsDeobfuscator):
    """
    Every rewrite this pass makes attributes a write to a name that had none, which is the direction
    that makes a *held* model unsound rather than merely stale: the gate on the next spelling asks
    exactly what the last rewrite just made visible, so an answer read before that rewrite clears a
    rewrite the file's own facts refuse. The models are therefore re-read per rewrite, and what that
    costs is one model build per spelling found.
    """

    def test_a_write_this_pass_spells_out_refuses_the_next_rewrite(self):
        rows = A_MECHANISM_THIS_PASS_ITSELF_MAKES_VISIBLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
