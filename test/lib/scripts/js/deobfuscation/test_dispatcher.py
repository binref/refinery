from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.dispatcher import (
    _UNREADABLE,
    JsDispatcherUnwrapper,
    _flag_argument,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
)
from refinery.lib.scripts.js.parser import JsParser


def a_dispatcher(dict_lines: list, tail_lines: list) -> str:
    """
    The dispatcher scaffold: one function `d` that looks its callee up in a map by name and
    reads that callee's arguments out of the one shared payload array `p`. *dict_lines* spell
    the entries of the map and *tail_lines* the calls made through it.

    It is written here, where the law about unwrapping it is stated, and read from wherever
    else a program built around one is needed.
    """
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


class TestDispatcherUnwrapping(TestJsDeobfuscator):

    def _make_dispatcher(self, dict_lines: list, tail_lines: list):
        return a_dispatcher(dict_lines, tail_lines)

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

    def test_unwrapping_invalidates_shared_model_cache(self):
        """
        Unwrapping removes the dispatcher's empty stub function through the shared analysis cache.
        When neither the payload nor the cache declarator is in removable form, that stub deletion
        is the unwrapper's only boilerplate removal, so the removal itself must invalidate the shared
        cache: a later transform sharing the cache must not observe a model that still declares the
        already-deleted stub.
        """
        source = '\n'.join((
            'var c = {};',
            'var p = 0;',
            'function d(name, flag, rtype, lengths) {',
            '  var output;',
            '  var fns = {',
            '    "k": function() { return 42; }',
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
            'console.log(d("k"));',
        ))
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        transformer = JsDispatcherUnwrapper()
        transformer.models = cache
        transformer.visit(ast)
        remaining = sorted(
            node.id.name
            for node in ast.walk()
            if isinstance(node, JsFunctionDeclaration) and node.id is not None
        )
        self.assertEqual(['k'], remaining)
        self.assertIsNone(cache.model.lookup('stub', cache.model.root_scope))


#: A program that dispatches through a callee name built by an expression rather than written as a
#: string literal, mapped to what Node prints for it. The dispatcher is reached the ordinary way and
#: answers the ordinary way; only the spelling of the name keeps the unwrapper from reading it.
A_DISPATCH_THROUGH_A_COMPUTED_KEY = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=[
            'var k = "f" + 1;',
            'console.log((p = ["a", "b", "c"], d(k)));',
        ],
    ): 'abc\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatcherIsKeptWhileACallToItSurvives(TestBase):
    """
    Unwrapping a dispatcher extracts the functions its table holds, replaces each call made through
    it with a direct call to the function that call selects, and removes the declaration. A call
    whose callee name is not written as a string literal is one the pass cannot read, and the whole
    unwrap is refused where one is present rather than the removal alone.

    Refusing the whole of it is what extraction costs: the extracted function reuses the statement
    nodes of the table entry it is built from and strips the payload destructuring out of them in
    place, so a dispatcher left standing beside the extracted functions would call bodies that no
    longer read the payload it writes.
    """

    def test_a_dispatch_through_a_computed_key_keeps_the_dispatcher(self):
        rows = A_DISPATCH_THROUGH_A_COMPUTED_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program that installs a value at the index a dispatcher's payload was written with no element
#: in, and dispatches through it, mapped to what Node prints for it. The dispatcher reaches its
#: callee's arguments by reading them off the payload, so a position the payload does not hold is
#: read from the prototype chain like any other.
A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE = {
    "Array.prototype[1] = 'X';\n" + a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["first", , "third"], d("f1")));'],
    ): 'firstXthird\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatcherPayloadHoleIsTheChainsToAnswer(TestBase):
    """
    Unwrapping a dispatcher into direct calls has to spell out each argument the payload carried,
    and a position the payload was written with no element in is not one it carries: what reaches
    the callee there is whatever the prototype chain answers for that index. Spelling it `undefined`
    is right only while that chain is the one the language describes, so the rewrite asks the effect
    model whether it still is, and refuses the dispatch where it is not.

    This is the law `test.lib.scripts.js.deobfuscation.test_inherited_reads` states of a read, at a
    site that decides it in the syntax rather than in the interpreter. The same program with the
    prototype left alone is `test_dispatcher_sparse_payload_preserves_arity` and prints
    `firstundefinedthird`, which is what the refusal here must not cost.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_payload_position_no_element_was_written_in_finds_what_the_chain_holds(self):
        rows = A_DISPATCH_WHOSE_PAYLOAD_HOLDS_A_HOLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs whose dispatch is written inside another dispatch's payload, mapped to what Node prints
#: for each. The direct-call rewrite carries the payload elements into the call it builds, so a
#: dispatch standing in one is not taken away with the dispatch it is an argument of: the first row
#: is one this pass can read and has to rewrite as well, and the second is one it cannot, which
#: leaves a call the declaration is still needed for.
A_DISPATCH_WRITTEN_INTO_ANOTHER_DISPATCHS_PAYLOAD = {
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=['console.log((p = [(p = ["x"], d("f1"))], d("f2")));'],
    ): 'BAx\n',
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=[
            'var k = "f" + 1;',
            'console.log((p = [(p = ["x"], d(k))], d("f2")));',
        ],
    ): 'BAx\n',
}


#: Dispatches written in forms this pass reads only in part, mapped to what Node prints for each.
#: The first two unwrap the return value on the wrap key, which is the callee's result rather than
#: the callee, and the third writes the ordinary payload pair with a grouping around the call.
#: Reading any of them as a bare zero-argument dispatch calls the callee with no arguments at all.
#: The second stands where the payload pair is refused, which is what leaves the unwrap to be read
#: by whoever else claims the call inside it.
A_DISPATCH_SPELLED_AROUND_THE_CALL = {
    a_dispatcher(
        dict_lines=['"f1": function() { return 5; }'],
        tail_lines=['console.log(d("f1", "x", "wrapF")["wk"]);'],
    ): '5\n',
    "Array.prototype[1] = 'X';\n" + a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["first", , "third"], d("f1", "x", "wrapF")["wk"]));'],
    ): 'firstXthird\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a, b, c] = p; return a + b + c; }'],
        tail_lines=['console.log((p = ["a", "b", "c"], (d("f1"))));'],
    ): 'abc\n',
}


#: A dispatcher one of whose table entries this pass cannot extract, mapped to what Node prints for
#: it. The second entry destructures the payload with a hole in it, which `_extract_params` refuses,
#: and the first is an entry the extraction would otherwise take the payload destructuring out of.
A_TABLE_HOLDING_AN_ENTRY_THAT_CANNOT_BE_EXTRACTED = {
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a, b] = p, x = 1; return a + b + x; },',
            '"f2": function() { var [c, , e] = p; return c + e; }',
        ],
        tail_lines=['console.log((p = [1, 2], d("f1")));'],
    ): '4\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEveryDispatchThroughADispatcherIsAccountedFor(TestBase):
    """
    Removing the declaration is right exactly while no reference to it survives, so the plan has to
    account for each reference one by one. A dispatch nested in a payload is the shape that shows
    it: what the rewrite of the outer dispatch does with that payload is carry it over, so the
    inner dispatch is still there afterwards and is either rewritten too or is a reason to refuse.
    """

    def test_a_dispatch_written_into_another_dispatchs_payload_is_accounted_for(self):
        rows = A_DISPATCH_WRITTEN_INTO_ANOTHER_DISPATCHS_PAYLOAD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_dispatch_spelled_around_the_call_is_not_read_as_a_bare_one(self):
        rows = A_DISPATCH_SPELLED_AROUND_THE_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATableEntryIsExtractedWithoutBeingTakenApart(TestBase):
    """
    Extraction is attempted for every entry of a table before any of them is installed, and an
    entry this pass cannot read is a reason to abandon the whole unwrap. What it must not be is a
    reason to abandon it half done: an entry built from the statements of the table entry itself
    would leave that entry stripped of the payload destructuring its body still reads.
    """

    def test_an_entry_that_cannot_be_extracted_leaves_the_table_as_it_stands(self):
        rows = A_TABLE_HOLDING_AN_ENTRY_THAT_CANNOT_BE_EXTRACTED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Dispatches whose flag arguments say the expression means something other than the reading its
#: shape suggests, mapped to what Node prints for each. The key selects the table entry and the two
#: flags behind it select the branch: emptying the payload, handing back the entry instead of what
#: calling it returned, and wrapping that result in an object under the wrap key. A `new` dispatch
#: hands back the object the dispatcher returned only where it returned one, which is the wrapper
#: branch alone.
A_DISPATCH_WHOSE_FLAGS_SAY_SOMETHING_ELSE = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1", "initF")));'],
    ): 'Aundefined\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log(typeof (p = ["x"], d("f1", "createF")));'],
    ): 'function\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1")["wk"]));'],
    ): 'undefined\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log((p = ["x"], d("f1", "y", "wrapF")).wk);'],
    ): 'Ax\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['console.log(typeof (p = ["x"], new d("f1")));'],
    ): 'object\n',
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=[
            'p = ["x"];',
            'console.log(typeof new d("f1", "zz", "wrapF")["wk"]);',
        ],
    ): 'string\n',
}


#: A bare dispatch over a payload something else filled, mapped to what Node prints for it. Reading
#: one as a call with no arguments is a claim about the payload rather than about the site: the
#: callee takes its arguments out of the array, and a dispatch that does not empty it first reaches
#: whatever the last one left there.
A_BARE_DISPATCH_OVER_A_PAYLOAD_SOMETHING_ELSE_FILLED = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=['p = ["x"];', 'console.log(d("f1"));'],
    ): 'Ax\n',
}


#: Dispatches carrying an argument the replacement keeps no room for, mapped to what Node prints for
#: each. The dispatcher takes its arguments out of the payload, so everything the site writes after
#: the key is read by the dispatcher alone and is gone from the call this pass builds — which makes
#: what evaluating it did the site's to account for. The second writes a whole dispatch there, which
#: no payload carries over.
A_DISPATCH_ARGUMENT_THE_REWRITE_WOULD_DROP = {
    a_dispatcher(
        dict_lines=['"f1": function() { var [a] = p; return "A" + a; }'],
        tail_lines=[
            'var n = 0;',
            'function s() { n++; return "z"; }',
            'console.log((p = ["x"], d("f1", s())));',
            'console.log(n);',
        ],
    ): 'Ax\n1\n',
    a_dispatcher(
        dict_lines=[
            '"f1": function() { var [a] = p; return "A" + a; },',
            '"f2": function() { var [b] = p; return "B" + b; }',
        ],
        tail_lines=['console.log((p = ["a"], d("f1", (p = ["b"], d("f2")))));'],
    ): 'Ab\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADispatchIsReadPastItsKey(TestBase):
    """
    The key names the table entry and settles nothing else. Which branch of the dispatcher runs, and
    therefore what the expression standing at the site denotes, is decided by the two flags behind
    the key and by whether the site spelled `new` — and the payload the callee reads its arguments
    from is filled by the dispatch before it, not by the one being read. A reading that takes the
    key alone answers a value the original never computed.
    """

    def test_a_dispatch_whose_flags_say_something_else_is_left_alone(self):
        rows = A_DISPATCH_WHOSE_FLAGS_SAY_SOMETHING_ELSE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_bare_dispatch_does_not_claim_the_payload_is_empty(self):
        rows = A_BARE_DISPATCH_OVER_A_PAYLOAD_SOMETHING_ELSE_FILLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_dispatch_argument_the_rewrite_would_drop_is_first_asked_what_it_runs(self):
        rows = A_DISPATCH_ARGUMENT_THE_REWRITE_WOULD_DROP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestFlagArgumentReadsAPresentArgumentThatDenotesNothingAsUnreadable(TestBase):
    """
    `_flag_argument` keeps three answers apart: the fixed string an argument denotes, `None` where
    the call has no argument at that index, and `_UNREADABLE` where it has one this pass cannot read
    as a fixed string. A string written with a `\\x` escape naming no character is present but
    denotes nothing, so it is unreadable and not absent — answering `None` for it would let the pass
    read a flag it cannot see as a flag that is not there and take the safety gate off the
    unwrapping. The backslash is spelled with `chr(92)` so nothing between the source and the parser
    reads it as an escape of its own.
    """

    @staticmethod
    def _call(source: str) -> JsCallExpression:
        statement = JsParser(source + ';').parse().body[0]
        assert isinstance(statement, JsExpressionStatement)
        call = statement.expression
        assert isinstance(call, JsCallExpression)
        return call

    def test_a_present_argument_that_denotes_nothing_is_unreadable_not_absent(self):
        call = self._call(F'f("K", "{chr(92)}xZZ", g())')
        self.assertEqual(
            [_flag_argument(call, index) for index in range(4)],
            ['K', _UNREADABLE, _UNREADABLE, None],
        )
