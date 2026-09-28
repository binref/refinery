"""
The positions in a program that hold a name a value carries, rather than a name the program reads.

The member after a dot, a key of an object literal written out, the name of a class member, and the
key of an import attribute are all such positions. Text standing in one of them refers to nothing:
it cannot be renamed, and no value may be put where it stands, since `o.5` and `{ -2: 1 }` are not
programs at all while `o.zz` and `{ 'zz': 1 }` are programs about a different property. Every other
identifier position reads a binding, writes one, or declares one, and a computed key is the ordinary
read it looks like.

Three positions are both at once, and they are what this module presses on. A shorthand property is
one identifier standing for two things — `{ a }` means `{ a: a }` — so a value reaching it has to be
written out beside the name it may not replace, and a question about which names a program reads has
to count it. The local half of an export list is the second: `export { a };` reads the binding it
names — an engine refuses to link the list where nothing declares `a` — while no value may take
the read's place, because a list exports bindings and never values, so the read is one every
substitution declines. And `__proto__` is the one name for which the shorthand expansion is not
available:
`{ __proto__ }` gives the object an own property of that name, while `{ __proto__: v }` hands the
value to the object's prototype slot and gives it no such property, so the two spellings are
different programs, and Node says which is which for a value that is an object and for one that is
not.

SECURITY: every program here is written out by this module and Node runs only those. Nothing from
`samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from typing import Iterable

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
    folded,
    printed,
)

from refinery.lib.scripts.js.analysis.model import build_semantic_model, is_use_position
from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


def rewritten(programs: Iterable[str]) -> dict[str, str]:
    """
    What `refinery.js` writes for each program, keyed by the program it was given.
    """
    return {program: folded(program) for program in programs}


def spelled(programs: Iterable[str]) -> dict[str, str]:
    """
    Each program spelled by the synthesizer with no pass run over it, keyed by itself. A rewrite
    compared against this states which program was expected and never which layout, so a row cannot
    fail over a line break or a quote the synthesizer chose.
    """
    return {program: printed(program) for program in programs}


def spelled_as_expected(rows: dict[str, str]) -> dict[str, str]:
    """
    The expected program of each row, spelled by the synthesizer and keyed by the program the row
    starts from.
    """
    return {source: printed(expected) for source, expected in rows.items()}


def run_by_node(programs: Iterable[str]) -> dict[str, tuple[str, str | None]]:
    """
    What Node makes of each program, keyed by the program.
    """
    return {program: behavior(program) for program in programs}


def run_by_node_as_expected(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    """
    What Node makes of the expected program of each row, keyed by the program the row starts from.
    This is what makes an expectation the engine's answer rather than this module's opinion: a row
    whose two halves do not run alike is a row written wrong, whatever the tool does with it.
    """
    return {source: behavior(expected) for source, expected in rows.items()}


def occurrences_of(name: str, source: str) -> tuple[int, int]:
    """
    How often *name* is written as an identifier in *source*, and how many of those occurrences are
    positions that read or write a binding rather than name a property.

    Each occurrence counts once. A shorthand property is a single identifier filling two slots of
    its parent, and a walk of the tree arrives at it through both, so counting nodes rather than
    visits is what keeps `{ q }` from reading as two occurrences of `q`.
    """
    occurrences: dict[int, JsIdentifier] = {}
    for node in JsParser(source).parse().walk():
        if isinstance(node, JsIdentifier) and node.name == name:
            occurrences[id(node)] = node
    reads = sum(1 for node in occurrences.values() if is_use_position(node))
    return len(occurrences), reads


#: A program whose object literal names a property by its shorthand somewhere other than at the top
#: of a literal standing alone, mapped to the program a correct deobfuscation writes for it. The one
#: identifier of a shorthand is both the name of the property and a read of the binding, so a value
#: reaches it as it reaches any other read and the property still has to be named afterwards.
#: `test.lib.scripts.js.deobfuscation.test_constants` states the plainest shapes; these are the ones
#: a fix that only looked at the outermost literal, or only at a property standing on its own, would
#: leave broken.
A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE = {
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify({ a: { q } }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ a: { q: 1 } }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify([{ a: { q } }]));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify([{ a: { q: 1 } }]));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var w = 'x';
        console.log(JSON.stringify({ a: 0, b: { q, r: 2, c: { w } } }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ a: 0, b: { q: 1, r: 2, c: { w: 'x' } } }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var w = 2;
        var e = 3;
        console.log(JSON.stringify({ q, w, e }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 1, w: 2, e: 3 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify({ q, r: q }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 1, r: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'k';
        console.log(JSON.stringify({ q, [q]: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 'k', k: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'q';
        console.log(JSON.stringify({ q }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 'q' }));
        """
    ),
    inspect.cleandoc(
        """
        var async = 1;
        console.log(JSON.stringify({ async }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ async: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var o = { if: 1, q };
        console.log(o.if, JSON.stringify(o));
        """
    ): inspect.cleandoc(
        """
        var o = { if: 1, q: 1 };
        console.log(o.if, JSON.stringify(o));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        class C { f = { q }; }
        console.log(JSON.stringify(new C().f));
        """
    ): inspect.cleandoc(
        """
        class C { f = { q: 1 }; }
        console.log(JSON.stringify(new C().f));
        """
    ),
    inspect.cleandoc(
        """
        var q = void 0;
        var o = { q };
        console.log(JSON.stringify(o), JSON.stringify(Object.keys(o)));
        """
    ): inspect.cleandoc(
        """
        var o = { q: void 0 };
        console.log(JSON.stringify(o), JSON.stringify(Object.keys(o)));
        """
    ),
}


class TestAConstantReachingAShorthandPropertyIsWrittenBesideItsName(TestBase):
    """
    `{ q }` is `{ q: q }` written with one word instead of two, so the value of the read has to be
    put beside the name and never over it. The rows of
    `A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE` put the shorthand where a
    fix that only handled the simplest case would miss it: inside a nested literal, inside a literal
    inside an array, in a literal holding a spelled-out key and a computed one beside it, in a class
    field initializer, and under a name that is a contextual keyword.

    The last row is the one a shorthand dropped altogether would still pass without:
    `JSON.stringify` omits a key whose value is `undefined`, so `Object.keys` is what says the key
    is there at all.

    The expectation is stated as a program and compared after both sides have been spelled by the
    synthesizer, so a row says what the tool must write and not how it must lay it out.
    """

    def test_a_shorthand_below_the_top_of_a_literal_is_written_out_under_its_name(self):
        rows = A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


#: Each of the ways an object literal can carry the key `__proto__`, mapped to what Node prints for
#: it. The value is an object in the first four rows and a number in the last three, because the
#: prototype slot takes only an object or `null` and is silently left alone for anything else, which
#: parts the spellings a second way.
THE_SPELLINGS_OF_A_PROTO_KEY = {
    inspect.cleandoc(
        """
        var __proto__ = { z: 9 };
        var o = { __proto__ };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{"__proto__":{"z":9}} undefined\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { __proto__: v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{} 9\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { '__proto__': v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{} 9\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { ['__proto__']: v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{"__proto__":{"z":9}} undefined\n',
    inspect.cleandoc(
        """
        var __proto__ = 5;
        var o = { __proto__ };
        console.log(JSON.stringify(o));
        """
    ): '{"__proto__":5}\n',
    inspect.cleandoc(
        """
        var v = 5;
        var o = { __proto__: v };
        console.log(JSON.stringify(o));
        """
    ): '{}\n',
    inspect.cleandoc(
        """
        var v = 5;
        var o = { ['__proto__']: v };
        console.log(JSON.stringify(o));
        """
    ): '{"__proto__":5}\n',
}


#: A program whose shorthand property is named `__proto__`, which is therefore the one shorthand no
#: value may be written out beside. The last of them holds both spellings in one literal, which is a
#: program only because they are different property definitions: writing the shorthand out would
#: make two prototype setters of them, and a literal carrying two of those is a syntax error.
A_PROTO_SHORTHAND_IS_LEFT_STANDING = [
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log(JSON.stringify({ __proto__ }));
        """
    ),
    inspect.cleandoc(
        """
        var __proto__ = { z: 9 };
        var o = { __proto__ };
        console.log(JSON.stringify(o), o.z);
        """
    ),
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log(JSON.stringify({ a: { __proto__ } }));
        """
    ),
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var __proto__ = 5;
        var a = { __proto__, __proto__: v };
        console.log(JSON.stringify(a), a.z);
        """
    ),
]


#: A program carrying a `__proto__` key in a position where a value may reach it, mapped to the
#: program a correct deobfuscation writes. A key written out or given as a string hands the value to
#: the prototype slot, and a computed key makes an own property of it however the string reaching it
#: was spelled, so the one thing none of these rewrites may do is turn a computed key into a
#: written-out one. The ordinary-name rows are the controls: that collapse is right for every name
#: but this one, and a fix that stopped collapsing computed keys at all would show up here rather
#: than reading as a refusal.
A_PROTO_KEY_A_VALUE_MAY_REACH = {
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ __proto__: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ __proto__: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ ['__proto__']: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ ['__proto__']: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = '__proto__';
        var v = 5;
        console.log(JSON.stringify({ [k]: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ ['__proto__']: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = 'q';
        var v = 5;
        console.log(JSON.stringify({ [k]: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ ['q']: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 5 }));
        """
    ),
}


#: A program declaring `__proto__` with the shorthand that reads it taken out, mapped to the program
#: a correct deobfuscation writes. Nothing reads the binding there, so the declaration goes — which
#: is what makes the shorthand rows above a statement about the shorthand rather than about a
#: declaration the tool never removes.
THE_SAME_PROTO_DECLARATION_WITH_NO_SHORTHAND_READING_IT = {
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log('done');
        """
    ): inspect.cleandoc(
        """
        console.log('done');
        """
    ),
}


class TestTheShorthandProtoIsADifferentProgramFromTheWrittenOutOne(TestBase):
    """
    `{ __proto__ }` and `{ __proto__: v }` are not two spellings of one program. Node prints
    `{"__proto__":{"z":9}}` and `undefined` for the first with an object in hand, and `{}` and `9`
    for the second: one gives the object an own property under that name, the other hands the value
    to the prototype slot and leaves the object with no own property at all. A value that is neither
    an object nor `null` parts them again — `{ __proto__: 5 }` is an object with nothing in it —
    and a key given as a string behaves as the written-out one while a computed key behaves as the
    shorthand.

    So the expansion every other shorthand needs is the one rewrite this shorthand may not have, and
    the collapse of `{ ['__proto__']: v }` to `{ __proto__: v }` that is right for every other name
    is wrong for this one. Both directions are pinned, each against a control under an ordinary
    name, so that refusing to touch an object literal at all cannot pass for handling `__proto__`.
    """

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_every_spelling_of_a_proto_key_still_prints_what_it_printed(self):
        """
        Node prints four different lines for the seven programs of `THE_SPELLINGS_OF_A_PROTO_KEY`,
        and prints the same for their deobfuscations.
        """
        rows = THE_SPELLINGS_OF_A_PROTO_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_proto_shorthand_is_not_written_out(self):
        rows = A_PROTO_SHORTHAND_IS_LEFT_STANDING
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_a_proto_key_a_value_reaches_keeps_the_spelling_it_was_written_in(self):
        rows = A_PROTO_KEY_A_VALUE_MAY_REACH
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_PROTO_KEY_A_VALUE_MAY_REACH
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))

    def test_the_same_declaration_goes_once_the_shorthand_reading_it_is_gone(self):
        rows = THE_SAME_PROTO_DECLARATION_WITH_NO_SHORTHAND_READING_IT
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))


#: A program holding a constant and a property of the same name, mapped to the program a correct
#: deobfuscation writes. The constant is a string in most rows, because that is the substitution an
#: engine would accept without complaint: `o.q` becoming `o.zz` and `{ q: 1 }` becoming
#: `{ 'zz': 1 }` are programs, and programs about a property nothing else in the file mentions.
#: Each row keeps a read of the property beside the read of the binding, so the value the name still
#: answers is part of what the row states.
A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME = {
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 1 };
        console.log(q, o.q);
        """
    ): inspect.cleandoc(
        """
        console.log('zz', 1);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 1 };
        console.log(q, o['q']);
        """
    ): inspect.cleandoc(
        """
        console.log('zz', 1);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        console.log(q, JSON.stringify({ q: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log('zz', JSON.stringify({ q: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { q() { return 1; } }
        console.log(q, new C().q());
        """
    ): inspect.cleandoc(
        """
        class C { q() { return 1; } }
        console.log('zz', new C().q());
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { q = 1; }
        console.log(q, new C().q);
        """
    ): inspect.cleandoc(
        """
        class C { q = 1; }
        console.log('zz', new C().q);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { static q = 1; }
        console.log(q, C.q);
        """
    ): inspect.cleandoc(
        """
        class C { static q = 1; }
        console.log('zz', C.q);
        """
    ),
    inspect.cleandoc(
        """
        var q = 5;
        console.log(JSON.stringify({ q() { return 1; } }), q);
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q() { return 1; } }), 5);
        """
    ),
    inspect.cleandoc(
        """
        var q = 5;
        var o = { get q() { return 1; } };
        console.log(o.q, q);
        """
    ): inspect.cleandoc(
        """
        var o = { get q() { return 1; } };
        console.log(o.q, 5);
        """
    ),
}


class TestANamePositionNeverTakesAValue(TestBase):
    """
    A property is named, not referred to, so a constant that happens to carry the same name has
    nothing to do with it. The rows of `A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME` put the two
    side by side in every position that names a property with a bare word: after a dot, as a key
    written out, as a class method, as an instance field and a static one, as a shorthand method of
    an object literal, and as a getter.

    Each row still reads the property, which is what turns a substitution into a wrong answer rather
    than into a broken file. `o.q` folds to `1` because the key is `q`; had the key been replaced by
    `'zz'` the same read would fold to nothing, and had the read after the dot been replaced instead
    the program would ask for a property nobody wrote.
    """

    def test_a_property_keeps_its_name_where_a_constant_carries_the_same_one(self):
        rows = A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


#: A program whose property is named by a computed key, mapped to the program a correct
#: deobfuscation writes. A computed key is an expression and so an ordinary read, and the value it
#: answers is the name the property gets — which is why the substitution belongs here and nowhere
#: else in this module.
A_COMPUTED_KEY_IS_A_READ = {
    inspect.cleandoc(
        """
        var q = 'k';
        console.log(JSON.stringify({ [q]: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ k: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'k';
        var o = { k: 3 };
        console.log(o[q]);
        """
    ): inspect.cleandoc(
        """
        console.log(3);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { [q]() { return 1; } }
        console.log(new C().zz());
        """
    ): inspect.cleandoc(
        """
        class C { ['zz']() { return 1; } }
        console.log(new C().zz());
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = {};
        o[q] = 1;
        console.log(JSON.stringify(o));
        """
    ): inspect.cleandoc(
        """
        var o = {};
        o.zz = 1;
        console.log(JSON.stringify(o));
        """
    ),
}


class TestAComputedKeyIsAnOrdinaryRead(TestBase):
    """
    Brackets around a key make the name a value the program computes, so the identifier inside them
    is a read like any other and the substitution a name position refuses is the one this position
    requires. The rows of `A_COMPUTED_KEY_IS_A_READ` compute the key of an object literal, the
    property of a member read, the name of a class method, and the target of a member write.

    A tool that refused every key alike would leave all four standing, which is why they are stated
    beside the classes that pin the refusals: the two answers have to come apart on the brackets and
    on nothing else.
    """

    def test_a_computed_key_takes_the_value_it_reads(self):
        rows = A_COMPUTED_KEY_IS_A_READ
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_COMPUTED_KEY_IS_A_READ
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


#: A program taking an object apart with a pattern, mapped to the program a correct deobfuscation
#: writes. A pattern reuses the nodes of an object literal and means something else with them: the
#: key names the property read off the object, the word beside it names the binding written, and the
#: default is an expression evaluated where the property is missing.
A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS = {
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 4 };
        var { q: x } = o;
        console.log(q, x);
        """
    ): inspect.cleandoc(
        """
        var o = { q: 4 };
        var { q: x } = o;
        console.log('zz', x);
        """
    ),
    inspect.cleandoc(
        """
        var d = 'zz';
        function f(o) { var { q = d } = o; return q; }
        console.log(f({}), f({ q: 1 }));
        """
    ): inspect.cleandoc(
        """
        function f(o) { var { q = 'zz' } = o; return q; }
        console.log(f({}), f({ q: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = 'q';
        var o = { q: 4 };
        var { [k]: x } = o;
        console.log(x);
        """
    ): inspect.cleandoc(
        """
        var o = { q: 4 };
        var { q: x } = o;
        console.log(x);
        """
    ),
}


class TestADestructuringPatternBindsWhereALiteralReads(TestBase):
    """
    `var { q: x } = o` and `{ q: x }` as an expression are the same nodes read two ways. In the
    pattern, `q` still names the property — a constant called `q` has nothing to do with it — but
    `x` is written rather than read, and the default of `var { q = d } = o` is an expression a value
    reaches like any other. The computed key of a pattern is a read there too, and the row that
    collapses one to a plain key is what says so.

    Each row is decided by running it: the second prints `zz 1`, one value coming from the default
    and one from a property that is present, so a substitution landing on the wrong half of the
    pattern changes what is printed rather than only how it is spelled.
    """

    def test_a_pattern_takes_a_value_into_its_default_and_its_computed_key_only(self):
        rows = A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


#: A program whose only mention of a binding is a shorthand property beside which no value can be
#: written out, so that the declaration has nothing else keeping it and the shorthand alone has to.
A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING = {
    inspect.cleandoc(
        """
        var q = { z: 1 };
        console.log(JSON.stringify({ q }));
        """
    ): '{"q":{"z":1}}\n',
    inspect.cleandoc(
        """
        var q = { z: 1 };
        var o = { q };
        console.log(JSON.stringify(o), o.q.z);
        """
    ): '{"q":{"z":1}} 1\n',
}


#: The same declaration in a program with the shorthand taken out, mapped to the program a correct
#: deobfuscation writes.
THE_SAME_DECLARATION_WITH_NO_SHORTHAND_READING_IT = {
    inspect.cleandoc(
        """
        var q = { z: 1 };
        console.log('done');
        """
    ): inspect.cleandoc(
        """
        console.log('done');
        """
    ),
}


class TestAShorthandKeepsTheDeclarationItReads(TestBase):
    """
    The value half of a shorthand is a read, so a binding nothing else mentions is still read and
    its declaration is still live. The rows of `A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING` hold an
    object, which is a value no expansion can write out beside the name: doing so would make a
    second object where the program has one, and `o.q.z` in the second row is a read of the one the
    program made.

    An analysis that took the identifier for a name and not for a read would find the declaration
    unread and drop it, and the shorthand left behind would then read a binding nobody declares.
    """

    def test_a_declaration_read_only_by_a_shorthand_stays(self):
        rows = A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_the_same_declaration_goes_with_the_shorthand_taken_out(self):
        rows = THE_SAME_DECLARATION_WITH_NO_SHORTHAND_READING_IT
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_program_read_only_by_a_shorthand_still_prints_what_it_printed(self):
        rows = A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


def _a_module_reporting_it_loaded(module: str) -> str:
    """
    `inspect.cleandoc` of *module* with a statement printing `loaded` appended. A module that only
    declares and exports does nothing an engine reports, and the print is what makes the difference
    between a module that loads and one that does not an answer rather than a silence on both
    sides.
    """
    return F"{inspect.cleandoc(module)}\nconsole.log('loaded');\n"


def rewritten_as_modules(programs: Iterable[str]) -> dict[str, str]:
    """
    What `refinery.js` writes for each program under the module execution model, keyed by the
    program it was given.
    """
    return {program: folded(program, module=True) for program in programs}


#: The one module of `A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES` that also reads what it exports.
#: The read beside the list is a substitution target and the list is not, so this is the module
#: whose deobfuscation is not the module itself.
A_MODULE_READING_WHAT_IT_EXPORTS = inspect.cleandoc(
    """
    var a = 1;
    export { a };
    console.log(a);
    """
)

#: A module that exports a binding it declares, mapped to what Node prints for it. Every one of them
#: is a module an engine loads, which is the whole of what an export list has to be checked against:
#: a list compiles only where the module declares what it names.
A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES = {
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        let a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        const a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        const a = () => 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        let a;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a as b };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1, b = 2;
        export { a, b };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a as default };
        """
    ): 'loaded\n',
    A_MODULE_READING_WHAT_IT_EXPORTS: '1\n',
    _a_module_reporting_it_loaded(
        """
        function a() { return 1; }
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        class a {}
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        import { format } from 'node:util';
        export { format };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var format = 1;
        export { format } from 'node:util';
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded('export var a = 1;'): 'loaded\n',
}

#: The rows of `A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES` whose correct deobfuscation is not the
#: module itself, mapped to the module a correct tool writes. The read beside the list is
#: substituted while the declaration stays; and a local nothing reads goes even though a `from`
#: list spells its name, because that list names the far side of the module boundary, so a rule
#: reading every list as a local read would be caught keeping it.
A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS = {
    A_MODULE_READING_WHAT_IT_EXPORTS: inspect.cleandoc(
        """
        var a = 1;
        export { a };
        console.log(1);
        """
    ),
    _a_module_reporting_it_loaded(
        """
        var format = 1;
        export { format } from 'node:util';
        """
    ): inspect.cleandoc(
        """
        export { format } from 'node:util';
        console.log('loaded');
        """
    ),
}


class TestAnExportListReadsTheBindingItNames(TestBase):
    """
    The local half of `export { a };` reads the module's own binding: an engine refuses to link
    the list where nothing declares `a`, and the refusal is the linker's rather than the parser's,
    so whoever imports the module gets it as much as whoever runs it. A declaration whose only
    reader is such a list is therefore live, and substituting a constant into its every other read
    does not free it either, because no value can stand where the list names it — a list exports
    bindings and never values, and `export { 1 };` is refused as readily as the export of a name
    nothing declares.

    The rows put a declaration under an export list in every spelling: each keyword, with an
    initializer and without, renamed, exported as `default`, two names at once, and read elsewhere
    besides. The `from` row is the control of the opposite kind: its list names a binding on the
    far side of the module boundary and nothing local, so reading every name in every list as a
    local read is not this rule either — a constant substituted into that list writes
    `export { 1 } from 'node:util'`, and the local its name happens to match is unread and free to
    go. The remaining controls each hold the rule somewhere else: a list re-exporting an import
    reads the binding the import statement bound, an `export var` is one statement and not two,
    and the function and class declarations are kept on their own terms.
    """

    def test_a_module_the_list_alone_reads_comes_back_as_it_was(self):
        rows = [
            source for source in A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
            if source not in A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        ]
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_a_substituted_read_and_a_far_side_name_leave_their_own_marks(self):
        rows = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    def test_every_rewritten_row_is_a_row_of_the_table(self):
        self.assertLessEqual(
            set(A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS),
            set(A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES),
        )

    def test_the_module_model_hands_back_the_same_modules(self):
        rows = A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
        rewrites = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(
            {source: printed(rewrites.get(source, source)) for source in rows},
            rewritten_as_modules(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_module_still_prints_what_it_printed(self):
        rows = A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_module_runs_the_way_the_module_it_replaces_does(self):
        rows = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: behavior(expected, module=True) for source, expected in rows.items()},
        )


#: A program mentioning the name `a`, mapped to how many times it is written as an identifier and
#: how many of those occurrences read or write a binding. The declarator is one occurrence that
#: writes in every row; what varies is the list: the local half of a sourceless list is the one
#: half of a specifier that reads, the name a binding is exported under is not a read, and a list
#: carrying a `from` clause reads nothing at all, and neither does the name a re-export invents.
WHAT_A_NAME_IN_AN_EXPORT_LIST_COUNTS_FOR = {
    inspect.cleandoc(
        """
        var a = 1;
        export { a };
        """
    ): (2, 2),
    inspect.cleandoc(
        """
        var a = 1;
        export { a as b };
        """
    ): (2, 2),
    inspect.cleandoc(
        """
        var a = 1, x = 2;
        export { x as a };
        """
    ): (2, 1),
    inspect.cleandoc(
        """
        var a = 1;
        export { a } from 'node:util';
        """
    ): (2, 1),
    inspect.cleandoc(
        """
        export * as a from 'node:util';
        var a = 1;
        """
    ): (2, 1),
}


class TestOnlyTheLocalHalfOfAnExportListReads(TestBase):
    """
    A specifier has two halves and, where nothing renames, one node: `export { a };` is a single
    identifier filling both slots, exactly as a shorthand property is, and only the local half is
    a read. The table counts what a pass asking which names a program reads would be handed, so it
    says the answer follows the position: the exported name is not a read however it is spelled,
    and a `from` clause turns the local half into a name on the far side of the module boundary.
    """

    def test_the_halves_of_a_specifier_are_counted_by_position(self):
        rows = WHAT_A_NAME_IN_AN_EXPORT_LIST_COUNTS_FOR
        self.assertEqual(
            rows,
            {source: occurrences_of('a', source) for source in rows},
        )


#: A module exporting a binding through the declaration itself rather than a list, mapped to what
#: Node prints for it. `export var a` ties `a` to the outside in the declaration, so no list names
#: it and the specifier read that keeps the list form alive has nothing to attach to; the fact has
#: to be the binding's own. Every keyword is here, a function and a class and a default one, the
#: binding relocation would move into the one function writing it, the write nothing in the module
#: reads back, the const whose one reader is folded away, and the exported arrow whose one call
#: folds to its result while its declarator has to stay.
A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION = {
    _a_module_reporting_it_loaded('export let b = 5;'): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export function g() { return 3; }
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded('export class K {}'): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export default function h() { return 4; }
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export var a;
        a = 1;
        """
    ): 'loaded\n',
    inspect.cleandoc(
        """
        export var a;
        function f() { a = 2; return a; }
        console.log(f());
        """
    ): '2\n',
    inspect.cleandoc(
        """
        export const c = 7;
        console.log(c);
        """
    ): '7\n',
    inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(f());
        """
    ): '4\n',
}

#: The rows of `A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION` whose correct deobfuscation is not
#: the module itself: the const's reader is folded to the value and the exported function's one
#: call is folded to its result, while the export declaration stays in both, because an importer
#: reads the binding it names. The function row is the one an evaluator that folds the call and then
#: deletes the now-referenceless declarator would leave as `export const ;`, a module no engine
#: parses.
A_DECLARATION_EXPORT_INLINES_ITS_READERS = {
    inspect.cleandoc(
        """
        export const c = 7;
        console.log(c);
        """
    ): inspect.cleandoc(
        """
        export const c = 7;
        console.log(7);
        """
    ),
    inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(f());
        """
    ): inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(4);
        """
    ),
}

#: A module whose exported binding is written and never read again within it, and the importer that
#: reads that binding out of it. The module prints `1` and the importer prints the `1` the write
#: stored; a tool that drops the write as dead leaves the importer reading `undefined`, which no
#: single-file oracle can see, because the module itself reads `a` nowhere.
A_MODULE_WHOSE_EXPORTED_WRITE_AN_IMPORTER_READS = inspect.cleandoc(
    """
    export var a;
    a = 1;
    console.log(1);
    """
)
AN_IMPORTER_READING_THE_EXPORTED_WRITE = inspect.cleandoc(
    """
    import { a } from './lib.mjs';
    console.log(a);
    """
)
A_MODULE_WHOSE_FUNCTION_WRITES_THE_EXPORT = inspect.cleandoc(
    """
    export var a;
    var f = function () { a = 2; return a; };
    console.log(f());
    """
)

#: Modules whose exported function reads an element of an exported table, through an accessor and
#: directly, and the importer that changes the table before it calls the function. Node prints the
#: element the importer wrote; a module whose read became the element the text spells prints `a`.
MODULES_READING_AN_EXPORTED_TABLE = (
    inspect.cleandoc(
        """
        export const T = ['a'];
        function A(i) { return T[i]; }
        export function get() { return A(0); }
        """
    ),
    inspect.cleandoc(
        """
        export const T = ['a'];
        export function get() { return T[0]; }
        """
    ),
)
AN_IMPORTER_CHANGING_THE_EXPORTED_TABLE = inspect.cleandoc(
    """
    import { T, get } from './lib.mjs';
    T[0] = 'z';
    console.log(get());
    """
)


class TestAnExportDeclarationKeepsTheBindingItExports(TestBase):
    """
    A declaration written under an export ties the binding it declares to the outside: an importer
    reads its value once the module has run, so the declaration must stay where it stands, keep the
    writes that decide that value, and never be relocated out of module scope. This is the export
    list's rule stated for the declaration half, where there is no specifier and so no read for the
    fact to ride on — it is a fact of the binding itself.

    The rows put the rule in every declaration shape. Most come back untouched: a `let` with an
    initializer, a function, a class, a default-exported function, and the write to a `var` the
    module never reads back, which a dead-store sweep would drop although an importer reads it. The
    `var` whose every reference sits in one function would be relocated into that function, leaving
    an `export` naming a binding the module no longer declares, and stays put here. Two rows change:
    the `const` reader is folded to its value and the exported arrow's one call to its result, while
    each export declaration is kept, since removing it would strand the export. The arrow is the row
    an evaluator that folds the call and then deletes the now-referenceless declarator would
    leave as `export const ;`, a module no engine parses.
    """

    def test_a_module_that_only_exports_comes_back_as_it_was(self):
        rows = [
            source for source in A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
            if source not in A_DECLARATION_EXPORT_INLINES_ITS_READERS
        ]
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_an_inlined_reader_leaves_the_export_declaration_standing(self):
        rows = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    def test_every_rewritten_row_is_a_row_of_the_table(self):
        self.assertLessEqual(
            set(A_DECLARATION_EXPORT_INLINES_ITS_READERS),
            set(A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION),
        )

    def test_the_module_model_hands_back_the_same_modules(self):
        rows = A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
        rewrites = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(
            {source: printed(rewrites.get(source, source)) for source in rows},
            rewritten_as_modules(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_module_still_prints_what_it_printed(self):
        rows = A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_module_runs_the_way_the_module_it_replaces_does(self):
        rows = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: behavior(expected, module=True) for source, expected in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_exported_write_is_read_by_an_importer_after_the_fold(self):
        module = A_MODULE_WHOSE_EXPORTED_WRITE_AN_IMPORTER_READS
        importer = AN_IMPORTER_READING_THE_EXPORTED_WRITE
        agreed = ('1\n1\n', None)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                module_graph_behavior(
                    {
                        'main.mjs': importer,
                        'lib.mjs': deobfuscate_source(module, module=True),
                    },
                    'main.mjs',
                ),
            ),
            (agreed, agreed),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_function_writing_the_export_keeps_the_write_an_importer_reads(self):
        module = A_MODULE_WHOSE_FUNCTION_WRITES_THE_EXPORT
        importer = AN_IMPORTER_READING_THE_EXPORTED_WRITE
        agreed = ('2\n2\n', None)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                module_graph_behavior(
                    {
                        'main.mjs': importer,
                        'lib.mjs': deobfuscate_source(module, module=True),
                    },
                    'main.mjs',
                ),
            ),
            (agreed, agreed),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_of_an_exported_table_answers_what_an_importer_wrote(self):
        importer = AN_IMPORTER_CHANGING_THE_EXPORTED_TABLE
        self.assertEqual(
            {
                module: (
                    module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                    module_graph_behavior(
                        {
                            'main.mjs': importer,
                            'lib.mjs': deobfuscate_source(module, module=True),
                        },
                        'main.mjs',
                    ),
                )
                for module in MODULES_READING_AN_EXPORTED_TABLE
            },
            {
                module: (('z\n', None), ('z\n', None))
                for module in MODULES_READING_AN_EXPORTED_TABLE
            },
        )

    def test_a_read_of_an_exported_table_is_left_as_it_is(self):
        modules = MODULES_READING_AN_EXPORTED_TABLE
        self.assertEqual(
            {module: deobfuscate_source(module, module=True) for module in modules},
            {module: printed(module) for module in modules},
        )


#: A module written in every `export` form, mapped to the set of local binding names the export
#: ties to the outside. A declaration exports the names it declares, descending through
#: destructuring; a sourceless list exports each specifier's local half; an anonymous or expression
#: `export default`, a re-export, and `export *` name no local binding and tie nothing. The set is
#: the fact `_record_exports` must compute from the binding itself, since a declaration export has
#: no specifier read for the fact to ride on.
WHICH_LOCAL_BINDINGS_AN_EXPORT_TIES_TO_THE_OUTSIDE = {
    'export var a;': {'a'},
    'export let b = 5;': {'b'},
    'export const c = 7;': {'c'},
    'export var a, b;': {'a', 'b'},
    'export function g() {}': {'g'},
    'export class K {}': {'K'},
    'export const { a, b } = o;': {'a', 'b'},
    'export const [x, , y] = o;': {'x', 'y'},
    'export const { p: { q }, ...r } = o;': {'q', 'r'},
    'export const [a = 1] = o;': {'a'},
    'export default function h() {}': {'h'},
    'export default class D {}': {'D'},
    'export default function () {}': set(),
    'export default class {}': set(),
    'var foo = 1;\nexport default foo;': set(),
    'export default 1 + 2;': set(),
    'var q = 1;\nexport { q };': {'q'},
    'var q = 1;\nexport { q as w };': {'q'},
    'var q = 1;\nexport { q as default };': {'q'},
    "export { a } from 'm';": set(),
    "export { a as b } from 'm';": set(),
    "export * from 'm';": set(),
    "export * as ns from 'm';": set(),
}


def exported_bindings(source: str) -> set[str]:
    """
    The names of the bindings `SemanticModel._record_exports` flags as exported in *source*,
    gathered across every scope so a mark placed anywhere but module scope would show here too.
    """
    model = build_semantic_model(JsParser(source).parse())
    names: set[str] = set()
    stack = [model.root_scope]
    while stack:
        scope = stack.pop()
        names |= {name for name, binding in scope.bindings.items() if binding.exported}
        stack.extend(scope.children)
    return names


class TestRecordExportsMarksTheBindingEachExportFormTies(TestBase):
    """
    `_record_exports` marks exactly the local bindings an export ties to the outside, in every
    grammar form: a declaration under an export marks the names it declares, descending through
    destructuring; a sourceless list marks each specifier's local half; a named `export default`
    marks its name. An anonymous or expression default, a re-export, and `export *` mark nothing
    local, so a pass that finds no static read of such a name is free to act on it. This is the
    declaration half of the export-list rule, stated as a fact of the binding.
    """

    def test_each_export_form_ties_exactly_its_local_bindings(self):
        rows = WHICH_LOCAL_BINDINGS_AN_EXPORT_TIES_TO_THE_OUTSIDE
        self.assertEqual(
            rows,
            {source: exported_bindings(source) for source in rows},
        )


#: A program mentioning the name `type`, mapped to how many times it is written as an identifier and
#: how many of those occurrences read or write a binding. The first three put it in an import
#: attribute, where it names the attribute and refers to nothing; the last three are the controls,
#: the same word as a key written out, as a computed key, and as a shorthand.
WHAT_A_NAME_IN_AN_IMPORT_ATTRIBUTE_COUNTS_FOR = {
    inspect.cleandoc(
        """
        var type = 1;
        import d from './x.json' with { type: 'json' };
        console.log(type, d);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        import d from './x.json' with { type: 'json' };
        console.log(d);
        """
    ): (1, 0),
    inspect.cleandoc(
        """
        var type = 1;
        import d from './x.json' assert { type: 'json' };
        console.log(type, d);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        var type = 1;
        sink({ type: 'json' });
        console.log(type);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        var type = 'k';
        sink({ [type]: 'json' });
        console.log(type);
        """
    ): (3, 3),
    inspect.cleandoc(
        """
        var type = 1;
        sink({ type });
        console.log(type);
        """
    ): (3, 3),
}


class TestAnImportAttributeKeyIsNotARead(TestBase):
    """
    The key of an import attribute names the attribute and refers to nothing, exactly as a key
    written out in an object literal does. Nothing a program does can be made to show it: the
    attribute decides how a module is loaded, a module reached through it has to exist on disk to be
    loaded at all, and a key renamed or replaced makes the load fail rather than making the program
    answer differently. `refinery.lib.scripts.js.analysis.model.is_use_position` is therefore what
    this is stated over, counting how many occurrences of a name a pass asking whether the program
    reads it would be handed.

    The controls carry the same word in the two object-literal positions that are decided the other
    way and in the one that is decided both ways at once, so the table says that the answer follows
    the position and not the spelling of the name.
    """

    def test_an_attribute_key_is_counted_as_a_name_and_never_as_a_read(self):
        rows = WHAT_A_NAME_IN_AN_IMPORT_ATTRIBUTE_COUNTS_FOR
        self.assertEqual(
            rows,
            {source: occurrences_of('type', source) for source in rows},
        )


#: A program whose namespace object carries a property that a same-named property of another
#: receiver stands beside, mapped to the program flattening writes for it. Flattening turns `NS.q`
#: into a binding `q`, which is the one rewrite in the tool that gives a name to something that had
#: none; the other `q` in each program names a property of something else and is not the tool's to
#: touch.
A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME = {
    inspect.cleandoc(
        """
        var o = JSON.parse('{"q":9}');
        var NS = {};
        NS.q = 1;
        console.log(NS.q, o['q']);
        """
    ): inspect.cleandoc(
        """
        var q;
        var o = JSON.parse('{"q":9}');
        q = 1;
        console.log(q, o['q']);
        """
    ),
    inspect.cleandoc(
        """
        class C { ['q']() { return 'm'; } }
        var NS = {};
        NS.q = 1;
        console.log(NS.q, new C()['q']());
        """
    ): inspect.cleandoc(
        """
        var q;
        class C { ['q']() { return 'm'; } }
        q = 1;
        console.log(q, new C()['q']());
        """
    ),
}


class TestRenamingAVariableLeavesASameNamedPropertyAlone(TestJsDeobfuscator):
    """
    `refinery.lib.scripts.js.deobfuscation.namespaces.JsNamespaceFlattening` turns the properties of
    a namespace object into bindings, which is the rewrite that renames. A property of any other
    receiver spelled the same way is a different thing entirely, and both rows of
    `A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME` keep one beside the flattened
    namespace and read it afterwards.

    The pass is run on its own rather than through the whole tool, because the whole tool folds both
    reads to their values and a program with no reads left in it cannot say which name answered.
    """

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def test_a_property_of_another_receiver_is_not_renamed_with_the_namespace(self):
        rows = A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(
            spelled_as_expected(rows),
            {source: self._flatten(source) for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_flattened_program_prints_what_the_program_printed(self):
        rows = A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(
            run_by_node(rows),
            {source: behavior(self._flatten(source)) for source in rows},
        )
