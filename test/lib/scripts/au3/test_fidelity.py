"""
The law that the AutoIt3 parser and synthesizer are inverses of one another, and the corpus it is
checked over.

Every pass rewrites a tree and the tool then prints it, so a rendering that reads back as a
different program silently changes what a script does. What makes such a defect hard to see is that
it usually survives a second round trip unchanged: printing `f((a, b))` as `f(a, b)` is a fixed
point, so a test that only asserts the output is *stable* reports nothing. The law asserted here is
fidelity rather than stability — what comes back out is the same program that went in — and it is
checked without running a single deobfuscation pass, so it says something about this layer alone.

Sameness is `refinery.lib.scripts.canonical`, which compares away exactly what the model declares
is spelling rather than meaning. It is deliberately blind to how a value was written, and what that
buys and costs for AutoIt3 is stated in `TestAu3SamenessIsBlindToHowAValueIsWritten` below.

The law is quantified over the trees that spell a program. Half of that is
`refinery.lib.scripts.is_well_formed`, which for this model answers one question: a member access
with a leading dot that no enclosing `With` statement owns. The other half is
`test.lib.scripts.au3.corpus.shapes_the_grammar_forbids`, which states the shapes the model does not
refuse on its own. A domain a filter decides is one whose size is invisible, so it is asserted
rather than assumed: every snippet is required to be in it, and a cut child list is required to
leave it only for a shape the grammar names.

Three tiers of input feed the law:

- `SNIPPETS`, one hand-authored program per node class, which is also what the generators mutate.
  Every concrete node class appears there, and a class added to the model without an entry fails
  `test_every_node_class_has_a_snippet` rather than going unchecked.
- Every string literal in the test modules of this package that is a program rather than prose or a
  piece of one, and that looks like AutoIt3. These are the inputs the rest of the suite already
  exercises, read back out of it so that the law covers them too.
- The generators, which cut a child list short and which take the parentheses away. Both reach tree
  shapes a pass builds and a parse never produces, and it is those shapes a printer is most likely
  to have no rule for.
"""
from __future__ import annotations

import ast as pyast
import functools
import glob
import os

from test import TestBase
from test.lib.scripts.au3.corpus import SNIPPETS, shapes_the_grammar_forbids

from refinery.lib.scripts import (
    Node,
    canonical,
    child_list_fields,
    is_well_formed,
    owning_field,
    owning_list,
    set_child,
    set_child_list,
)
from refinery.lib.scripts.au3 import model as au3model
from refinery.lib.scripts.au3.model import Au3ParenExpression
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer

#: A string is taken for AutoIt3 when it carries at least one of these. Punctuation rather than
#: keywords, because a sentence about AutoIt3 is full of the keywords and a program that does
#: anything is full of the punctuation. The pattern is deliberately generous either way: an input
#: that is not AutoIt3 parses to something with an error node in it, which the domain below leaves
#: out, whereas one that is and gets skipped is coverage silently lost.
HINTS = ('$', '@', '(', '"', '#')

#: The corpus cannot silently shrink to nothing: a harvest that stops matching would leave the law
#: quantified over almost no inputs and still green. The bound is well under the count observed so
#: far that adding or removing a test does not move it.
MINIMUM_HARVEST = 150

#: Differences for which fidelity is known not to hold, each with the reason it does not. The
#: mapping is checked in both directions — every difference the corpus produces must be listed, and
#: every entry must still be produced by something — so a fix cannot land without removing its
#: entry, and a regression cannot hide behind one. An entry names a normalization that preserves the
#: program; work that has not been done yet is not a reason, because the law would then be satisfied
#: by writing it down. The synthesizer normalizes nothing this model counts: keywords never enter
#: the tree, a single-line `If` parses to the same tree as the block form, and `canonical` itself
#: identifies a parenthesized expression with what it holds, so printing brackets the program needs
#: is not a difference at all.
KNOWN_VIOLATIONS: dict[str, str] = {}


@functools.cache
def _harvested() -> tuple[str, ...]:
    """
    Every AutoIt3 string the test modules of this package hold, deduplicated and in a stable order.
    Two kinds of string are not data. One is prose: a string standing alone as a statement, which
    is what a docstring is — in a module, in a class, in a function, and after the variable it
    documents. The other is a fragment: the literal parts of an f-string are pieces of a program and
    not one, since `F'If {name} Then'` holds the text `If ` and ` Then` and no test ever ran
    either. The module this function is defined in is skipped as well, because its own strings are
    the reasons above rather than programs the suite exercises.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    seen: set[str] = set()
    result: list[str] = []
    for path in sorted(glob.glob(os.path.join(here, '**', 'test_*.py'), recursive=True)):
        if os.path.abspath(path) == os.path.abspath(__file__):
            continue
        with open(path, 'r', encoding='utf8') as fd:
            tree = pyast.parse(fd.read(), filename=path)
        prose = {
            id(node.value) for node in pyast.walk(tree)
            if isinstance(node, pyast.Expr)
            and isinstance(node.value, pyast.Constant)
            and isinstance(node.value.value, str)
        }
        fragments = {
            id(part) for node in pyast.walk(tree) if isinstance(node, pyast.JoinedStr)
            for part in pyast.walk(node) if isinstance(part, pyast.Constant)
        }
        for node in pyast.walk(tree):
            if not isinstance(node, pyast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in prose or id(node) in fragments:
                continue
            text = node.value.strip('\n')
            if not text.strip() or len(text) > 4000 or text in seen:
                continue
            seen.add(text)
            if any(hint in text for hint in HINTS):
                result.append(text)
    return tuple(result)


def _differences(before: Node, after: Node) -> set[str]:
    """
    How the program that came back differs from the one that went in, named one difference at a
    time. `canonical` answers whether two trees are the same program and not how they part ways, and
    a printer that normalizes has to be described by *what* it normalizes: the inputs that reach a
    normalization are a corpus that changes, the normalizations themselves are a short list that
    does not.

    A difference the classifier has no name for is named after the two node types, so that an
    unforeseen one is reported rather than swallowed.
    """
    found: set[str] = set()

    def compare(one: Node, other: Node) -> bool:
        if canonical(one) == canonical(other):
            return False
        if type(one) is not type(other):
            found.add(F'{type(one).__name__} is printed as {type(other).__name__}')
            return True
        mine, theirs = one.children(), other.children()
        if len(mine) != len(theirs):
            found.add(
                F'{type(one).__name__} holds {len(mine)} children and prints with {len(theirs)}')
            return True
        differed = False
        for child, counterpart in zip(mine, theirs):
            differed = compare(child, counterpart) or differed
        if not differed:
            found.add(F'{type(one).__name__} differs in a value it holds')
        return True

    compare(before, after)
    return found


def _strip_parentheses(root: Node) -> bool:
    """
    Replace every parenthesis in the tree with what it holds, and report whether anything moved.
    """
    changed = False
    for node in list(root.walk()):
        if not isinstance(node, Au3ParenExpression) or node.expression is None:
            continue
        inner = node.expression
        if (field := owning_field(node)) is not None:
            holder, name = field
            set_child(holder, name, inner)
        elif (entry := owning_list(node)) is not None:
            holder, name = entry
            set_child_list(holder, name, [
                inner if item is node else item for item in getattr(holder, name)
            ])
        else:
            continue
        changed = True
    return changed


class TestAu3Fidelity(TestBase):

    @staticmethod
    def _parse(source: str) -> Node:
        return Au3Parser(source).parse()

    @staticmethod
    def _synth(tree: Node) -> str:
        return Au3Synthesizer().convert(tree)

    @staticmethod
    def _spells_a_program(tree: Node) -> bool:
        return is_well_formed(tree) and not shapes_the_grammar_forbids(tree)

    def _corpus(self) -> list[str]:
        return [*SNIPPETS.values(), *_harvested()]

    def _parsed(self, source: str) -> Node | None:
        tree = self._parse(source)
        return tree if self._spells_a_program(tree) else None

    def _unbracketed(self, source: str) -> Node | None:
        tree = self._parsed(source)
        if tree is None:
            return None
        while _strip_parentheses(tree):
            pass
        return tree if self._spells_a_program(tree) else None

    def _round_trip(self, tree: Node) -> tuple[str, set[str]]:
        printed = self._synth(tree)
        return printed, _differences(tree, self._parse(printed))

    def test_the_harvest_still_finds_the_corpus(self):
        self.assertGreater(len(_harvested()), MINIMUM_HARVEST)

    def test_every_node_class_has_a_snippet(self):
        """
        A node class with no snippet is one the law is never asked about, so the table is required
        to keep up with the model. Two kinds of class are exempt: an abstract base, which the model
        refines and the parser never builds on its own, and an `unparsed` class, which stands for
        source no parser read so that printing it back says nothing about fidelity.
        """
        classes = {
            name: value for name, value in vars(au3model).items()
            if isinstance(value, type) and issubclass(value, Node) and not name.startswith('_')
        }
        refined = {base.__name__ for value in classes.values() for base in value.__mro__[1:]}
        concrete = {
            name for name, value in classes.items()
            if name not in refined and not value.unparsed
        }
        self.assertEqual(sorted(concrete - set(SNIPPETS)), [])

    def test_every_snippet_parses_to_the_node_class_it_names(self):
        for name, source in SNIPPETS.items():
            with self.subTest(node=name):
                produced = {type(node).__name__ for node in self._parse(source).walk()}
                self.assertIn(name, produced)

    def test_every_snippet_spells_a_program(self):
        """
        The domain the laws below are stated over, asserted rather than assumed. A source that
        spells no program is skipped by each of them, and a skip is a filter: a parser that stops
        reading a construct takes every source holding it out of the domain, which leaves the laws
        quantified over less and every one of them green.

        Only the hand-authored half can carry the claim, and it carries it as far as it can: each
        snippet is a program the pegjs grammar and the language documentation read, so a snippet
        outside the domain is the parser being wrong about AutoIt3 rather than the corpus holding
        text no reference reads. Nothing stronger can be said without an AutoIt3 installation, which
        is also why nothing here executes a snippet. Nothing of the kind can be said about the
        harvested half either, which is every AutoIt3 string the suite holds and therefore holds the
        ones a test deliberately left broken.

        With `test_every_node_class_has_a_snippet`, this is what makes fidelity a statement about
        every node class rather than about whichever ones the parser still reads: the table has an
        entry per class, and every entry is in the domain.
        """
        skipped = [
            name for name, source in SNIPPETS.items()
            if not self._spells_a_program(self._parse(source))
        ]
        self.assertEqual(skipped, [])

    def test_the_parser_never_builds_a_shape_the_grammar_forbids(self):
        """
        A shape the language cannot write is one the parser must not hand back, because the
        synthesizer then has to invent a spelling for it and the tool fails on, or silently changes,
        input it had just read. Recovery has one escape hatch for this and it is `Au3ErrorNode`,
        which keeps the source verbatim and is excluded from the law by `is_well_formed`.
        """
        for source in self._corpus():
            with self.subTest(source=source):
                self.assertEqual(shapes_the_grammar_forbids(self._parse(source)), [])

    def test_the_synthesizer_inverts_the_parser(self):
        for source in self._corpus():
            if (tree := self._parsed(source)) is None:
                continue
            with self.subTest(source=source):
                printed, differences = self._round_trip(tree)
                self.assertEqual(
                    sorted(differences - set(KNOWN_VIOLATIONS)), [], F'printed as {printed!r}')

    def test_every_known_violation_is_produced_by_the_corpus(self):
        """
        The other direction of the mapping. An entry that nothing reaches any more is a claim about
        the printer that nothing checks, and it would keep admitting the difference it names long
        after the printer stopped making it.
        """
        witnessed: set[str] = set()
        for source in self._corpus():
            if set(KNOWN_VIOLATIONS) <= witnessed:
                break
            for reading in (self._parsed(source), self._unbracketed(source)):
                if reading is not None:
                    witnessed |= self._round_trip(reading)[1]
        self.assertEqual(sorted(set(KNOWN_VIOLATIONS) - witnessed), [])

    def test_the_output_is_stable(self):
        """
        Printing what was printed changes nothing. This is weaker than fidelity and does not follow
        from it — `canonical` ignores spelling, so a rendering that alternates between two spellings
        of one value satisfies the law and fails here — and it is asserted over the same domain,
        since a tree that spells no program has no output to be stable.
        """
        for source in self._corpus():
            if (tree := self._parsed(source)) is None:
                continue
            with self.subTest(source=source):
                once = self._synth(tree)
                self.assertEqual(once, self._synth(self._parse(once)))

    def test_the_synthesizer_inverts_the_parser_at_every_cardinality(self):
        """
        The generator: each snippet is re-parsed and one of its child lists is cut short, which
        reaches the tree shapes a pass builds when it removes the last argument of a call or the
        last element of an array. This is what catches a rendering that is only valid at the
        cardinality it was written for — a separator printed between entries that are no longer
        there is exactly that — and it is why the shortened lists are checked rather than only the
        ones a script happens to spell. A cut that leaves a shape the grammar has no text for is not
        one a pass makes, so it is passed over rather than printed.
        """
        for name, source in SNIPPETS.items():
            for index, field, size in self._truncations(source):
                with self.subTest(node=name, field=field, size=size):
                    tree = self._truncated(source, index, field, size)
                    if not self._spells_a_program(tree):
                        continue
                    printed, differences = self._round_trip(tree)
                    self.assertEqual(
                        sorted(differences - set(KNOWN_VIOLATIONS)), [],
                        F'{field}[:{size}] printed as {printed!r}')

    def test_a_truncation_is_passed_over_only_for_a_shape_the_grammar_forbids(self):
        """
        The domain the law above is stated over. A cut that leaves no program is passed over rather
        than printed, so were cutting to stop producing programs the law would check nothing and
        report it nowhere.

        Only one of the two ways out of the domain is a reason. Removing entries from a child list
        can leave a shape no text spells, which is what `SHORTEST_LIST` states from the grammar, and
        a cut reaching one of those is not a cut a pass makes. Cutting cannot instead take a tree
        out of `is_well_formed`: a leading-dot member sits inside the body of the `With` that owns
        it, so removing statements wholesale cannot orphan one, and a shorter list is a walk over
        fewer nodes rather than over different ones. Were that ever to change, the rule about how
        short a list may be would have moved into the model, and this is what says so.
        """
        unspelled = [
            (name, field, size)
            for name, source in SNIPPETS.items()
            for index, field, size in self._truncations(source)
            if not is_well_formed(self._truncated(source, index, field, size))
        ]
        self.assertEqual(unspelled, [])

    def test_the_synthesizer_inverts_the_parser_without_the_original_brackets(self):
        """
        The generator that reaches the trees a pass actually builds. Every parenthesis is replaced
        by what it holds, which is what happens whenever a transform folds an expression into the
        slot a parenthesis used to occupy, and the synthesizer then has to put back exactly the
        brackets the program needs. A tree that came from a parse carries its own parentheses and so
        says nothing about whether the printer can do this.
        """
        for source in self._corpus():
            if (tree := self._unbracketed(source)) is None:
                continue
            with self.subTest(source=source):
                printed, differences = self._round_trip(tree)
                self.assertEqual(
                    sorted(differences - set(KNOWN_VIOLATIONS)), [], F'printed as {printed!r}')

    def _truncations(self, source: str):
        for index, node in enumerate(self._parse(source).walk_in_order()):
            for field, items in child_list_fields(node):
                for size in range(len(items)):
                    yield index, field, size

    def _truncated(self, source: str, index: int, field: str, size: int) -> Node:
        tree = self._parse(source)
        holder = list(tree.walk_in_order())[index]
        set_child_list(holder, field, getattr(holder, field)[:size])
        return tree


class TestAu3SamenessIsBlindToHowAValueIsWritten(TestBase):
    """
    What the law above compares values by. `canonical` is blind to the text of a literal and to the
    case of a name, and for AutoIt3 that is the right blindness: `0x10` and `16` denote one number,
    either quote style around `a` denotes one string, and `$FOO` is `$foo` because the interpreter
    reads variables without case. What it is not blind to is the value itself and the operator that
    carries it, which is why `=` and `==` stay two programs, and why `0x80000000` is not
    `2147483648`: AutoIt reads a hexadecimal literal of up to eight digits as a signed 32-bit
    number, so it carries the value `-2147483648`. The minus of a decimal is an operator in the
    tree rather than part of the literal, so `0x80000000` and `-2147483648` are two programs although
    AutoIt computes the same value from both.
    """

    @staticmethod
    def _parse(source: str) -> Node:
        return Au3Parser(source).parse()

    def test_two_spellings_of_one_value_are_one_program(self):
        for one, other in (
            ('$x = 0x10', '$x = 16'),
            ('$x = 1.50', '$x = 1.5'),
            ('$x = "a"', '$x = \'a\''),
            ('$x = $FOO', '$x = $foo'),
            ('$x = @SCRIPTDIR', '$x = @ScriptDir'),
            ('If $x Then\n$y = 1\nEndIf', 'IF $x THEN\n$y = 1\nENDIF'),
        ):
            with self.subTest(one=one, other=other):
                self.assertEqual(canonical(self._parse(one)), canonical(self._parse(other)))

    def test_two_values_are_two_programs(self):
        for one, other in (
            ('$x = 255', '$x = 256'),
            ('$x = 0x80000000', '$x = 2147483648'),
            ('$x = "a"', '$x = "b"'),
            ('If $x = 1 Then\n$y = 1\nEndIf', 'If $x == 1 Then\n$y = 1\nEndIf'),
        ):
            with self.subTest(one=one, other=other):
                self.assertNotEqual(canonical(self._parse(one)), canonical(self._parse(other)))
