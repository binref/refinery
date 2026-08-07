"""
The law that the PowerShell parser and synthesizer are inverses of one another, and the corpus it
is checked over.

Every pass rewrites a tree and the tool then prints it, so a rendering that reads back as a
different program silently changes what a script does. What makes such a defect hard to see is that
it usually survives a second round trip unchanged: printing `$x = ,1` as `$x = 1` is a fixed point,
so a test that only asserts the output is *stable* reports nothing. The law asserted here is
fidelity rather than stability — what comes back out is the same program that went in — and it is
checked without running a single deobfuscation pass, so it says something about this layer alone.

Sameness is `refinery.lib.scripts.canonical`, which compares away exactly what the model declares
is spelling rather than meaning. It is deliberately blind to how a value was written, so the few
places where an exact spelling is the point keep their own assertions in `test_synth.py`.

Two tiers of input feed the law:

- `SNIPPETS`, one hand-authored script per node class, which is also what the generator mutates.
  Every concrete node class appears here, and a class added to the model without an entry fails
  `test_every_node_class_has_a_snippet` rather than going unchecked.
- Every string literal in the PowerShell test files listed in `HARVEST` that is not a docstring and
  that looks like PowerShell. These are the inputs the rest of the suite already exercises, read
  back out of it so that the law covers them too.
"""
from __future__ import annotations

import ast as pyast
import os

from test import TestBase
from test.lib.scripts.ps1.corpus import SNIPPETS

from refinery.lib.scripts import (
    Node,
    canonical,
    child_list_fields,
    is_well_formed,
    owning_field,
    owning_list,
)
from refinery.lib.scripts.ps1 import model as ps1model
from refinery.lib.scripts.ps1.model import Ps1ParenExpression
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

#: The test files whose PowerShell string literals are read back into the corpus. These are the
#: files that hold PowerShell as data; a file that merely mentions it in prose is not listed,
#: because the harvest cannot tell a script from a sentence about one.
HARVEST = [
    'test_parser_shape.py',
    'test_parser_expr.py',
    'test_parser_stmt.py',
    'test_lexer.py',
    'test_synth.py',
    'test_corruptions.py',
    'test_ast.py',
]

#: A string is taken for PowerShell when it carries at least one of these. The pattern is
#: deliberately generous: an input that is not PowerShell parses to something the law holds for
#: anyway, whereas one that is and gets skipped is coverage silently lost.
HINTS = (
    '$', '@(', '@{', '::', '|', '[', 'function', 'param', 'if', 'foreach', 'while', 'switch',
    'try', 'do', 'for', 'class', 'enum', 'return', 'throw', 'exit', 'trap', 'data', 'filter',
    'break', 'continue', '"', "'",
)

#: The corpus cannot silently shrink to nothing: a harvest that stops matching would leave the law
#: quantified over almost no inputs and still green. The bound is well under the count observed so
#: that adding or removing a test does not move it.
MINIMUM_HARVEST = 400

#: Inputs for which fidelity is known not to hold, each with the reason it does not. The mapping is
#: checked in both directions — every entry must still fail and everything absent must pass — so a
#: fix cannot land without removing its entry, and a regression cannot hide behind one. An entry
#: names a deliberate normalization the model makes; work that has not been done yet is not a
#: reason, because the law would then be satisfied by writing it down.
KNOWN_VIOLATIONS: dict[str, str] = {}

#: The same, for the paren-stripped tier. Every entry here is one shape: an argument built with the
#: comma operator cannot be bracketed until the words inside it are re-spelled as quoted strings,
#: because what stands inside a bracket is read as a pipeline and a bare word there is a command
#: name. Bracketing them first would break more than it fixes, so the bracket is withheld and the
#: loss recorded until the leaf spellings are chosen by the slot they are printed into.
KNOWN_BRACKET_VIOLATIONS: dict[str, str] = {
    'New-Object IO.MemoryStream (,$b)':
        'a comma-built argument needs a bracket that needs its elements re-spelled first',
    'New-Object IO.MemoryStream(,$b)':
        'a comma-built argument needs a bracket that needs its elements re-spelled first',
    'Should -Be [System.Management.Automation.LanguagePrimitives]::ConvertTo($rval, [string])':
        'a comma-built argument needs a bracket that needs its elements re-spelled first',
}


def _harvested() -> list[str]:
    here = os.path.dirname(__file__)
    seen: set[str] = set()
    result: list[str] = []
    for name in HARVEST:
        path = os.path.join(here, name)
        with open(path, 'r', encoding='utf-8') as fd:
            tree = pyast.parse(fd.read(), filename=path)
        prose = set()
        for node in pyast.walk(tree):
            if not isinstance(node, (pyast.Module, pyast.ClassDef, pyast.FunctionDef)):
                continue
            if node.body and isinstance(first := node.body[0], pyast.Expr):
                if isinstance(first.value, pyast.Constant) and isinstance(first.value.value, str):
                    prose.add(id(first.value))
        for node in pyast.walk(tree):
            if not isinstance(node, pyast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in prose:
                continue
            text = node.value.strip('\n')
            if not text.strip() or len(text) > 4000 or text in seen:
                continue
            seen.add(text)
            if any(hint in text for hint in HINTS):
                result.append(text)
    return result


def _strip_parentheses(root: Node) -> bool:
    """
    Replace every parenthesis in the tree with what it holds, and report whether anything moved.
    """
    changed = False
    for node in list(root.walk()):
        if not isinstance(node, Ps1ParenExpression) or node.expression is None:
            continue
        inner = node.expression
        if (field := owning_field(node)) is not None:
            holder, name = field
            setattr(holder, name, inner)
        elif (entry := owning_list(node)) is not None:
            holder, name = entry
            items = getattr(holder, name)
            items[:] = [inner if item is node else item for item in items]
        else:
            continue
        inner.parent = holder
        changed = True
    return changed


class TestPs1Fidelity(TestBase):

    @staticmethod
    def _parse(source: str) -> Node:
        return Ps1Parser(source).parse()

    @staticmethod
    def _synth(tree: Node) -> str:
        return Ps1Synthesizer().convert(tree)

    def _is_faithful(self, tree: Node) -> bool:
        return canonical(self._parse(self._synth(tree))) == canonical(tree)

    def _corpus(self) -> list[str]:
        return [*SNIPPETS.values(), *_harvested()]

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
            name: value for name, value in vars(ps1model).items()
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
                produced = {type(n).__name__ for n in self._parse(source).walk()}
                self.assertIn(name, produced)

    def test_the_parser_never_builds_a_node_that_has_no_spelling(self):
        """
        A shape the language cannot write is one the parser must not hand back, because the
        synthesizer refuses it and the tool would then fail on input it had just read. Error
        recovery has one escape hatch for this and it is `Ps1ErrorNode`, which always prints.
        """
        for source in self._corpus():
            with self.subTest(source=source):
                unspellable = [
                    type(node).__name__
                    for node in self._parse(source).walk()
                    if not node.has_spelling()
                ]
                self.assertEqual(unspellable, [])

    def test_the_synthesizer_inverts_the_parser(self):
        for source in self._corpus():
            tree = self._parse(source)
            if not is_well_formed(tree):
                continue
            with self.subTest(source=source):
                faithful = self._is_faithful(tree)
                reason = KNOWN_VIOLATIONS.get(source)
                if reason is None:
                    self.assertTrue(faithful, F'not faithful: {self._synth(tree)!r}')
                else:
                    self.assertFalse(faithful, F'listed as violating but holds: {reason}')

    def test_every_known_violation_is_an_input_of_the_corpus(self):
        self.assertEqual(sorted(set(KNOWN_VIOLATIONS) - set(self._corpus())), [])

    def test_the_output_is_stable(self):
        """
        Printing what was printed changes nothing. This is weaker than fidelity and does not follow
        from it — `canonical` ignores spelling, so a rendering that alternates between two spellings
        of one value satisfies the law and fails here.
        """
        for source in self._corpus():
            with self.subTest(source=source):
                once = self._synth(self._parse(source))
                self.assertEqual(once, self._synth(self._parse(once)))

    def test_the_synthesizer_inverts_the_parser_at_every_cardinality(self):
        """
        The generator: each snippet is re-parsed and one of its child lists is cut short, which
        reaches the tree shapes a pass builds when it removes the last argument of a call or the
        last element of an array. This is what catches a rendering that is only valid at the
        cardinality it was written for — printing a one-element array literal without the comma
        that makes it an array is exactly that, and it is why the shortened lists are checked
        rather than only the ones a script happens to spell.
        """
        for name, source in SNIPPETS.items():
            for index, field, size in self._truncations(source):
                with self.subTest(node=name, field=field, size=size):
                    tree = self._parse(source)
                    holder = list(tree.walk_in_order())[index]
                    setattr(holder, field, getattr(holder, field)[:size])
                    if not is_well_formed(tree):
                        continue
                    self.assertTrue(
                        self._is_faithful(tree),
                        F'not faithful at {field}[:{size}]: {self._synth(tree)!r}')

    def test_the_synthesizer_inverts_the_parser_without_the_original_brackets(self):
        """
        The generator that reaches the trees a pass actually builds. Every parenthesis is replaced
        by what it holds, which is what happens whenever a transform folds an expression into the
        slot a parenthesis used to occupy, and the synthesizer then has to put back exactly the
        brackets the program needs. A tree that came from a parse carries its own parentheses and
        so says nothing about whether the printer can do this.
        """
        for source in self._corpus():
            tree = self._parse(source)
            if not is_well_formed(tree):
                continue
            while _strip_parentheses(tree):
                pass
            if not is_well_formed(tree):
                continue
            with self.subTest(source=source):
                faithful = self._is_faithful(tree)
                reason = KNOWN_BRACKET_VIOLATIONS.get(source)
                if reason is None:
                    self.assertTrue(faithful, F'not faithful: {self._synth(tree)!r}')
                else:
                    self.assertFalse(faithful, F'listed as violating but holds: {reason}')

    def test_every_known_bracket_violation_is_an_input_of_the_corpus(self):
        self.assertEqual(sorted(set(KNOWN_BRACKET_VIOLATIONS) - set(self._corpus())), [])

    def _truncations(self, source: str):
        for index, node in enumerate(self._parse(source).walk_in_order()):
            for field, items in child_list_fields(node):
                for size in range(len(items)):
                    yield index, field, size
