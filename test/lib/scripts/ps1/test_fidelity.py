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

from refinery.lib.scripts import Node, canonical, child_list_fields, is_well_formed
from refinery.lib.scripts.ps1 import model as ps1model
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

#: One script per node class, written by hand rather than generated, and kept minimal so that a
#: failure names the construct it is about. Where a node has a child list, the snippet fills it
#: with two entries: the generator truncates from there, and a rendering that is only correct at
#: the cardinality its author had in mind is what this is looking for.
SNIPPETS: dict[str, str] = {
    'Block'                   : 'if ($a) { 1 }',
    'Ps1ArrayExpression'      : '@(1, 2)',
    'Ps1ArrayLiteral'         : '$x = 1, 2',
    'Ps1AssignmentExpression' : '$x = 1',
    'Ps1Attribute'            : 'function f { [CmdletBinding()] param($a) }',
    'Ps1BinaryExpression'     : '1 + 2',
    'Ps1BreakStatement'       : 'while ($a) { break }',
    'Ps1CastExpression'       : '[int]$x',
    'Ps1CatchClause'          : 'try { 1 } catch [A], [B] { 2 } catch { 3 }',
    'Ps1ClassDefinition'      : 'class C : B { [int] $P; [void] M() { 1 } }',
    'Ps1CommandArgument'      : 'Get-Item -Path a b',
    'Ps1CommandInvocation'    : 'Get-Item a b',
    'Ps1ContinueStatement'    : 'while ($a) { continue }',
    'Ps1DataSection'          : 'data d { 1 }',
    'Ps1DoLoop'               : 'do { 1 } while ($a)',
    'Ps1EnumDefinition'       : 'enum E { A = 1; B = 2 }',
    'Ps1EnumMember'           : 'enum E { A = 1; B = 2 }',
    'Ps1ExitStatement'        : 'exit 1',
    'Ps1ExpandableHereString' : '@"\na$b\n"@',
    'Ps1ExpandableString'     : '"a$b c"',
    'Ps1ExpressionStatement'  : '1',
    'Ps1FileRedirection'      : 'a > b',
    'Ps1ForEachLoop'          : 'foreach ($i in $a) { 1 }',
    'Ps1ForLoop'              : 'for ($i = 0; $i -lt 2; $i++) { 1 }',
    'Ps1FunctionDefinition'   : 'function f { 1 }',
    'Ps1HashLiteral'          : '@{ a = 1; b = 2 }',
    'Ps1HereString'           : "@'\nabc\n'@",
    'Ps1IfStatement'          : 'if ($a) { 1 } elseif ($b) { 2 } else { 3 }',
    'Ps1IndexExpression'      : '$x[0]',
    'Ps1InputRedirection'     : 'a < b',
    'Ps1IntegerLiteral'       : '1',
    'Ps1InvokeMember'         : '$x.Substring(1, 2)',
    'Ps1MemberAccess'         : '$x.Length',
    'Ps1MergingRedirection'   : 'a 2>&1',
    'Ps1MethodMember'         : 'class C { [void] M() { 1 } }',
    'Ps1ParamBlock'           : 'function f { param($a, $b) }',
    'Ps1ParameterDeclaration' : 'function f { param([int] $a, $b) }',
    'Ps1ParenExpression'      : '(1)',
    'Ps1Pipeline'             : 'a | b',
    'Ps1PipelineElement'      : 'a | b',
    'Ps1PropertyMember'       : 'class C { [int] $P }',
    'Ps1RangeExpression'      : '1..2',
    'Ps1RealLiteral'          : '1.5',
    'Ps1ReturnStatement'      : 'return 1',
    'Ps1Script'               : '1',
    'Ps1ScriptBlock'          : '{ 1; 2 }',
    'Ps1StringLiteral'        : "'a'",
    'Ps1SubExpression'        : '$(1; 2)',
    'Ps1SwitchStatement'      : 'switch ($a) { 1 { "x" } default { "y" } }',
    'Ps1ThrowStatement'       : 'throw 1',
    'Ps1TrapStatement'        : 'trap [E] { 1 }',
    'Ps1TryCatchFinally'      : 'try { 1 } catch { 2 } finally { 3 }',
    'Ps1TypeExpression'       : 'function f { param([int] $a) }',
    'Ps1UnaryExpression'      : '-not $x',
    'Ps1Variable'             : '$x',
    'Ps1WhileLoop'            : 'while ($a) { 1 }',
}

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

    def _truncations(self, source: str):
        for index, node in enumerate(self._parse(source).walk_in_order()):
            for field, items in child_list_fields(node):
                for size in range(len(items)):
                    yield index, field, size
