import ast
import functools
import importlib
import os.path
import pkgutil
import pytest
import symtable
import unittest

from contextlib import ExitStack
from glob import glob
from typing import NamedTuple
from unittest.mock import patch

from . import TestBase, TestUnitBase

import refinery.lib.scripts as scripts

from refinery.lib.scripts.ps1.deobfuscation import removal


#: The module that owns statement removal, and so the one place a removal may be spelled out. Path
#: anchored rather than matched by base name, so a `removal.py` elsewhere in the tree is still read.
_RATCHET_OWNER = os.path.join('deobfuscation', 'removal.py')

#: The module that owns putting one node in another's place, exempt from the ratchet on the tree
#: primitives for the same reason and read the same way.
_SUBSTITUTION_OWNER = os.path.join('deobfuscation', 'substitution.py')

_PASSES = os.path.join('refinery', 'lib', 'scripts', 'ps1', 'deobfuscation')

_TESTS = os.path.join('test', 'lib', 'scripts', 'ps1', 'deobfuscation')

#: The witness suite runs whole suites of its own under mutation, so a run of it would report a
#: guard firing inside a deliberately broken analysis. Excluded to keep the evidence the tests'
#: own, and because rerunning it here costs more than the rest of the directory together. Stated
#: once because both observations below read the same run: a divergence in what either of them
#: excludes is how one starts watching an analysis the other broke.
_EXCLUDED = 'test_witnessed'


def _project_root() -> str:
    """
    The repository root, found by walking up from this file. Every check below globs source trees
    relative to it, and a check whose glob comes back empty passes on nothing at all, so the walk
    is written once rather than repeated at each call site.
    """
    root = os.path.abspath(__file__)
    for _ in range(3):
        root = os.path.dirname(root)
    return root


@functools.lru_cache(maxsize=None)
def _parse(path: str) -> ast.Module:
    """
    The parsed source at `path`. Cached because the checks below overlap: the removal ratchet reads
    every `ps1` source and the protected-body ratchet reads the deobfuscation package again.
    """
    with open(path, 'r', encoding='utf8') as stream:
        return ast.parse(stream.read(), path)


def _sources(*parts: str) -> list[tuple[str, ast.Module]]:
    """
    Every Python source under the given path, relative to the repository root, beside its parse. A
    glob that comes back empty is an error rather than a result, for the reason `_project_root`
    gives: a check with nothing to read passes on nothing at all.
    """
    directory = os.path.join(*parts)
    paths = glob(os.path.join(_project_root(), directory, '**', '*.py'), recursive=True)
    if not paths:
        raise FileNotFoundError(F'no sources found under {directory}')
    return [(path, _parse(path)) for path in sorted(paths)]


class TestRemovalDiscipline(TestUnitBase):
    """
    A statement is removed from a PowerShell body in exactly one place. Every removal has to pass
    the vetoes that keep a payload from being deleted, and a pass that deletes a statement by any
    other route reaches none of them — the guard set it skips is invisible at the call site and
    stays invisible in review, which is how the two removal sites in `unused.py` came to answer the
    fault question differently. This is a ratchet: the exempt list only shrinks.

    Both spellings of a bypass are looked for, because both have occurred. `_remove_from_parent` is
    searched for by *name*, anywhere in the module, so that reaching it through the module object
    rather than through a `from ... import` is caught too. `BodyEdit` is searched for by *use*, and
    by any use rather than by the empty-replacement spelling a deletion takes: `iexinline.py`
    spliced a statement out and its inlined code in through a raw edit, which is a substitution and
    so no deletion at all, and the narrower reading let it past a check written for that module.
    """

    #: Packages whose deobfuscation passes still remove statements without a removal plan. Every
    #: name here is work not yet done, not a language that is exempt on principle.
    UNRATCHETED = ('js',)

    @classmethod
    def _removes_statements(cls, tree: ast.Module) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == '_remove_from_parent':
                return True
            if isinstance(node, ast.Attribute) and node.attr == '_remove_from_parent':
                return True
            if isinstance(node, ast.alias) and node.name == '_remove_from_parent':
                return True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == 'splice':
                    return True
        return False

    @classmethod
    def _offenders(cls, language: str) -> list[str]:
        root = _project_root()
        return [
            os.path.relpath(path, root)
            for path, tree in _sources('refinery', 'lib', 'scripts', language)
            if not path.endswith(_RATCHET_OWNER)
            and cls._removes_statements(tree)
        ]

    def test_no_ps1_pass_removes_a_statement_outside_a_removal_plan(self):
        self.assertListEqual(
            self._offenders('ps1'), [], 'use refinery.lib.scripts.ps1.deobfuscation.removal')

    def test_the_unratcheted_languages_are_still_unratcheted(self):
        for language in self.UNRATCHETED:
            if not self._offenders(language):
                self.fail(F'{language} no longer needs the exemption; drop it from UNRATCHETED')


class TestSubstitutionDiscipline(TestUnitBase):
    """
    One part of the PowerShell tree is put in another's place in exactly two modules: the one that
    owns removals and the one that owns substitutions.

    The rule those two hold is that a rewrite keeping a value has to keep what producing it did, and
    a replacement expression carries no redirections, so a pass reaching for the tree primitives
    itself writes a rewrite the rule never sees. Three passes did, in three different ways, and each
    left the file a redirection named uncreated. The question this asks is *route* — is there a way
    around the owners — which is the same question `TestRemovalDiscipline` asks about deletions and
    is answered the same way, by reading the source rather than by watching a run.

    Every primitive is searched for by name anywhere in the module, so that reaching one through the
    module object rather than through a `from ... import` is caught too.
    """

    PRIMITIVES = ('_replace_in_parent', 'set_child', 'set_child_list', 'set_body', 'BodyEdit')

    OWNERS = (_RATCHET_OWNER, _SUBSTITUTION_OWNER)

    @classmethod
    def _named_primitives(cls, tree: ast.Module) -> set[str]:
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            elif isinstance(node, ast.alias):
                name = node.name
            else:
                continue
            if name in cls.PRIMITIVES:
                found.add(name)
        return found

    def test_no_ps1_pass_rewrites_the_tree_outside_the_two_owners(self):
        root = _project_root()
        offenders = [
            F'{os.path.relpath(path, root)}: {", ".join(sorted(named))}'
            for path, tree in _sources('refinery', 'lib', 'scripts', 'ps1')
            if not path.endswith(self.OWNERS)
            and (named := self._named_primitives(tree))
        ]
        self.assertListEqual(
            offenders, [], 'use refinery.lib.scripts.ps1.deobfuscation.substitution')


_PLANS = ('Ps1RemovalPlan', 'Ps1RemovalPlans')


def _passes_that_remove() -> set[str]:
    """
    The name of every pass that opens a removal plan, and so of every pass whose deletions have to
    have been tried against the fault veto.
    """
    found = set()
    for path, tree in _sources(_PASSES):
        if path.endswith(_RATCHET_OWNER):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                    continue
                if call.func.id in _PLANS:
                    found.add(node.name)
    return found


def _pass_type(name: str) -> type:
    """
    The class object a pass name denotes. Looked up across the package's modules rather than through
    one import, so a pass that moves between modules is still found; the name comes from
    `_passes_that_remove`, which read the same tree, so an unresolvable one is a bug here.
    """
    package = importlib.import_module(_PASSES.replace(os.sep, '.'))
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(F'{package.__name__}.{module_name}')
        found = getattr(module, name, None)
        if isinstance(found, type):
            return found
    raise AssertionError(F'{name} removes statements but no module in {_PASSES} defines it')


def _pass_types() -> dict[str, type]:
    """
    Every transform the deobfuscation package defines, by name. `_pass_type` answers for one name a
    static scan produced; this answers for all of them, which is what an observer watching who edits
    the tree needs — a pass credited to `<no pass>` is a report nobody can act on.

    A class another one in the set derives from is dropped. Such a base is not a pass, and wrapping
    its `visit` beside its subclass's inherited one wraps the same function twice: the report then
    credits every edit to the base, which owns no rewrite and is the same unactionable answer.
    """
    package = importlib.import_module(_PASSES.replace(os.sep, '.'))
    found = {}
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(F'{package.__name__}.{module_name}')
        for name in dir(module):
            item = getattr(module, name)
            if not isinstance(item, type) or not issubclass(item, scripts.Transformer):
                continue
            if item is not scripts.Transformer:
                found[item.__name__] = item
    return {
        name: item
        for name, item in found.items()
        if not any(other is not item and issubclass(other, item) for other in found.values())
    }


def _deobfuscation_suite() -> unittest.TestSuite:
    names = []
    for path in sorted(glob(os.path.join(_project_root(), _TESTS, 'test_*.py'))):
        stem = os.path.splitext(os.path.basename(path))[0]
        if stem != _EXCLUDED:
            names.append(F"{_TESTS.replace(os.sep, '.')}.{stem}")
    assert names, F'no test modules under {_TESTS}'
    return unittest.defaultTestLoader.loadTestsFromNames(names)


class _Observations(NamedTuple):
    """
    What one watched run of the ps1 deobfuscation suite reports.
    """
    vetoed: frozenset[str]
    parsed: tuple[str, ...]


@functools.lru_cache(maxsize=1)
def _watched_run() -> _Observations:
    """
    Run the ps1 deobfuscation suite once, watching the fault veto and recording every source the
    suite hands to the parser.

    One run rather than two, because the checks below would otherwise each carry their own copy of
    the module glob and the `test_witnessed` exclusion, and a divergence between those copies is how
    one of them starts observing an analysis the other deliberately broke.

    The pass a veto fired for is read off a stack of the `visit` calls in flight rather than from
    the plan, since a plan is told nothing about who built it and this must not become a reason to
    tell it.

    **The two refusals are watched, not the predicates they ask.** A removal is declined either one
    at a time, by `Ps1RemovalPlan._vetoed`, or as a batch that would clear the body, by
    `_empties_a_protected_body` — and which of the two a given pass meets depends on whether it can
    rule the fault out itself. Watching whichever predicate they happened to share was a reading
    that went stale the moment the veto learned to ask a second question: the fault routing, the
    transpose a `trap` needs, and the emptiness policy are three questions now, and a pass credited
    through one of them would have gone uncredited by an observer over another.

    **One refusal `_vetoed` makes is deliberately not credited**: declining to delete a `trap`,
    which is the transpose and involves no `try`, no acting `catch` and no guarded body at all. A
    pass whose only exercise is deleting a load-bearing handler at script scope has never been put
    in front of the shape this ratchet exists to require, and crediting it would report green for
    the same reason the string-matching reading did — a proxy that fires where the thing does not.
    """
    from refinery.lib.scripts.ps1.parser import Ps1Parser
    from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan, _removes_a_handler

    active: list[str] = []
    fired: set[str] = set()
    parsed: list[str] = []
    vetoed = Ps1RemovalPlan._vetoed
    emptied = Ps1RemovalPlan._empties_a_protected_body
    build = Ps1Parser.__init__

    def refusing(refusal, credits=lambda argument: True):
        def refused(self, argument):
            answer = refusal(self, argument)
            if answer and active and credits(argument):
                fired.add(active[-1])
            return answer
        return refused

    def declines_a_faulting_statement(proposal) -> bool:
        return not _removes_a_handler(proposal.statement)

    def recording(self, source, *args, **kwargs):
        if isinstance(source, str):
            parsed.append(source)
        return build(self, source, *args, **kwargs)

    def entered(name: str, visit):
        def visiting(self, node):
            active.append(name)
            try:
                return visit(self, node)
            finally:
                active.pop()
        return visiting

    with ExitStack() as stack:
        stack.enter_context(patch.object(
            Ps1RemovalPlan, '_vetoed', refusing(vetoed, declines_a_faulting_statement)))
        stack.enter_context(
            patch.object(Ps1RemovalPlan, '_empties_a_protected_body', refusing(emptied)))
        stack.enter_context(patch.object(Ps1Parser, '__init__', recording))
        for name in sorted(_passes_that_remove()):
            pass_type = _pass_type(name)
            stack.enter_context(patch.object(pass_type, 'visit', entered(name, pass_type.visit)))
        _deobfuscation_suite().run(unittest.TestResult())
    return _Observations(frozenset(fired), tuple(sorted(set(parsed))))


class TestRemovalIsTriedInsideAProtectedBody(TestBase):
    """
    A removal that empties a `try` body beside an acting handler makes the handler unreachable, and
    every pass answers that question through the same veto. Both bugs this ratchet was written for
    lived in exactly that shape and both survived suites that were otherwise well formed, so the
    shape is required rather than hoped for: what a suite never puts inside a `try` it never checks.

    **A pass is credited by the veto firing, not by its tests looking as though it would.** The
    reading this replaced matched `try` and `catch` against every string constant in a test method,
    which is a proxy for the thing and wrong in both directions: it read a docstring mentioning
    `try`, it accepted a handler holding nothing but `catch { # comment }`, it missed the lowercase
    spellings PowerShell accepts, and it credited a pass for a script that reached the veto with no
    proposal for it to decline. Running the suite with the fault veto under observation asks the
    question directly: which passes actually put a removal in front of it and were told no.
    """

    def test_every_pass_that_removes_is_tried_inside_a_protected_body(self):
        missing = sorted(_passes_that_remove() - _watched_run().vetoed)
        self.assertListEqual(
            missing, [], 'apply each of these to a removal inside try/catch and pin what survives')


class TestNoSubstitutionDropsARedirection(TestBase):
    """
    No pass installs a value-preserving replacement that takes a redirection out of the tree.

    The suite the source ratchets watch never puts a redirection anywhere, so watching it directly
    reports nothing with every one of these bugs present — three of them were, and an observer over
    the tree primitives counted zero. The corpus is therefore built rather than found: every source
    the suite hands to the parser is reissued once per line with a file redirection appended to that
    line, which puts one in front of every rewrite the suite exercises. It grows as the suite does,
    which is the floor a check that only watches has not got.

    Edits made through `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan` are not
    substitutions and are exempt. A removal claims the code does not run — resolving a constant `if`
    deletes the branch that was never taken, redirections and all — and that claim is the plan's to
    check. `refinery.lib.scripts.ps1.deobfuscation.substitution.substitute_statement` opens a plan
    of its own, so the exemption is lifted around it, or the very shape this was written for would
    hide inside the owner meant to enforce it.

    **A redirection is counted lost when the pass has finished and it is still gone**, not at the
    moment it leaves a slot. `Ps1ExpandableStringHoist` takes a subexpression out of a string and
    puts it back one statement later, and telling that apart from a loss by reading the `moved`
    argument the pass declares would be taking the pass's word for the very thing this checks. The
    verdict is deferred to the end of the pass rather than to the end of the run, so a later
    removal cannot be charged to an earlier substitution.

    The redirections are counted by walking the trees here rather than by asking the predicate the
    passes ask, so that a bug in that predicate cannot answer for itself.
    """

    TARGET = ' > C:\\o.txt'

    #: A source longer than this is not reissued line by line. Every deobfuscation pass runs over
    #: every probe, so the corpus is quadratic in the length of what the suite parses, and the few
    #: sources above the bound are whole malware scripts whose individual lines are covered many
    #: times over by the smaller cases.
    LONGEST = 40

    #: A line ending in one of these opens a construct the appended redirection would land inside,
    #: which parses as something else entirely. A line ending in `}` is not one of them: it closes a
    #: scriptblock, and `<pipeline> | %{ ... } > C:\o.txt` is the shape two redirection-dropping
    #: folds took, so excluding it took the corpus's whole reason for existing with it.
    OPENERS = ('{', '(', ',')

    @staticmethod
    def _redirections(part) -> list:
        found = []
        for node in part if isinstance(part, (list, tuple)) else [part]:
            if not isinstance(node, scripts.Node):
                continue
            for descendant in node.walk():
                found.extend(getattr(descendant, 'redirections', None) or ())
        return found

    @classmethod
    def _probes(cls) -> list[str]:
        """
        Only the variants that actually parse to a redirection are kept, so the corpus is measured
        by what it can detect rather than by how many strings were built. A line the appended target
        does not attach to — the parser answers a `Ps1ErrorNode` for a redirection after an
        expression — probes nothing at all, and counting it hides a corpus that has gone blind.
        """
        from refinery.lib.scripts.ps1.parser import Ps1Parser
        probes = set()
        for source in _watched_run().parsed:
            lines = source.splitlines()
            if len(lines) > cls.LONGEST:
                continue
            for index, line in enumerate(lines):
                if not line.strip() or line.rstrip().endswith(cls.OPENERS):
                    continue
                variant = list(lines)
                variant[index] = F'{line}{cls.TARGET}'
                probes.add('\n'.join(variant))
        carrying = []
        for probe in sorted(probes):
            try:
                if cls._redirections(Ps1Parser(probe).parse()):
                    carrying.append(probe)
            except Exception:
                continue
        return carrying

    @classmethod
    def _losses(cls, probes: list[str]) -> list[str]:
        from refinery.lib.scripts.ps1.deobfuscation import deobfuscate, substitution
        from refinery.lib.scripts.ps1.parser import Ps1Parser

        active: list[str] = []
        removing = [0]
        taken: list[tuple[str, object]] = []
        losses: list[str] = []
        source = ['']

        def took(removed, installed) -> None:
            if removing[0]:
                return
            kept = {id(item) for item in cls._redirections(installed)}
            who = active[-1] if active else '<no pass>'
            taken.extend(
                (who, item)
                for item in cls._redirections(removed)
                if id(item) not in kept
            )

        def settle(root) -> None:
            standing = {id(item) for item in cls._redirections(root)}
            losses.extend(
                F'{who}: {source[0]!r}'
                for who, item in taken
                if id(item) not in standing
            )
            taken.clear()

        def installing(original):
            def install(parent, attr, value):
                took(getattr(parent, attr, None), value)
                return original(parent, attr, value)
            return install

        def replacing(original):
            def replace(old, new):
                took(old, new)
                return original(old, new)
            return replace

        def committing(original):
            def commit(plan):
                removing[0] += 1
                try:
                    return original(plan)
                finally:
                    removing[0] -= 1
            return commit

        def substituting(original):
            def substitute(*args, **kwargs):
                removing[0] -= 1
                try:
                    return original(*args, **kwargs)
                finally:
                    removing[0] += 1
            return substitute

        def entered(name: str, visit):
            def visiting(self, node):
                active.append(name)
                try:
                    result = visit(self, node)
                finally:
                    active.pop()
                # Settled on the way out and not in the `finally`, so a pass that raises mid-edit
                # is charged nothing: its tree is half rewritten, every take still open reads as
                # lost, and the report would name `may_substitute` for a crash.
                if not active:
                    settle(node)
                return result
            return visiting

        watched = substituting(substitution.substitute_statement)
        with ExitStack() as stack:
            # Patched per module and not only on `refinery.lib.scripts`, because a `from ... import`
            # binds a name of its own: the owner's two slot entry points call the copy they bound at
            # import time, and a patch on the defining module leaves both of them unobserved.
            for module in (scripts, substitution):
                stack.enter_context(
                    patch.object(module, 'set_child', installing(module.set_child)))
                stack.enter_context(
                    patch.object(module, 'set_child_list', installing(module.set_child_list)))
            for module in (removal, substitution):
                stack.enter_context(patch.object(
                    module, '_replace_in_parent', replacing(module._replace_in_parent)))
            for plans in _PLANS:
                owner = getattr(removal, plans)
                stack.enter_context(
                    patch.object(owner, 'commit', committing(owner.commit)))
            for module in cls._importers('substitute_statement'):
                stack.enter_context(patch.object(module, 'substitute_statement', watched))
            for name, pass_type in sorted(_pass_types().items()):
                stack.enter_context(
                    patch.object(pass_type, 'visit', entered(name, pass_type.visit)))
            for probe in probes:
                source[0] = probe
                try:
                    deobfuscate(Ps1Parser(probe).parse())
                except Exception as error:
                    # A probe that raises is a defect of its own and is reported as one, rather
                    # than skipped: a regression that makes every redirected script throw would
                    # otherwise empty this check without emptying its corpus.
                    losses.append(F'{type(error).__name__}: {probe!r}')
                    taken.clear()
        return losses

    @classmethod
    def _importers(cls, name: str) -> list:
        package = importlib.import_module(_PASSES.replace(os.sep, '.'))
        found = []
        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(F'{package.__name__}.{module_name}')
            if hasattr(module, name):
                found.append(module)
        return found

    def test_no_probe_loses_a_redirection_to_a_substitution(self):
        probes = self._probes()
        self.assertGreater(
            len(probes), 500, 'the probe corpus collapsed; the suite run saw nothing')
        self.assertListEqual(
            sorted(set(self._losses(probes))),
            [],
            'ask substitution.may_substitute before deciding, not after installing')


class TestCacheDiscipline(TestBase):
    """
    A cache decorator on a method keys its entries by the instance, so it keeps every instance it
    has seen, and everything that instance refers to, alive for the life of the process.
    """

    @staticmethod
    def _name(decorator: ast.expr) -> str | None:
        if isinstance(decorator, ast.Call):
            decorator = decorator.func
        if isinstance(decorator, ast.Attribute):
            return decorator.attr
        if isinstance(decorator, ast.Name):
            return decorator.id
        return None

    def test_no_method_is_decorated_with_a_cache(self):
        cached = []
        for path, tree in _sources('refinery'):
            if 'thirdparty' in path:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for method in node.body:
                    if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    names = {self._name(decorator) for decorator in method.decorator_list}
                    if names & {'staticmethod', 'classmethod'}:
                        continue
                    if names & {'cache', 'lru_cache'}:
                        cached.append(F'{os.path.relpath(path, _project_root())}:{method.lineno}')
        self.assertListEqual(cached, [])


class TestPartialReadDiscipline(TestBase):
    """
    A pipeline that is read only partly is suspended inside the code of its units, which refers to
    them, so once it is dropped, only the cycle collector frees its input. Code that reads part of
    a pipeline enters it in a `with` statement, which closes it.
    """

    _CONVERSIONS = {'bytes', 'bytearray', 'str', 'list', 'set', 'dict', 'tuple', 'memoryview', 'int'}
    _READERS = {'next', 'one', 'iter', 'islice', 'any', 'all', 'zip'}
    _STREAM_READERS = {'read', 'read1', 'readline'}

    @classmethod
    def _is_pipeline(cls, node: ast.expr | None) -> bool:
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.BitOr):
            return False
        if isinstance(right := node.right, (ast.Constant, ast.List, ast.Set, ast.Dict)):
            return False
        return not isinstance(right, ast.Name) or right.id not in cls._CONVERSIONS

    @staticmethod
    def _can_stop(loop: ast.For) -> bool:
        return any(isinstance(node, (ast.Break, ast.Return, ast.Raise, ast.Yield, ast.YieldFrom)) for node in ast.walk(loop))

    @classmethod
    def _partial_reads(cls, scope: ast.AST):
        bound: set[str] = set()
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and cls._is_pipeline(node.value):
                bound.update(target.id for target in node.targets if isinstance(target, ast.Name))
            if isinstance(node, (ast.NamedExpr, ast.AnnAssign)) and cls._is_pipeline(node.value):
                if isinstance(node.target, ast.Name):
                    bound.add(node.target.id)

        def is_pipeline(node: ast.expr) -> bool:
            return cls._is_pipeline(node) or isinstance(node, ast.Name) and node.id in bound

        def iterates_pipeline(node: ast.expr) -> bool:
            if isinstance(node, ast.GeneratorExp):
                return any(is_pipeline(generator.iter) for generator in node.generators)
            return is_pipeline(node)

        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Name) and function.id in cls._READERS:
                    if any(iterates_pipeline(arg) for arg in node.args):
                        yield node.lineno
                if isinstance(function, ast.Attribute):
                    if function.attr in cls._READERS and any(iterates_pipeline(arg) for arg in node.args):
                        yield node.lineno
                    if function.attr in cls._STREAM_READERS and is_pipeline(function.value):
                        if function.attr != 'read' or node.args:
                            yield node.lineno
            if isinstance(node, ast.For) and is_pipeline(node.iter) and cls._can_stop(node):
                yield node.lineno

    def test_every_pipeline_that_is_read_partly_is_closed(self):
        unclosed = set()
        for path, tree in _sources('refinery'):
            for line in self._partial_reads(tree):
                unclosed.add(F'{os.path.relpath(path, _project_root())}:{line}')
        self.assertListEqual(sorted(unclosed), [])


class TestCycleDiscipline(TestBase):
    """
    Objects in a reference cycle are freed only by the cycle collector, and so is everything they
    refer to, like the data that a unit was given. Each shape checked here forms such a cycle,
    whatever the rest of the code does. Vendored code is kept as it was published.
    """

    #: Script packages that still contain these shapes. Every name here is work not yet done, not a
    #: package that is exempt on principle.
    UNRATCHETED = ('bat', 'js', 'ps1')

    _CONTAINER_METHODS = {'add', 'append', 'appendleft', 'extend', 'insert', 'put', 'setdefault', 'update'}
    _EXCEPTION_ATTRIBUTES = {'__traceback__', '__context__', '__cause__'}

    @staticmethod
    def _unratcheted_prefix(name: str) -> str:
        return os.path.join('refinery', 'lib', 'scripts', name, '')

    @classmethod
    def _checked_sources(cls) -> list[tuple[str, ast.Module, symtable.SymbolTable]]:
        root = _project_root()
        vendored = os.path.join('refinery', 'lib', 'thirdparty', '')
        sources = []
        for path, tree in _sources('refinery'):
            relative = os.path.relpath(path, root)
            if relative.startswith(vendored):
                continue
            with open(path, 'r', encoding='utf8') as stream:
                table = symtable.symtable(stream.read(), relative, 'exec')
            sources.append((relative, tree, table))
        return sources

    @staticmethod
    def _free_names(table: symtable.SymbolTable) -> set[str]:
        names = {symbol.get_name() for symbol in table.get_symbols() if symbol.is_free()}
        for child in table.get_children():
            names |= TestCycleDiscipline._free_names(child)
        return names

    @staticmethod
    def _lambda_bindings(tree: ast.Module) -> dict[int, str]:
        bindings: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                targets = [node.target]
            else:
                continue
            if isinstance(node.value, ast.Lambda):
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings[node.value.lineno] = target.id
        return bindings

    @classmethod
    def _closure_cycles(cls, table: symtable.SymbolTable, lambdas: dict[int, str]):
        if table.get_type() == 'function':
            nested: dict[str, symtable.SymbolTable] = {}
            for child in table.get_children():
                if child.get_type() not in ('function', 'class'):
                    continue
                if child.get_name() != 'lambda':
                    nested[child.get_name()] = child
                elif (name := lambdas.get(child.get_lineno())) is not None:
                    nested[name] = child
            refers = {name: cls._free_names(child) & nested.keys() for name, child in nested.items()}
            for name, child in nested.items():
                reached: set[str] = set()
                pending = list(refers[name])
                while pending:
                    if (other := pending.pop()) in reached:
                        continue
                    reached.add(other)
                    pending.extend(refers[other])
                if name in reached:
                    yield child.get_lineno()
        for child in table.get_children():
            yield from cls._closure_cycles(child, lambdas)

    @classmethod
    def _carries(cls, node: ast.AST | None, name: str | None) -> bool:
        if isinstance(node, ast.Name):
            return node.id == name
        if isinstance(node, ast.Attribute):
            return node.attr in cls._EXCEPTION_ATTRIBUTES and cls._carries(node.value, name)
        if isinstance(node, ast.Subscript):
            return cls._carries(node.value, name)
        if isinstance(node, ast.Call):
            function = node.func
            return (
                isinstance(function, ast.Attribute)
                and function.attr in ('exc_info', 'exception')
                and isinstance(function.value, ast.Name)
                and function.value.id == 'sys'
            )
        if isinstance(node, ast.BoolOp):
            return any(cls._carries(value, name) for value in node.values)
        if isinstance(node, ast.IfExp):
            return cls._carries(node.body, name) or cls._carries(node.orelse, name)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return any(cls._carries(element, name) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(cls._carries(value, name) for value in node.values)
        if isinstance(node, ast.Starred):
            return cls._carries(node.value, name)
        return False

    @staticmethod
    def _cleared_in_finally(function: ast.AST, handler: ast.ExceptHandler, name: str) -> bool:
        for node in ast.walk(function):
            if not isinstance(node, ast.Try):
                continue
            if not any(
                inner is handler
                for part in (node.body, node.handlers, node.orelse)
                for statement in part
                for inner in ast.walk(statement)
            ):
                continue
            for statement in node.finalbody:
                if isinstance(statement, ast.Delete):
                    targets = statement.targets
                elif isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Constant):
                    targets = statement.targets if statement.value.value is None else []
                else:
                    continue
                if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                    return True
        return False

    @classmethod
    def _kept_exceptions(cls, function: ast.FunctionDef | ast.AsyncFunctionDef):
        for handler in ast.walk(function):
            if not isinstance(handler, ast.ExceptHandler):
                continue
            name = handler.name
            for node in (node for statement in handler.body for node in ast.walk(statement)):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if not cls._carries(node.value, name):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if all(
                        isinstance(target, ast.Name) and (
                            target.id == name or cls._cleared_in_finally(function, handler, target.id))
                        for target in targets
                    ):
                        continue
                    yield node.lineno
                elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                    if cls._carries(node.value, name):
                        yield node.lineno
                elif isinstance(node, ast.Call) and isinstance(method := node.func, ast.Attribute):
                    if method.attr in cls._CONTAINER_METHODS and any(cls._carries(arg, name) for arg in node.args):
                        yield node.lineno

    @staticmethod
    def _raised_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef):
        arguments = function.args
        parameters = {argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
        for node in ast.walk(function):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Name) and node.exc.id in parameters:
                yield node.lineno

    @staticmethod
    def _raised_attributes(tree: ast.Module):
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, (ast.Attribute, ast.Subscript)):
                yield node.lineno

    @staticmethod
    def _functions(tree: ast.Module):
        return (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))

    @classmethod
    @functools.lru_cache(maxsize=None)
    def _all_offenders(cls) -> dict[str, list[str]]:
        offenders: dict[str, set[str]] = {
            'closure cycle': set(),
            'kept exception': set(),
            'raised parameter': set(),
            'raised attribute': set(),
        }
        for path, tree, table in cls._checked_sources():
            found = {
                'closure cycle': cls._closure_cycles(table, cls._lambda_bindings(tree)),
                'kept exception': (line for f in cls._functions(tree) for line in cls._kept_exceptions(f)),
                'raised parameter': (line for f in cls._functions(tree) for line in cls._raised_parameters(f)),
                'raised attribute': cls._raised_attributes(tree),
            }
            for shape, lines in found.items():
                offenders[shape].update(F'{path}:{line}' for line in lines)
        return {shape: sorted(places) for shape, places in offenders.items()}

    def _offenders(self, shape: str) -> list[str]:
        unratcheted = tuple(self._unratcheted_prefix(name) for name in self.UNRATCHETED)
        return [place for place in self._all_offenders()[shape] if not place.startswith(unratcheted)]

    def test_no_function_or_class_defined_in_a_function_refers_to_itself(self):
        self.assertListEqual(self._offenders('closure cycle'), [])

    def test_no_handler_keeps_its_exception(self):
        self.assertListEqual(self._offenders('kept exception'), [])

    def test_no_function_raises_an_exception_it_was_given(self):
        self.assertListEqual(self._offenders('raised parameter'), [])

    def test_no_function_raises_an_exception_kept_in_an_attribute(self):
        self.assertListEqual(self._offenders('raised attribute'), [])

    def test_the_unratcheted_packages_are_still_unratcheted(self):
        places = [place for shape in self._all_offenders().values() for place in shape]
        for name in self.UNRATCHETED:
            if not any(place.startswith(self._unratcheted_prefix(name)) for place in places):
                self.fail(F'{name} no longer needs the exemption; drop it from UNRATCHETED')


class TestStyleGuides(TestUnitBase):

    @pytest.mark.cosmetics
    def test_happy_flakes(self):
        import pyflakes.api
        import pyflakes.reporter
        import io

        python_files = [path for path in glob(
            os.path.join(_project_root(), 'refinery', '**', '*.py'), recursive=True)
            if 'thirdparty' not in path]

        alerts = io.StringIO()
        errors = io.StringIO()

        for path in python_files:
            with open(path, 'r', encoding='utf8') as stream:
                code = stream.read()
            pyflakes.api.check(code, path, pyflakes.reporter.Reporter(alerts, errors))

        error_log = errors.getvalue().strip().splitlines(False)
        alert_log = alerts.getvalue().strip().splitlines(False)

        error_log.extend(line for line in alert_log if not any(
            ignore in line for ignore in [
                ': undefined name',
                ': syntax error in forward annotation',
            ]
        ))

        if error_log:
            print()
        for error in error_log:
            print(error)

        self.assertListEqual(error_log, [])

    @pytest.mark.cosmetics
    def test_style_guide(self):
        import pycodestyle

        class RespectFlake8NoQA(pycodestyle.StandardReport):
            def error(self, lno, offset, text, check):
                for line in self.lines[:5]:
                    _, _, noqa = line.partition('flake8:')
                    if noqa.lstrip().startswith('noqa'):
                        return
                line: str = self.lines[lno - 1]
                _, _, comment = line.partition('#')
                if comment.lower().strip().startswith('noqa'):
                    return
                super().error(lno, offset, text, check)

        stylez = pycodestyle.StyleGuide(
            ignore=[
                'E128',  # A continuation line is under-indented for a visual indentation.
                'E203',  # Colons should not have any space before them.
                'W503',  # Line break occurred before a binary operator
                'E261',  # at least two spaces before inline comment
            ],
            max_line_length=140,
            reporter=RespectFlake8NoQA,
        )

        python_files = [path for path in glob(
            os.path.join(_project_root(), 'refinery', '**', '*.py'), recursive=True)
            if 'thirdparty' not in path]

        for file in python_files:
            with open(file, 'rb') as code_lines:
                for k, line in enumerate(code_lines):
                    self.assertFalse(line.endswith(b'\r\n'), F'CRLF sequence on line {k} in {file}')

        report = stylez.check_files(python_files)
        self.assertEqual(report.total_errors, 0, 'PEP8 formatting errors were found.')
