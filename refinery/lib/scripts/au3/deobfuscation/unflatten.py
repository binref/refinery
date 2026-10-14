"""
Control-flow deflattening, degenerate form: a truthy-constant `While` whose body is one state
assignment and one `Switch` over that state splices down to the one case body that ever runs. The
state is re-initialized before every dispatch, so only the case matching the constant can run, and
the terminator gate proves the loop body runs exactly once — everything else in the region is
flattener scaffolding: the dead cases, the state deltas inside them, the wrapper.

Which case runs is the interpreter's rule, not a rederived matcher: cases scan in source order, a
`Case Else` is the live case the moment it is reached — before any later label is consulted — and
a label matches by `=` comparison or by range containment, both through the value tables. The
scan runs on the value the discriminant holds at runtime — the state the init just wrote when the
discriminant is the state variable, the pinned constant when the discriminant is one itself —
because the interpreter dispatches on the discriminant, and two values that compare `=`-equal
can still part ways on a label when one is a string and the other a number. A label the shared
evaluator cannot decide refuses the whole region: the runtime value could match it, so no later
case may be assumed live. The constants themselves are read through the evaluator
`refinery.lib.scripts.au3.analysis.constants`, exactly as the fold reads them, so a disguised
state (`While(821 - 212)`, `Case BitXOR(a, b)`) splices without waiting for a fold to rewrite it.

Keeping the state assignment is always sound — it executes exactly where the `While` stood — so it
leaves only when nothing can read the storage it writes: no occurrence of the name in the live
case body, none outside the region anywhere in the script, none spelled by unread source text —
live source the real AutoIt runs — no string or directive spelling the name, no constant of that
name (dropping a fatal write to a constant would let the script continue where the original
dies), no include anywhere in the script, parsed or unread — an included file is outside every
fact the tree holds and may itself be spliced into the region's own function — and no
computed-name channel that could reach the storage: one in the region's own scope when the write
provably targets a local of it, any channel anywhere when it targets the global or proves
nothing.
Two regions sharing one state name need no pairing machinery — each sees the other's
occurrences and keeps its assignment.

What the splice deletes — the `While` test, the dead cases, the trailing `ExitLoop`, the state
assignment when it leaves — must hold no function declaration, directive, or include, which are
load-bearing at load time or unreachable-shape declarations no runtime proof covers, and no error
text the usage model reads as holding an AutoIt block keyword: that text could shift where the
real parser's block boundaries fall and with it which code is dead at all. Error text without one
can still change how a dead case's statements decompose, but never where a block boundary falls;
whether real AutoIt accepts those statement forms is the parser-recovery phase's question, stated
here rather than paid for on every region the corpus offers.

The live body pays for the splice with its controls. Its last statement must end the loop — an
`ExitLoop` of this loop, which is dropped, or a `Return` or `Exit`, which end everything the
splice could affect and stay as the last statement — and every loop control left in it must pin
its level and spend it inside a loop of the live body itself: anything else would reach or pass
the dispatching `While`, which the splice would silently retarget, and a bare `ContinueLoop` makes
the original an infinite loop the splice would repair. A `ContinueCase` must sit inside a `Switch`
or `Select` of the live body: one that reaches the dispatching `Switch` jumps into a case the
splice deletes.

One sweep per visit, the `refinery.lib.scripts.au3.deobfuscation.eliminate` shape: every
statement list is rebuilt, and a spliced payload is taken through the same sweep, so a region
nested in a live case body leaves in the same pass and dead cases are never descended into. The
sweep holds its model snapshot for the visit — its edits delete statements and hoist live-body
statements between statement positions of one scope — so occurrence sets, spellings, channels,
and constant names only shrink, and every shrink keeps a state assignment that could have left.
The storage question mixes snapshot indices with live positions and can drift between a local and
a none answer, but a region whose assignment may leave has already lost every fact a local answer
is built from — a parameter, a local-forcing declaration, a `For` claim, each an occurrence of the
name outside the region — so its answer is stably the wide one, where any channel anywhere blocks
the drop.
"""
from __future__ import annotations

from collections.abc import Sequence

from refinery.lib.scripts import Node, Statement, Transformer
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.constants import Policy, constant_value
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.usage import Au3UsageModel
from refinery.lib.scripts.au3.analysis.values import Au3Value, compare, to_number, truthy
from refinery.lib.scripts.au3.deobfuscation.helpers import rebuild_nested, rebuild_statements
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3CaseRange,
    Au3ContinueCaseStatement,
    Au3ContinueLoopStatement,
    Au3Directive,
    Au3DoUntilStatement,
    Au3ExitLoopStatement,
    Au3ExitStatement,
    Au3ExpressionStatement,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Include,
    Au3IncludeOnce,
    Au3ReturnStatement,
    Au3Script,
    Au3SelectStatement,
    Au3SwitchCase,
    Au3SwitchStatement,
    Au3Variable,
    Au3WhileStatement,
    Expression,
)

_LOOPS = (Au3WhileStatement, Au3DoUntilStatement, Au3ForStatement, Au3ForInStatement)
_SWITCHES = (Au3SwitchStatement, Au3SelectStatement)


class Au3ControlFlowDeflattening(Transformer):
    """
    Replaces a dispatcher loop — a truthy-constant `While` whose body re-initializes one state and
    switches over it — with the one case body that ever runs, keeping the state assignment
    wherever anything could still read it.
    """

    def __init__(self):
        super().__init__()
        self._scopes: Au3ScopeModel | None = None
        self._usage: Au3UsageModel | None = None
        self._policy = Policy(frozenset())
        self._occurrences: dict[str, list[Au3Variable]] = {}
        self._channel_scopes: frozenset[Au3FunctionDeclaration] = frozenset()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script) and self._holds_a_dispatcher(node):
            self._read_snapshot(node)
            if rebuild_statements(node, 'body', None, self._take):
                self.mark_changed()
        return None

    def _holds_a_dispatcher(self, script: Au3Script) -> bool:
        """
        Whether the script holds any `While` whose body could be a dispatcher — the structural
        prefix of the region match, asked before the model snapshot so that a script with no
        flattening pays one walk instead of the usage model.
        """
        for node in script.walk():
            if (
                isinstance(node, Au3WhileStatement)
                and len(node.body) == 2
                and isinstance(node.body[1], Au3SwitchStatement)
            ):
                return True
        return False

    def _read_snapshot(self, script: Au3Script) -> None:
        cache = model_cache(self, script)
        self._scopes = cache.scopes
        self._usage = cache.usage
        self._policy = Policy(self._scopes.function_names)
        occurrences: dict[str, list[Au3Variable]] = {}
        for node in script.walk():
            if isinstance(node, Au3Variable):
                occurrences.setdefault(node.name, []).append(node)
        self._occurrences = occurrences
        self._channel_scopes = frozenset(filter(None, (
            ast.enclosing_function(channel) for channel in self._usage.channels
        )))

    def _take(
        self,
        statement: Statement,
        scope: Au3FunctionDeclaration | None,
    ) -> list[Statement] | None:
        """
        The statements that replace *statement* — the flattened splice of the region it is, with
        each replacement statement taken the same way, so a region nested in a live case body
        leaves in the same sweep — or `None` when it stands as it is.
        """
        replacement = self._splice(statement)
        if replacement is None:
            return None
        flattened: list[Statement] = []
        for item in replacement:
            nested = self._take(item, scope)
            if nested is None:
                rebuild_nested(item, scope, self._take)
                flattened.append(item)
            else:
                flattened.extend(nested)
        return flattened

    def _splice(self, statement: Statement) -> list[Statement] | None:
        """
        The statements a dispatcher region splices to — the state assignment when it stays, then
        the live case body without its `ExitLoop` terminator — or `None` when the statement is no
        region or a gate refuses it. Every refusal leaves the tree alone.
        """
        assert self._scopes is not None
        assert self._usage is not None
        if not isinstance(statement, Au3WhileStatement):
            return None
        test = constant_value(statement.test, self._policy)
        if test is None or truthy(test) is not True:
            return None
        if len(statement.body) != 2:
            return None
        init_statement = statement.body[0]
        switch = statement.body[1]
        if not isinstance(init_statement, Au3ExpressionStatement):
            return None
        if not isinstance(switch, Au3SwitchStatement):
            return None
        assignment = ast.unwrap_parens(init_statement.expression)
        if not isinstance(assignment, Au3Assignment) or assignment.operator != '=':
            return None
        target = ast.unwrap_parens(assignment.target)
        if not isinstance(target, Au3Variable):
            return None
        state = constant_value(assignment.value, self._policy)
        if state is None:
            return None
        name = target.name
        discriminant = ast.unwrap_parens(switch.discriminant)
        if isinstance(discriminant, Au3Variable):
            if discriminant.name != name:
                return None
            dispatched = state
        else:
            spelled = constant_value(switch.discriminant, self._policy)
            if spelled is None or self._equal_state(state, spelled) is not True:
                return None
            dispatched = spelled
        live = self._live_case(switch.cases, dispatched)
        if live is None:
            return None
        body = live.body
        if not body:
            return None
        terminator = body[-1]
        if isinstance(terminator, Au3ExitLoopStatement):
            if self._loop_level(terminator.level) != 1:
                return None
            tail = body[:-1]
        elif isinstance(terminator, (Au3ReturnStatement, Au3ExitStatement)):
            tail = list(body)
        else:
            return None
        if not self._controls_stay_inside(tail):
            return None
        keeps_init = self._init_is_kept(statement, init_statement, body, name)
        deleted: list[Node | None] = [statement.test, switch.discriminant]
        for case in switch.cases:
            if case is live:
                if case.values is not None:
                    deleted.extend(case.values)
            else:
                deleted.append(case)
        if isinstance(terminator, Au3ExitLoopStatement):
            deleted.append(terminator)
        if not keeps_init:
            deleted.append(init_statement)
        if not self._parts_leave(deleted):
            return None
        replacement = [init_statement] if keeps_init else []
        replacement.extend(tail)
        return replacement

    def _live_case(
        self,
        cases: Sequence[Au3SwitchCase],
        dispatched: Au3Value,
    ) -> Au3SwitchCase | None:
        """
        The one case a dispatcher region ever runs, read with the interpreter's in-order scan over
        *dispatched* — the value the switch dispatches on: a `Case Else` is the live case the
        moment it is reached, and a case with labels is live when one of its labels matches the
        dispatched value. A label that cannot decide refuses the region.
        """
        for case in cases:
            if case.values is None:
                return case
            for label in case.values:
                verdict = self._label_matches(dispatched, label)
                if verdict is None:
                    return None
                if verdict:
                    return case
        return None

    def _label_matches(self, dispatched: Au3Value, label: Node) -> bool | None:
        """
        Whether *label* matches the dispatched value — a single label by `=` comparison, a range by
        containment, both through the value tables — or `None` where the match cannot be decided.
        """
        if isinstance(label, Au3CaseRange):
            low = constant_value(label.start, self._policy)
            high = constant_value(label.end, self._policy)
            if low is None or high is None:
                return None
            within = compare('<=', low, dispatched)
            ending = compare('<=', dispatched, high)
            if within is None or ending is None:
                return None
            return truthy(within) is True and truthy(ending) is True
        value = constant_value(label, self._policy)
        if value is None:
            return None
        return self._equal_state(dispatched, value)

    def _equal_state(self, one: Au3Value, two: Au3Value) -> bool | None:
        """
        Whether two pinned values compare equal the way a label compares with the discriminant, or
        `None` where the value tables refuse the comparison.
        """
        equal = compare('=', one, two)
        if equal is None:
            return None
        return truthy(equal) is True

    def _loop_level(self, level: Expression | None) -> int | None:
        """
        The loop level an `ExitLoop` or `ContinueLoop` holds — `None`, or a value the evaluator
        pins to an int, read as `max(1, n)` the way the interpreter does — or `None` where nothing
        pins the level: the interpreter refuses such a level, so the region refuses with it.
        """
        if level is None:
            return 1
        value = constant_value(level, self._policy)
        if value is None:
            return None
        number = to_number(value)
        if number is None or not isinstance(number, int):
            return None
        return max(1, number)

    def _controls_stay_inside(self, body: Sequence[Statement]) -> bool:
        """
        Whether every loop control of the live body stays inside it, and every `ContinueCase` sits
        inside a `Switch` or `Select` of the live body. A nested function declaration is a scope of
        its own and never descended into.
        """
        return self._controls_walk(body, 0, 0)

    def _controls_walk(self, body: Sequence[Statement], loops: int, switches: int) -> bool:
        for statement in body:
            if isinstance(statement, (Au3ExitLoopStatement, Au3ContinueLoopStatement)):
                level = self._loop_level(statement.level)
                if level is None or level > loops:
                    return False
                continue
            if isinstance(statement, Au3ContinueCaseStatement):
                if switches == 0:
                    return False
                continue
            inner_loops = loops + int(isinstance(statement, _LOOPS))
            inner_switches = switches + int(isinstance(statement, _SWITCHES))
            for owner, nested in ast.statement_lists(statement):
                if not self._controls_walk(getattr(owner, nested), inner_loops, inner_switches):
                    return False
        return True

    def _init_is_kept(
        self,
        loop: Au3WhileStatement,
        init_statement: Au3ExpressionStatement,
        live_body: Sequence[Statement],
        name: str,
    ) -> bool:
        """
        Whether the state assignment stays: always sound, so it leaves only when nothing can read
        the storage it writes — no occurrence of the name in the live case body, where a read would
        see the pre-region value once the assignment is gone, none outside the region anywhere in
        the script, none in unread source text, no string or directive spelling it, no constant of
        that name, and no computed-name channel that could reach the storage — one in the region's
        own scope when the write provably targets a local of it, any channel anywhere when it does
        not — and no include anywhere in the script, parsed or unread, whose file is outside every
        fact the tree holds and may itself be spliced into the region's own function.
        """
        assert self._scopes is not None
        assert self._usage is not None
        if self._scopes.holds_an_include:
            return True
        if self._usage.holds_unread_include():
            return True
        for statement in live_body:
            for node in statement.walk():
                if isinstance(node, Au3Variable) and node.name == name:
                    return True
        for occurrence in self._occurrences.get(name, ()):
            if not occurrence.is_descendant_of(loop):
                return True
        if name in self._usage.unparsed_variables:
            return True
        if self._usage.spells(name):
            return True
        if name in self._scopes.constant_names:
            return True
        scope = ast.enclosing_function(loop)
        binding = self._scopes.binding(scope, init_statement, name)
        if binding is Binding.LOCAL:
            return scope in self._channel_scopes
        return bool(self._usage.channels)

    def _parts_leave(self, roots: Sequence[Node | None]) -> bool:
        """
        Whether everything the splice deletes may leave: no function declaration, directive, or
        include — load-bearing at load time or unreachable-shape declarations no runtime proof
        covers — and no error text the usage model reads as holding an AutoIt block keyword,
        because that text could shift where the real parser's block boundaries fall and with it
        which code is dead at all.
        """
        usage = self._usage
        assert usage is not None
        for root in roots:
            if root is None:
                continue
            if usage.holds_block_keyword_text(root):
                return False
            for node in root.walk():
                if isinstance(node, (
                    Au3FunctionDeclaration,
                    Au3Directive,
                    Au3Include,
                    Au3IncludeOnce,
                )):
                    return False
        return True
