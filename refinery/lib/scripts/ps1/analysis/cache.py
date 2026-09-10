"""
A per-run cache of the PowerShell analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the model
only after that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter. The version tracking, invalidation, and
transformer-reuse mechanism live in `refinery.lib.scripts.modelcache.ModelCacheBase`; this module
only declares the PowerShell model slot and its `build_*` wiring.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.modelcache import ModelCacheBase
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockModel, build_block_model
from refinery.lib.scripts.ps1.analysis.callgraph import (
    Ps1CallGraph,
    build_call_graph,
    names_used_before_defined,
)
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.commands import Ps1CommandModel, build_command_model
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow, build_variable_flow
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.effects import Ps1OutputFlow, build_output_flow
from refinery.lib.scripts.ps1.analysis.errorstate import (
    Ps1ErrorStateReach,
    build_error_state_reach,
)
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach, build_fault_reach
from refinery.lib.scripts.ps1.analysis.model import Ps1SemanticModel, build_semantic_model
from refinery.lib.scripts.ps1.analysis.world import (
    Ps1TypeWorld,
    Ps1WorldMeasurement,
    measure_world,
)
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach, build_world_reach
from refinery.lib.scripts.ps1.model import Ps1Script


class Ps1ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the analysis models for one root script — the
    `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel`, the
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld`, the
    `refinery.lib.scripts.ps1.analysis.callgraph.Ps1CallGraph`, the
    `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow`, the
    `refinery.lib.scripts.analysis.cfg.ControlFlowModel`, the
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach`, the
    `refinery.lib.scripts.ps1.analysis.blocks.Ps1BlockModel` and the
    `refinery.lib.scripts.analysis.cycles.CycleModel` derived from it — each dropped
    whenever this root's AST-mutation counter advances past the value it was built at.
    """

    _SLOTS = (
        '_model',
        '_world_measurement',
        '_world_reach',
        '_call_graph',
        '_output_flow',
        '_control_flow',
        '_faults',
        '_dominance',
        '_blocks',
        '_cycles',
        '_variable_flow',
        '_commands',
        '_error_state',
        '_used_before_defined',
    )

    root: Ps1Script
    _model: Ps1SemanticModel | None
    _world_measurement: Ps1WorldMeasurement | None
    _world_reach: Ps1WorldReach | None
    _call_graph: Ps1CallGraph | None
    _output_flow: Ps1OutputFlow | None
    _control_flow: ControlFlowModel | None
    _faults: Ps1FaultReach | None
    _dominance: DominatorModel | None
    _blocks: Ps1BlockModel | None
    _cycles: CycleModel | None
    _variable_flow: Ps1VariableFlow | None
    _commands: Ps1CommandModel | None
    _error_state: Ps1ErrorStateReach | None
    _used_before_defined: frozenset[str] | None

    @property
    def model(self) -> Ps1SemanticModel:
        return self._lazy('_model', lambda: build_semantic_model(self.root))

    @property
    def world_measurement(self) -> Ps1WorldMeasurement:
        """
        The one walk that reads whether this script leaves the .NET type system and the command
        table intact, which command names it takes over, and where every world-opening statement
        sits. `closed_world` projects the verdict from it and `world_reach` floods from its openers,
        so the whole-run answer and the positional one are never two different readings of the tree.

        The run's `refinery.lib.scripts.ps1.options.Ps1DeobfuscationOptions` are read from the cache
        because the walk is performed once per cache. A cache made without them — a model built
        standalone in a test — measures the suspecting model, which is the sound answer.
        """
        return self._lazy('_world_measurement', lambda: measure_world(self.root, self.options))

    @property
    def closed_world(self) -> Ps1TypeWorld:
        """
        Whether this script leaves the .NET type system and the command table intact, and which
        command names it takes over. `refinery.lib.scripts.ps1.analysis.effects` takes this as the
        context of every purity verdict, and every verdict in a run must be asked against the same
        one, or two transforms reach opposite conclusions about the same node.
        """
        return self.world_measurement.world

    @property
    def world_reach(self) -> Ps1WorldReach:
        """
        The flow-sensitive reading of `closed_world`: whether the type world is closed, and a
        command name still trustworthy, at one particular node, over `control_flow`. The effect
        layer takes this in place of the leaf world so a member-read grant or a pure-command
        verdict may survive a leak the node provably runs before. Rebuilt with the rest of the
        cache when this root's tree changes, so a transform never reads a position against a stale
        graph. The control-flow model is passed as a thunk so a script that neither opens the
        world nor redefines a command — one with nothing to flood from — never pays to build a
        graph its reach model would not read.
        """
        return self._lazy('_world_reach', lambda: build_world_reach(
            self.world_measurement, lambda: self.control_flow))

    @property
    def call_graph(self) -> Ps1CallGraph:
        """
        Which definitions a command name reaches and which invocations reach it, over this root. The
        `closed_world` is a parameter of the build rather than of the queries because the verdict it
        supplies is one of the reasons the graph declares itself unreadable, and a graph that
        answered that differently per caller would be two graphs.
        """
        return self._lazy(
            '_call_graph',
            lambda: build_call_graph(self.root, self.closed_world, self.options),
        )

    @property
    def output_flow(self) -> Ps1OutputFlow:
        """
        Where each function body's output ends up, joined over the call sites in `call_graph`.
        Every pass that deletes a write to the output stream reads this one, so no two of them can
        disagree about who was going to see the value.
        """
        return self._lazy('_output_flow', lambda: build_output_flow(self.call_graph))

    @property
    def control_flow(self) -> ControlFlowModel:
        """
        One control-flow graph per script block and one for the script itself, over this root — see
        `refinery.lib.scripts.ps1.analysis.cfg.FUNCTION_NODES` for what owns one and why.

        Purely syntactic, so it needs none of the models above and nothing about the order they are
        built in matters. What it answers is the question every pass here has been approximating
        privately: whether one statement runs before another, whether a branch runs at all, and
        whether a handler is still reachable once a body is emptied.
        """
        return self._lazy('_control_flow', lambda: build_control_flow_model(self.root))

    @property
    def faults(self) -> Ps1FaultReach:
        """
        Where a terminating error raised at a point in this root goes, over `control_flow`. The
        single place a pass asks whether deleting something changes which handler runs; answering it
        from a statement's immediate holder alone reads a handler one nesting level away as no
        handler at all.

        It answers off a graph that descends into a `$( )` or `@( )`, so a soft error stepping over
        inside such a construct — and a `trap` written among its statements — is a point in its own
        right rather than detail hidden in the one node the coarse `control_flow` gives the whole
        statement. The reader draws that itself, on demand, from the root the passed model owns, and
        only for a script that writes such a bracket at all: one that writes none has the same graph
        either way, so `control_flow` is reused for it unchanged.

        Purely syntactic like the graphs it reads, so it joins nothing else and orders nothing else.
        """
        return self._lazy('_faults', lambda: build_fault_reach(self.control_flow))

    @property
    def dominance(self) -> DominatorModel:
        """
        Whether one statement of this root is guaranteed to have executed by the time another runs,
        over `control_flow`. The single place that ordering is answered: a pass that needs to know a
        write runs before a read, or that a statement after a `return` cannot be reached, asks here
        rather than reconstructing the relation from the tree.
        """
        return self._lazy('_dominance', lambda: build_dominance(self.control_flow))

    @property
    def blocks(self) -> Ps1BlockModel:
        """
        Where each script block of this root runs — at what point, in whose scope, how many times.
        Reads the whole-run shadow set from `closed_world` so a body handed to a `ForEach-Object` or
        `Where-Object` the script has redefined is placed as data, and is otherwise syntactic like
        `control_flow`. It answers where a block runs, not where it is written.
        """
        return self._lazy('_blocks', lambda: build_block_model(
            self.root, self.closed_world.shadowed_names))

    @property
    def cycles(self) -> CycleModel:
        """
        Which points of this script can be reached more than once, over `control_flow`. A pass that
        establishes a fact from one visit to a statement — a variable's value, a stream's contents —
        asks this before carrying it to a reader, because a point control returns to has no single
        value to carry.

        It is built over `blocks` so that a body run by a cmdlet that enumerates is known to repeat.
        Without that the walk out of a block follows it to where its value was written, and a
        `ForEach-Object` body reads as running exactly once.
        """
        return self._lazy('_cycles', lambda: CycleModel(self.control_flow, self.blocks.body_site))

    @property
    def commands(self) -> Ps1CommandModel:
        """
        What each command invocation of this root denotes — a name, nothing, or unknown — over
        `control_flow` and `dominance`. The one place command identity is answered: a pass that
        rewrites an alias, folds a call to a function, or reads which command a name runs asks here
        rather than splitting the alias relation or ignoring the precedence that makes a default
        alias beat a script function. It reads the script's function names from `call_graph`, the
        layer that already owns which definitions a name denotes, and the wider set of names the
        script takes over from `closed_world`, so the two models agree on what has been shadowed.
        """
        return self._lazy('_commands', lambda: build_command_model(
            self.root, self.control_flow, self.dominance, self.blocks,
            frozenset(self.call_graph.defined_names), self.closed_world.shadowed_names))

    @property
    def error_state(self) -> Ps1ErrorStateReach:
        """
        Where each read of the persistent error record (`$Error`/`$StackTrace`) this root places
        stands, over `commands`, `control_flow` and `dominance`. The removal veto reads this to keep
        a raise whose record a later read observes, the way it reads `output_flow` to keep a write a
        reader observes — a distinct observable channel with its own first-class model rather than a
        scattered whole-script gate. It reads the split read-sites from `commands`, which owns which
        name is the record and which is the success flag, and orders them with `dominance`.
        """
        return self._lazy('_error_state', lambda: build_error_state_reach(
            self.commands.error_state_read_sites(), self.control_flow, self.dominance))

    @property
    def variable_flow(self) -> Ps1VariableFlow:
        """
        Which write each variable read observes, over `model`, `control_flow`, `dominance`, `blocks`
        and `cycles`. The one place that question is answered: a pass that decides what a name holds
        at a point asks here rather than walking the tree for an assignment that looks near enough.
        """
        return self._lazy('_variable_flow', lambda: build_variable_flow(
            self.model, self.control_flow, self.dominance, self.blocks, self.cycles))

    @property
    def used_before_defined(self) -> frozenset[str]:
        """
        The command names some call to which no definition of the name is guaranteed to have run
        before, over `call_graph` and `dominance`. The single place that ordering is asked of the
        call graph: a pass that folds a call into its body or deletes a definition with its calls
        reads this rather than resolving a name whose earlier binding — nothing, at script scope —
        the fold cannot carry. It composes the two models here because
        `refinery.lib.scripts.ps1.analysis.callgraph.names_used_before_defined` needs the ordering
        `dominance` owns, which the deliberately syntactic `call_graph` does not carry.
        """
        return self._lazy('_used_before_defined', lambda: names_used_before_defined(
            self.call_graph, self.dominance))


def model_cache(transformer: Transformer, root: Node) -> Ps1ModelCache:
    """
    The pipeline's shared `Ps1ModelCache` for *root* when one is attached to *transformer* and
    built over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse
    within its single-pass lifetime. See
    `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return Ps1ModelCache.for_transformer(transformer, root)
