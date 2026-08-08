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

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.modelcache import ModelCacheBase
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockModel, build_block_model
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph, build_call_graph
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.commands import Ps1CommandModel, build_command_model
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow, build_variable_flow
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.effects import Ps1OutputFlow, build_output_flow
from refinery.lib.scripts.ps1.analysis.model import Ps1SemanticModel, build_semantic_model
from refinery.lib.scripts.ps1.analysis.types import TypeOracle
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld, build_closed_world
from refinery.lib.scripts.ps1.model import Ps1Script


class Ps1ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the analysis models for one root script — the
    `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel`, the
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld`, the
    `refinery.lib.scripts.ps1.analysis.callgraph.Ps1CallGraph`, the
    `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow`, the
    `refinery.lib.scripts.analysis.cfg.ControlFlowModel`, the
    `refinery.lib.scripts.ps1.analysis.blocks.Ps1BlockModel` and the
    `refinery.lib.scripts.analysis.cycles.CycleModel` derived from it — each dropped
    whenever this root's AST-mutation counter advances past the value it was built at.
    """

    _SLOTS = (
        '_model',
        '_closed_world',
        '_oracle',
        '_call_graph',
        '_output_flow',
        '_control_flow',
        '_dominance',
        '_blocks',
        '_cycles',
        '_variable_flow',
        '_commands',
    )

    root: Ps1Script
    _model: Ps1SemanticModel | None
    _closed_world: Ps1TypeWorld | None
    _oracle: TypeOracle | None
    _call_graph: Ps1CallGraph | None
    _output_flow: Ps1OutputFlow | None
    _control_flow: ControlFlowModel | None
    _dominance: DominatorModel | None
    _blocks: Ps1BlockModel | None
    _cycles: CycleModel | None
    _variable_flow: Ps1VariableFlow | None
    _commands: Ps1CommandModel | None

    @property
    def model(self) -> Ps1SemanticModel:
        return self._lazy('_model', lambda: build_semantic_model(self.root))

    @property
    def closed_world(self) -> Ps1TypeWorld:
        return self._lazy('_closed_world', lambda: build_closed_world(self.root))

    @property
    def call_graph(self) -> Ps1CallGraph:
        """
        Which definitions a command name reaches and which invocations reach it, over this root. The
        `oracle` is a parameter of the build rather than of the queries because the world verdict it
        supplies is one of the reasons the graph declares itself unreadable, and a graph that
        answered that differently per caller would be two graphs.
        """
        return self._lazy('_call_graph', lambda: build_call_graph(self.root, self.oracle))

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
        Purely syntactic like `control_flow`, and the answer three other layers used to guess from
        the code a block is *written* in.
        """
        return self._lazy('_blocks', lambda: build_block_model(self.root))

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
    def variable_flow(self) -> Ps1VariableFlow:
        """
        Which write each variable read observes, over `model`, `control_flow`, `dominance`, `blocks`
        and `cycles`. The one place that question is answered: a pass that decides what a name holds
        at a point asks here rather than walking the tree for an assignment that looks near enough.
        """
        return self._lazy('_variable_flow', lambda: build_variable_flow(
            self.model, self.control_flow, self.dominance, self.blocks, self.cycles))

    @property
    def oracle(self) -> TypeOracle:
        """
        The effect layer's context for this script, not a model despite the company it keeps in this
        class. `refinery.lib.scripts.ps1.analysis.effects` takes a
        `refinery.lib.scripts.ps1.analysis.types.TypeOracle` as its parameter object, and every
        purity verdict in a run must be asked through the same one, or two transforms reach opposite
        conclusions about the same node. Interprocedural purity later adds a real effect model
        beside this instead of replacing it: that would be a derived fact about the script, where
        this is the lens such facts are read through.

        This is the *base* oracle. Node-local typing — a pipeline item's type, a variable with one
        definition — is layered per call site through
        `refinery.lib.scripts.ps1.analysis.types.TypeOracle.with_variable_types`, so the shared
        instance never forks.
        """
        return self._lazy('_oracle', lambda: TypeOracle(world=self.closed_world))


def model_cache(transformer: Transformer, root: Ps1Script) -> Ps1ModelCache:
    """
    The pipeline's shared `Ps1ModelCache` for *root* when one is attached to *transformer* and
    built over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse
    within its single-pass lifetime. See
    `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return Ps1ModelCache.for_transformer(transformer, root)
