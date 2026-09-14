"""
Dependency-tree-based deobfuscation scheduler.

Transformers are organized into groups of co-dependent transforms that iterate internally until
stable. Groups form a DAG: a group only runs once all of its declared dependencies are stable. When
any group makes changes, all other groups are marked unstable.
"""
from __future__ import annotations

from refinery.lib.scripts import AnalysisCache, Node, Transformer


class DeobfuscationTimeout(Exception):
    """
    Raised when the pipeline exceeds the maximum number of transformation steps. The exception
    names the group and the transformer whose change exhausted the budget; with an oscillating
    fixpoint that transformer is the one that failed to settle.
    """

    def __init__(self, group: str, transformer: str):
        super().__init__(F'transformer {transformer} in group {group} exceeded the step budget')
        self.group = group
        self.transformer = transformer


class PipelineObserver:
    """
    A hook the scheduler calls around every transformer invocation, so that a property of the tree can
    be read before and after and the pass that changed it can be named. The scheduler knows nothing
    about the property: an observer for a particular language reads whatever that language's meaning
    depends on, and the hook only says when to look and on whose behalf.

    An observer sees a pass that ran and what it left behind. It cannot see a pass that examined
    something and declined, which reports no change and is indistinguishable here from one that found
    nothing to do — a refusal costs recall silently, and naming it needs a channel out of the pass
    itself rather than a hook around it.

    Every `before` is answered exactly once, by `after` when the transformer returns and by `failed`
    when it raises. `after` is not called on the failure path, because a transformer that raises
    leaves the tree half-edited and a reading taken from it would be reported as the pass's result;
    `failed` exists so an observer holding the reading taken in `before`, and through it the tree,
    can drop both rather than keep them for as long as it lives and compare the next pass against
    them. An `Exception` out of `failed` is suppressed, because it runs while the transformer's own
    exception unwinds and would otherwise replace the exception the caller needs. A `BaseException`
    is not, since `KeyboardInterrupt` is the caller asking for the run to end and no exception in
    flight outranks that. Nothing out of `after` is suppressed: the transformer returned, so there
    is no exception to mask, and an observer that cannot read a tree a pass finished with is a
    defect of the observer that the caller has to be shown.
    """

    def before(self, group: str, transformer: type[Transformer], ast: Node) -> None:
        """
        Called with the tree as it stands before *transformer* runs.
        """

    def after(
        self, group: str, transformer: type[Transformer], ast: Node, changed: bool,
    ) -> None:
        """
        Called with the tree as *transformer* left it, and whether it reported a change.
        """

    def failed(self, group: str, transformer: type[Transformer]) -> None:
        """
        Called instead of `after` when *transformer* raised. The tree is not passed, because the
        state it was left in is not the pass's result and must not be read as one.
        """


class TransformerGroup:
    """
    A named set of co-dependent transformers that iterate until stable.
    """

    def __init__(self, name: str, *transformers: type[Transformer]):
        self.name = name
        self.transformers = transformers

    def run(
        self,
        ast: Node,
        steps: int = 0,
        max_steps: int = 0,
        models: AnalysisCache | None = None,
        options: object | None = None,
        observer: PipelineObserver | None = None,
    ) -> tuple[bool, int]:
        """
        Run all transformers in a loop until none report changes. Returns (changed, steps) where
        changed indicates whether any transformation was applied and steps is the updated step
        counter. Each transformer instance shares the *models* cache so it reuses the run's analysis
        models instead of rebuilding them, and invalidates that cache when it changes the tree. The
        *options* value is attached to every transformer so language-specific transforms can read
        caller-supplied settings, and *observer* is called around each one.
        """
        changed = False
        active = set(range(len(self.transformers)))
        while True:
            round_changed = False
            for i, cls in enumerate(self.transformers):
                if i not in active:
                    continue
                t = cls()
                t.models = models
                t.options = options
                if observer is None:
                    t.visit(ast)
                else:
                    observer.before(self.name, cls, ast)
                    try:
                        t.visit(ast)
                    except BaseException:
                        try:
                            observer.failed(self.name, cls)
                        except Exception:
                            pass
                        raise
                    observer.after(self.name, cls, ast, t.changed)
                if t.changed:
                    steps += 1
                    round_changed = True
                    active = set(range(len(self.transformers)))
                    if cls.self_converging:
                        active.discard(i)
                    if max_steps and steps > max_steps:
                        raise DeobfuscationTimeout(self.name, cls.__name__)
                else:
                    active.discard(i)
            if not round_changed:
                break
            changed = True
        return changed, steps


class DeobfuscationPipeline:
    """
    Scheduler that runs transformer groups respecting a dependency DAG.

    Groups are run in declaration order, skipping any whose dependencies are not yet stable. When a
    group makes changes, all other groups are invalidated unless a selective invalidation set is
    configured for that group. The pipeline terminates when every group is stable.

    A selective invalidation set is an optimization over invalidating everything, and it has to
    list every group that transitively depends on the changing group. A set that omits one is
    refused: that group would stay stable and never see the tree the groups it depends on went on
    to change.
    """

    def __init__(
        self,
        groups: list[TransformerGroup],
        dependencies: dict[str, set[str]] | None = None,
        invalidators: dict[str, set[str]] | None = None,
    ):
        self._groups = {g.name: g for g in groups}
        self._pipeline = [g.name for g in groups]
        self._dependencies = dependencies or {}
        self._invalidators = invalidators or {}
        all_names = set(self._pipeline)
        for name, deps in self._dependencies.items():
            if name not in all_names:
                raise ValueError(F'unknown group in dependencies: {name!r}')
            if unknown := deps - all_names:
                raise ValueError(F'group {name!r} depends on unknown groups: {unknown}')
        dependents = self._transitive_dependents()
        for name, targets in self._invalidators.items():
            if name not in all_names:
                raise ValueError(F'unknown group in invalidators: {name!r}')
            if unknown := targets - all_names:
                raise ValueError(F'group {name!r} invalidates unknown groups: {unknown}')
            if missing := dependents[name] - targets:
                raise ValueError(F'group {name!r} does not invalidate {missing}, which depend on it')

    def _transitive_dependents(self) -> dict[str, set[str]]:
        direct: dict[str, set[str]] = {name: set() for name in self._pipeline}
        for name, deps in self._dependencies.items():
            for dep in deps:
                direct[dep].add(name)
        dependents: dict[str, set[str]] = {}
        for name in self._pipeline:
            reached: set[str] = set()
            pending = [name]
            while pending:
                for dependent in direct[pending.pop()]:
                    if dependent not in reached:
                        reached.add(dependent)
                        pending.append(dependent)
            dependents[name] = reached
        return dependents

    def run(
        self,
        ast: Node,
        max_steps: int = 0,
        initial_steps: int = 0,
        models: AnalysisCache | None = None,
        options: object | None = None,
        observer: PipelineObserver | None = None,
    ) -> int:
        """
        Execute the pipeline. Returns the total number of transformer invocations that resulted in a
        change, including `initial_steps` carried over from an earlier phase so that a shared
        `max_steps` budget is enforced across phases. A return value equal to `initial_steps` means
        the pipeline was already stable. When *models* is given, every transformer in the run shares
        that analysis cache. The *options* value is passed through to every transformer, and
        *observer* is called around each one.
        """
        stable: set[str] = set()
        steps = initial_steps
        while True:
            progress = False
            for name in self._pipeline:
                if name in stable:
                    continue
                if (d := self._dependencies.get(name)) and not d <= stable:
                    continue
                group = self._groups[name]
                changed, steps = group.run(ast, steps, max_steps, models, options, observer)
                stable.add(name)
                if changed:
                    targets = self._invalidators.get(name)
                    if targets is None:
                        stable = {name}
                    else:
                        stable -= targets
                    progress = True
                    break
                progress = True
            if not progress:
                break
        return steps
