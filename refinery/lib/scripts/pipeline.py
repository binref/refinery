"""
Dependency-tree-based deobfuscation scheduler.

Transformers are organized into groups of co-dependent transforms that iterate internally until
stable. Groups form a DAG: a group only runs once all of its declared dependencies are stable. When
any group makes changes, all other groups are marked unstable.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer


class DeobfuscationTimeout(Exception):
    """
    Raised when the pipeline exceeds the maximum number of transformation steps.
    """


class TransformerGroup:
    """
    A named set of co-dependent transformers that iterate until stable.
    """

    def __init__(self, name: str, *transformers: type[Transformer]):
        self.name = name
        self.transformers = transformers

    def run(self, ast: Node, steps: int = 0, max_steps: int = 0) -> tuple[bool, int]:
        """
        Run all transformers in a loop until none report changes. Returns (changed, steps) where
        changed indicates whether any transformation was applied and steps is the updated step
        counter.
        """
        changed = False
        active = set(range(len(self.transformers)))
        while True:
            round_changed = False
            for i, cls in enumerate(self.transformers):
                if i not in active:
                    continue
                t = cls()
                t.visit(ast)
                if t.changed:
                    steps += 1
                    round_changed = True
                    active = set(range(len(self.transformers)))
                    if max_steps and steps > max_steps:
                        raise DeobfuscationTimeout
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
        for name, targets in self._invalidators.items():
            if name not in all_names:
                raise ValueError(F'unknown group in invalidators: {name!r}')
            if unknown := targets - all_names:
                raise ValueError(F'group {name!r} invalidates unknown groups: {unknown}')

    def run(self, ast: Node, max_steps: int = 0) -> int:
        """
        Execute the pipeline. Returns the number of individual transformer invocations that
        resulted in a change. A return value of 0 means the entire pipeline was already stable.
        """
        stable: set[str] = set()
        steps = 0
        while True:
            progress = False
            for name in self._pipeline:
                if name in stable:
                    continue
                if (d := self._dependencies.get(name)) and not d <= stable:
                    continue
                group = self._groups[name]
                changed, steps = group.run(ast, steps, max_steps)
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
