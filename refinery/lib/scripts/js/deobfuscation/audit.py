"""
Attribute a change of strict mode to the pass that made it.

Which bodies of a program run in strict mode is not something any transform is meant to decide, and
the ways one can decide it by accident are all indirect: a fold writes a string where a directive is
read, a hoist puts a declaration above one, a sweep drops one, a promotion carries a body out of the
region that governed it. Each is a defect of a different pass, and what they have in common is only
visible from outside — the mode of some body is not what it was.

`StrictModeAudit` is that outside view. It reads the mode of every body around every transformer
invocation and reports the bodies that survived the pass and came out running in the other mode.
Surviving is what makes the report an answer rather than a distribution: a pass that removes a strict
function, or inlines one into its call site, changes how many strict bodies a program has and changes
nothing about any body that is still there.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.js.strict import is_prologue_host, strict_mode_at
from refinery.lib.scripts.pipeline import PipelineObserver


class ModeMovement(NamedTuple):
    """
    One transformer invocation after which some body that was already there runs in the other mode.
    """
    group: str
    transformer: str
    became_strict: list[Node]
    became_sloppy: list[Node]

    def __str__(self) -> str:
        return (
            F'{self.group}/{self.transformer}: '
            F'{len(self.became_strict)} bodies became strict, '
            F'{len(self.became_sloppy)} became sloppy'
        )


def mode_of_every_body(root: Node) -> dict[int, tuple[Node, bool]]:
    """
    The mode every body in the tree at *root* runs in, keyed by the identity of the node that holds it.
    The node is kept beside its mode so that it stays alive for as long as the reading does: an
    identity is only a name for as long as nothing else can be given it.

    The mode read is the one the body runs in and not only the one it declares, since a body is strict
    when anything around it is — which is what makes a body carried out of a strict region readable
    here at all.
    """
    return {
        id(node): (node, strict_mode_at(node))
        for node in root.walk()
        if is_prologue_host(node)
    }


class StrictModeAudit(PipelineObserver):
    """
    Records every transformer invocation after which a body that was already in the tree runs in a
    different mode than it did before.

    A body is followed by identity, which holds for as long as a pass edits in place. One that is
    replaced by a copy of itself reads as a body removed and another added, and is not followed; that
    is a gap in what the audit can see and never a false report.

    A pass that examined something and declined to act is not recorded either, because it reports no
    change and leaves no trace in the tree; see `PipelineObserver`.
    """

    def __init__(self):
        self.movements: list[ModeMovement] = []
        self._before: dict[int, tuple[Node, bool]] = {}

    def before(self, group: str, transformer: type[Transformer], ast: Node) -> None:
        self._before = mode_of_every_body(ast)

    def after(
        self, group: str, transformer: type[Transformer], ast: Node, changed: bool,
    ) -> None:
        before, self._before = self._before, {}
        became_strict: list[Node] = []
        became_sloppy: list[Node] = []
        for key, (node, strict) in mode_of_every_body(ast).items():
            was = before.get(key)
            if was is None or was[0] is not node or was[1] == strict:
                continue
            (became_strict if strict else became_sloppy).append(node)
        if became_strict or became_sloppy:
            self.movements.append(
                ModeMovement(group, transformer.__name__, became_strict, became_sloppy))

    def failed(self, group: str, transformer: type[Transformer]) -> None:
        self._before = {}

    def fork(self) -> StrictModeAudit:
        return StrictModeAudit()

    def merge(self, fork: PipelineObserver) -> None:
        if not isinstance(fork, StrictModeAudit):
            raise TypeError(F'a {type(self).__name__} merges only a fork of its own type')
        self.movements.extend(fork.movements)

    def report(self) -> str:
        """
        The recorded movements, one per line, in the order they happened.
        """
        return '\n'.join(str(movement) for movement in self.movements)
