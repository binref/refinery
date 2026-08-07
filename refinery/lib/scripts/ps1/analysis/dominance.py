"""
Dominance over the per-body control-flow graphs of one PowerShell script.

The relation itself is language-neutral and lives in `refinery.lib.scripts.analysis.dominance`; this
module only builds it over the script's cached control-flow model, so that the answer to "does this
statement run before that one" is computed once per run and shared, rather than reconstructed inside
each pass that needs it.

PowerShell uses the shared `refinery.lib.scripts.analysis.dominance.DominatorModel` directly, the way
it uses the shared `refinery.lib.scripts.analysis.cfg.ControlFlowModel` directly, because the
graph-theoretic relation is the same for every language. The interprocedural ordering a later
milestone adds — whether one body runs before another — belongs in the shared layer behind the
callbacks each language supplies, not in a per-language dominance subclass, which is why there is no
`Ps1DominanceModel` here today.
"""
from __future__ import annotations

from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.analysis.dominance import DominatorModel


def build_dominance(control_flow: ControlFlowModel) -> DominatorModel:
    """
    The dominator relations for a script's per-body control-flow graphs, over its cached
    `control_flow` model.
    """
    return DominatorModel(control_flow)
