"""
Whether a script-scope `var` behaves as a local of one function, so that its declaration can move
into that function: obfuscators hoist a function's locals to the top of the file, and moving them
back lets every later pass treat them as the locals they are.

A `var` behaves as a local of a function when every run of the function reads only what that run
stored: the function writes it before any read
(`refinery.lib.scripts.js.analysis.liveness.LivenessModel.is_dead_on_entry`), so no value carried
over from load or from an earlier run is read, and it is dead wherever another run of the function
may write it while this one is still under way. Another run starts or resumes only at a point where
the body hands control to other code: a call that may run the function again, and an `await` or a
`yield`, at which the body waits while other code runs. These are the points at which code other
than the body's own statements may change the binding
(`refinery.lib.scripts.js.analysis.reaching.ReachingModel.foreign_kills`), and the `var` must not
be live at any of them (`refinery.lib.scripts.js.analysis.liveness.LivenessModel.live_around`). In

    var x; function f(n) { x = n; if (n) f(n - 1); console.log(x); }

the call `f(n - 1)` writes `x` before the outer run reads it, and `f(2)` prints `0` three times;
with `x` moved into `f`, it prints `0`, `1` and `2`.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.liveness import LivenessModel
from refinery.lib.scripts.js.analysis.model import Binding
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.model import JsIdentifier


def localization_target(
    liveness: LivenessModel,
    reaching: ReachingModel,
    binding: Binding,
) -> Node | None:
    """
    The function into which *binding*, a script-scope `var`, can be soundly relocated, or `None`. A
    binding qualifies when one function's body holds every read of it and every store into it
    (`refinery.lib.scripts.js.analysis.liveness.LivenessModel.pseudo_local_owner`), every run of
    that function reads only what the run stored (see the module documentation), every reference
    spells its name rather than reaching it through an object — a member of a name that may hold
    the global object, `globalThis.x` as much as `G.x` after `var G = this`, would no longer find it
    once it leaves the global object — it is not exported (an importer reads its value where the
    module leaves it, which a body local cannot answer), the program keeps no reflection surface
    that could read it by name, and the program stores no property on the global object under a
    runtime key (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_opaque_global_write`):
    such a write may target the binding's own name, which a relocation would no longer receive.
    """
    model = liveness.model
    if model.has_reflection_surface() or model.has_opaque_global_write():
        return None
    if binding.exported:
        return None
    if not all(isinstance(ref, JsIdentifier) for ref in (*binding.reads, *binding.writes)):
        return None
    function = liveness.pseudo_local_owner(binding)
    if function is None:
        return None
    if not liveness.is_dead_on_entry(binding, function):
        return None
    if not _dead_where_another_run_may_write(liveness, reaching, binding, function):
        return None
    return function


def localizable_bindings(
    liveness: LivenessModel,
    reaching: ReachingModel,
) -> list[tuple[Binding, Node]]:
    """
    Every script-scope `var` binding that can be relocated into a function, each paired with that
    function, in the order the script declares them.
    """
    result: list[tuple[Binding, Node]] = []
    for binding in liveness.model.root_scope.bindings.values():
        function = localization_target(liveness, reaching, binding)
        if function is not None:
            result.append((binding, function))
    return result


def _dead_where_another_run_may_write(
    liveness: LivenessModel,
    reaching: ReachingModel,
    binding: Binding,
    function: Node,
) -> bool:
    """
    Whether *binding* is live at no point of *function*'s body at which code other than the body's
    own statements may write it. The graph does not order the parts of one node, so a binding read
    or live anywhere in the node of such a point counts as live there.
    """
    sites = reaching.foreign_kills(binding, function)
    if sites is None:
        return False
    for site in sites:
        live = liveness.live_around(site)
        if live is None or binding in live:
            return False
    return True
