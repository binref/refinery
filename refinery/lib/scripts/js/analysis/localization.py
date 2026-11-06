"""
Whether a script-scope `var`, or a name no declaration binds, behaves as a local of one function,
so that its declaration can move into that function: obfuscators hoist a function's locals to the
top of the file or leave them undeclared, and moving them back lets every later pass treat them as
the locals they are.

A `var` behaves as a local of a function when every run of the function reads only what that run
stored: the function writes it before any read
(`refinery.lib.scripts.js.analysis.liveness.LivenessModel.is_dead_on_entry`), so no value carried
over from load or from an earlier run is read, and it is dead wherever another run of the function
may write it while this one is still under way. Another run starts or resumes only at a point where
the body hands control to other code: a call that may run the function again, and an `await`, a
`yield`, or a point leaving the body of a `for await` loop, which waits for the iterator to close,
at which the body waits while other code runs. These are the points at which code other than the
body's own statements may change the binding
(`refinery.lib.scripts.js.analysis.reaching.ReachingModel.foreign_kills`), and the `var` must not
be live at any of them (`refinery.lib.scripts.js.analysis.liveness.LivenessModel.live_around`). A
function a run of which may start where no call of its name shows, through the global object, its
own `arguments`, the `caller` of a function it calls, `new.target`, a step of a generator object,
or code outside the file, has no such list of points
(`refinery.lib.scripts.js.analysis.effects.EffectModel.function_escapes`), and its `var` stays. In

    var x; function f(n) { x = n; if (n) f(n - 1); console.log(x); }

the call `f(n - 1)` writes `x` before the outer run reads it, and `f(2)` prints `0` three times;
with `x` moved into `f`, it prints `0`, `1` and `2`.

A `var` at the top of a classic script and a name no declaration binds are properties of the global
object, which code the file does not hold may read or change while the function runs; such a
binding moves only where the file runs no such code
(`refinery.lib.scripts.js.analysis.foreign`). A store into a name no declaration binds creates a
property of the global object only in sloppy code where nothing is installed under the name, and a
`delete` of the name takes that property away again; a store in strict code throws instead.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.liveness import LivenessModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    SemanticModel,
    is_delete_operand,
)
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.model import JsIdentifier


def localization_target(
    liveness: LivenessModel,
    reaching: ReachingModel,
    binding: Binding,
) -> Node | None:
    """
    The function into which *binding*, a script-scope `var` or a name no declaration binds, can be
    soundly relocated, or `None`. A binding qualifies when one function's body holds every read of
    it and every store into it
    (`refinery.lib.scripts.js.analysis.liveness.LivenessModel.pseudo_local_owner`), every run of
    that function reads only what the run stored (see the module documentation), every reference
    spells its name rather than reaching it through an object — a member of a name that may hold
    the global object, `globalThis.x` as much as `G.x` after `var G = this`, would no longer find it
    once it leaves the global object — it is not exported (an importer reads its value where the
    module leaves it, which a body local cannot answer), code outside the file does not reach it by
    name (`refinery.lib.scripts.js.analysis.model.SemanticModel.reached_from_outside`), the program
    keeps no reflection surface that could read it by name, and the program stores no property on
    the global object under a runtime key
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_opaque_global_write`): such a write
    may target the binding's own name, which a relocation would no longer receive. A name no
    declaration binds also needs every store into it to create a property of the global object
    (`_a_store_creates_a_property`), and a property of the global object needs a file that runs no
    code its text does not hold
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.may_run_code_it_does_not_hold`).
    """
    model = liveness.model
    if model.has_reflection_surface() or model.has_opaque_global_write():
        return None
    if binding.exported:
        return None
    if model.reached_from_outside(binding):
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
    effects = reaching.effects
    if binding.kind is BindingKind.IMPLICIT_GLOBAL and not _a_store_creates_a_property(model, effects, binding):
        return None
    if model.reaches_global_object(binding) and effects.may_run_code_it_does_not_hold():
        return None
    return function


def localizable_bindings(
    liveness: LivenessModel,
    reaching: ReachingModel,
) -> list[tuple[Binding, Node]]:
    """
    Every script-scope binding that can be relocated into a function, each paired with that
    function, in the order the script declares or first names them.
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


def _a_store_creates_a_property(model: SemanticModel, effects: EffectModel, binding: Binding) -> bool:
    """
    Whether every store into *binding*, a name no declaration binds, creates a property of the
    global object that a later read in the same run gives back, as a store into a `var` declared
    in the function does: no reference to it may run as strict code, where a store throws a
    `ReferenceError`; none is the operand of a `delete`, which takes the property away again; and
    the program installs nothing under the name
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.installed_under`), which a store would
    run or be refused by. A property the host keeps a value of its own in is refused before
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.kept_by_the_host`).
    """
    if any(
        model.may_run_as_strict(ref) or is_delete_operand(ref)
        for ref in (*binding.reads, *binding.writes)
    ):
        return False
    return not effects.installed_under(binding.name)
