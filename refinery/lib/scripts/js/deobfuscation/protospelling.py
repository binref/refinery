"""
Rewrite the spellings that reach an intrinsic prototype without naming it to `Owner.prototype`.

A prototype pollution gadget writes `Object.prototype` through a literal rather than through the
name — `({}).__proto__.z = 9`, `Object.getPrototypeOf({}).z = 9`,
`({}).constructor.prototype.z = 9` — and every one of them means the same object as
`Object.prototype`. Spelling it that way instead is what lets the rest of the pipeline see the
write at all: a write is attributed to the name at the root of the member chain it is written
through, so a chain rooted in a literal is attributed to nothing and every question about that
prototype goes on being answered from a table of what the language puts there.

The rewrite is the same shape as
`refinery.lib.scripts.js.deobfuscation.globalfinder.JsGlobalFinderInlining`, which already rewrites
a call that computes the global object to `globalThis`, and it earns its place the same way twice
over: the file the analyst reads says which object is being patched, and every existing check sees
the write with no new analysis behind it.

The identity is not unconditional and each gate below was established by running Node. It holds
because the mechanism each spelling goes through is the one the language installs, so a file that
replaces that mechanism is asking for something else — `Object.prototype.constructor = C` makes
`({}).constructor.prototype` mean `C.prototype`, and replacing the `__proto__` accessor or
`Object.getPrototypeOf` redirects the other two. Those are asked of the effect model per key,
since asking per name would refuse every file this exists for: a file that writes
`Object.prototype.z` has written `Object`.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Role,
    SemanticModel,
    crosses_dynamic_scope,
    reference_role,
)
from refinery.lib.scripts.js.deobfuscation.helpers import ScriptLevelTransformer, access_key
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsScript,
    JsSpreadElement,
    strip_parens,
)

_PROTO_KEY = '__proto__'

_GET_PROTOTYPE_OF = 'getPrototypeOf'

_CONSTRUCTOR_KEY = 'constructor'


class JsPrototypeSpellingNormalization(ScriptLevelTransformer):
    """
    Replace each expression that reaches an intrinsic prototype through a literal with the
    `Owner.prototype` that names it. See the module documentation for the spellings recognized and
    the gates the identity rests on.
    """

    self_converging = True

    def _process_script(self, node: JsScript) -> None:
        """
        Rewrite every recognized spelling in *node*.

        The models are re-read per rewrite rather than held for the walk, which is the one direction
        the pinning contract in `refinery.lib.scripts.js.analysis.cache.ModelCache.pinned` leaves
        open to a pass whose rewrites make the facts it reads **more** restrictive. Every rewrite
        here attributes a write to a name that had none — `({}).__proto__.constructor = C` becomes
        a write of `constructor` on `Object`, which is exactly what the gate on the next spelling
        asks about — so a held model would answer that gate from a program state its own rewrites
        have already left behind, and clear a rewrite the current facts refuse.

        A candidate an earlier rewrite has taken out of the tree is passed over. Its holder is no
        longer reachable from the script, so replacing it would write into a subtree the output
        does not contain and report a change nothing can observe.
        """
        cache = model_cache(self, node)
        for candidate in list(node.walk()):
            if not candidate.is_descendant_of(node):
                continue
            owner = self._owner_whose_prototype_is_named(candidate, cache.model, cache.effects)
            if owner is None:
                continue
            _replace_in_parent(candidate, _a_prototype_of(owner))
            self.mark_changed()

    def _owner_whose_prototype_is_named(
        self,
        node: Node,
        model: SemanticModel,
        effects: EffectModel,
    ) -> str | None:
        """
        The name of the intrinsic whose `prototype` *node* denotes, or `None` where *node* is not
        one of the recognized spellings or a gate refuses it.

        The identity is one between *values*, so it settles only a spelling read as a value. A
        spelling standing where the language wants a reference — the target of an assignment, the
        operand of a `delete`, the head of a `for-in` — is a different question with a different
        answer: `({}).__proto__ = x` sets the prototype of an object nothing else can reach, while
        `Object.prototype = x` writes a property the language made neither writable nor
        configurable, which a module answers with a `TypeError` and the original answered with
        nothing at all.
        """
        if isinstance(node, JsMemberExpression):
            if reference_role(node) is not Role.READ:
                return None
            key = access_key(node)
            if key == _PROTO_KEY:
                return self._owner_read_through_proto(node, model, effects)
            if key == 'prototype':
                return self._owner_read_through_constructor(node, model, effects)
            return None
        if isinstance(node, JsCallExpression):
            return self._owner_read_through_get_prototype_of(node, model, effects)
        return None

    def _owner_read_through_proto(
        self,
        node: JsMemberExpression,
        model: SemanticModel,
        effects: EffectModel,
    ) -> str | None:
        """
        The owner of `<literal>.__proto__`. The accessor that answers it is installed on
        `Object.prototype` whatever the receiver is, so replacing it there redirects the spelling
        for an array literal as much as for an object one.

        Installing it *closer* redirects the spelling too, and only for that receiver: the key is
        found by an ordinary chain walk, so an own `__proto__` on `Array.prototype` shadows the
        accessor for every array and leaves it answering for everything else. Both names are asked
        because a write to either is one the read goes through.
        """
        owner = _owner_of_literal(node.object, effects)
        if owner is None:
            return None
        if effects.global_key_written('Object', _PROTO_KEY):
            return None
        if effects.global_key_written(owner, _PROTO_KEY):
            return None
        return owner if _names_the_intrinsic(owner, node, model) else None

    def _owner_read_through_constructor(
        self,
        node: JsMemberExpression,
        model: SemanticModel,
        effects: EffectModel,
    ) -> str | None:
        """
        The owner of `<literal>.constructor.prototype`. The `constructor` the receiver inherits is a
        data property of the owner's own prototype, so a file that writes that key is naming its own
        function rather than the intrinsic.
        """
        inner = strip_parens(node.object)
        if not isinstance(inner, JsMemberExpression) or access_key(inner) != _CONSTRUCTOR_KEY:
            return None
        owner = _owner_of_literal(inner.object, effects)
        if owner is None or effects.global_key_written(owner, _CONSTRUCTOR_KEY):
            return None
        return owner if _names_the_intrinsic(owner, node, model) else None

    def _owner_read_through_get_prototype_of(
        self,
        node: JsCallExpression,
        model: SemanticModel,
        effects: EffectModel,
    ) -> str | None:
        """
        The owner of `Object.getPrototypeOf(<literal>)`, where `Object` is the intrinsic and the
        method is the one it was given.
        """
        callee = strip_parens(node.callee)
        if not isinstance(callee, JsMemberExpression) or access_key(callee) != _GET_PROTOTYPE_OF:
            return None
        base = strip_parens(callee.object)
        if not isinstance(base, JsIdentifier) or base.name != 'Object':
            return None
        if len(node.arguments) != 1:
            return None
        owner = _owner_of_literal(node.arguments[0], effects)
        if owner is None or effects.global_key_written('Object', _GET_PROTOTYPE_OF):
            return None
        if not _names_the_intrinsic('Object', node, model):
            return None
        return owner if _names_the_intrinsic(owner, node, model) else None


def _owner_of_literal(node: Node | None, effects: EffectModel) -> str | None:
    """
    The intrinsic whose prototype a literal receiver inherits, or `None` for a receiver whose
    prototype is not knowable from the syntax alone or whose evaluation the rewrite may not drop.

    An array literal always inherits `Array.prototype`: no spelling of one says otherwise, an
    elision included. An object literal is taken only when it is empty, because every way of
    writing a `__proto__` key changes what the receiver answers — written with a colon it sets the
    prototype, and written as a shorthand or a computed key it installs an own property that
    shadows the accessor — and a spread carries one in from a value the syntax does not show.

    The receiver is the one part of the spelling the rewrite does not keep, so the elements have to
    be free of anything the program could miss: `[f()].__proto__` runs `f` and `Array.prototype`
    does not. A spread is refused outright rather than asked, since it iterates its argument and
    `[...null]` is a `TypeError` where the array it would build is not.
    """
    node = strip_parens(node)
    if isinstance(node, JsArrayExpression):
        if any(isinstance(element, JsSpreadElement) for element in node.elements):
            return None
        if any(
            element is not None and not effects.is_side_effect_free(
                element, discarded=True, reads_may_throw=True)
            for element in node.elements
        ):
            return None
        return 'Array'
    if isinstance(node, JsObjectExpression) and not node.properties:
        return 'Object'
    return None


def _names_the_intrinsic(name: str, at: Node, model: SemanticModel) -> bool:
    """
    Whether *name* denotes the intrinsic at *at* rather than something the program can have given a
    meaning of its own. A file declaring `var Object = {prototype: {}}` names its own object with
    it, and rewriting a spelling to `Object.prototype` there would name that one instead of the
    prototype the spelling reaches.

    This is `refinery.lib.scripts.js.deobfuscation.helpers.name_is_unbound` asked of a name that is
    not written anywhere yet, so it cannot be asked through a reference to one. The three ways that
    predicate lists are all asked here: a binding, which `lookup` reports and which is crossed
    deliberately so that a `with` between the two does not hide it; the `with` itself, whose object
    may carry a property of the name and answer the read from it; and a direct `eval`, which
    declares bindings no reference records.
    """
    scope = model.scope_of(at)
    if scope is None:
        return False
    if model.lookup(name, scope, cross_dynamic=True) is not None:
        return False
    if crosses_dynamic_scope(scope):
        return False
    return not model.free_name_reachable_by_direct_eval(at)


def _a_prototype_of(owner: str) -> JsMemberExpression:
    return JsMemberExpression(
        object=JsIdentifier(name=owner),
        property=JsIdentifier(name='prototype'),
        computed=False,
    )
