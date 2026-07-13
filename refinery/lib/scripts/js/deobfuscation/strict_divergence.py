"""
Runtime strict-vs-sloppy divergence detection for reflection inlining. The reflection transform inlines
payloads from always-sloppy surfaces (`Function`, indirect `eval`, string timers) into their call site.
When that site runs in strict mode, splicing sloppy-only code there can change behavior, so the inlining
must be declined. Strict *parse* errors are decided by `collect_strict_violations`; this module decides the
complementary question — whether a payload that parses in both modes would *run* differently under strict
mode — and composes both into a single predicate, `diverges_under_strict`.

Soundness is the whole point: the precise gate this feeds inlines a strict subset of what a blunt
strict-context refusal declines, so a false negative here is an unsound inline. Every rule therefore either
decides a divergence class completely or conservatively reports divergence when it cannot. The rules cover
the complete runtime divergence taxonomy for code that parses in both modes:

- R0 a nested direct `eval`, whose bindings leak into the caller scope under sloppy but stay eval-local
  under strict; it also defeats the static scope resolution the other rules rely on.
- R1 any strict parse error (`collect_strict_violations`) — the ultimate divergence, a `SyntaxError`.
- R2 a `this` reference, whose bare-call receiver is the global object under sloppy and `undefined` under
  strict. The reflection caller has already rewritten the payload's own receiver `this` to `globalThis`, so
  every surviving `this` is inside a nested function whose receiver genuinely diverges.
- R3 a write to a name that resolves to no local binding — a sloppy implicit-global creation that throws a
  `ReferenceError` under strict, including a write to a read-only global (`undefined`, `NaN`, `Infinity`).
- R4 a member write or `delete` whose base is not a provably fresh, fully writable container, which may
  target a non-writable or non-configurable property and throw a `TypeError` under strict.
- R5 a block-level function declaration, which sloppy hoists into the enclosing function scope but strict
  scopes to the block.
- R6 a function with a mapped `arguments` object (a simple parameter list), whose element aliases a
  parameter under sloppy but not under strict.
- R7 a `caller`/`callee`/`arguments` poison-pill member read, which throws a `TypeError` under strict.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBlockStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsScript,
    JsStringLiteral,
    JsSwitchCase,
    JsThisExpression,
    strip_parens,
)
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    BindingKind,
    Role,
    SemanticModel,
    is_direct_eval_call,
    is_member_write_target,
    is_use_position,
    reference_role,
)
from refinery.lib.scripts.js.analysis.effects import object_member_access_runs_accessor
from refinery.lib.scripts.js.strict import collect_strict_violations
from refinery.lib.scripts.js.deobfuscation.helpers import walk_receiver_scope

_POISON_PILL_PROPERTIES = frozenset({'caller', 'callee', 'arguments'})


def diverges_under_strict(parsed: JsScript, model: SemanticModel) -> bool:
    """
    Whether the reflected body *parsed* — global sloppy code — would behave differently if it ran in strict
    mode, so that inlining it into a strict context would change meaning. *model* is a `SemanticModel` built
    over *parsed*. Reports divergence conservatively: any construct not provably mode-invariant declines. The
    reflection caller must have already rewritten the payload's own receiver `this` to `globalThis` (R2 sees
    only nested-function `this`).
    """
    return (
        bool(collect_strict_violations(parsed, strict=True))
        or _has_direct_eval(parsed)
        or _references_this(parsed)
        or _writes_free_name(parsed, model)
        or _writes_unsafe_member(parsed)
        or _has_block_function(parsed)
        or _has_mapped_arguments(parsed)
        or _reads_poison_pill(parsed)
    )


def _has_direct_eval(parsed: JsScript) -> bool:
    """
    R0 — whether the body contains a direct `eval` call. Its declarations leak into the caller scope under
    sloppy but stay eval-local under strict, and it can inject or shadow bindings that defeat the static
    scope resolution the write and reference rules depend on.
    """
    return any(is_direct_eval_call(node) for node in parsed.walk())


def _references_this(parsed: JsScript) -> bool:
    """
    R2 — whether the body still references `this`. The payload's own receiver `this` has been rewritten to
    `globalThis` by the caller, so a surviving `this` is inside a nested regular or generator function whose
    bare-call receiver is the global object under sloppy and `undefined` under strict.
    """
    return any(isinstance(node, JsThisExpression) for node in parsed.walk())


def _writes_free_name(parsed: JsScript, model: SemanticModel) -> bool:
    """
    R3 — whether the body assigns to a name that binds to no local declaration. Under sloppy such a write
    creates a global; under strict it throws a `ReferenceError` (or a `TypeError` for a read-only global
    such as `undefined`). A bare read of a free name throws in both modes and does not diverge, so only
    write and read-write references count.
    """
    for node in parsed.walk():
        if not isinstance(node, JsIdentifier) or not model.is_reference(node):
            continue
        if reference_role(node) is Role.READ:
            continue
        binding = model.resolve(node)
        if binding is None or binding.kind is BindingKind.IMPLICIT_GLOBAL:
            return True
    return False


def _writes_unsafe_member(parsed: JsScript) -> bool:
    """
    R4 — whether the body writes or deletes a member whose base is not a provably fresh, fully writable
    container. A write to a non-writable data property, an accessor without a setter, a property of a
    primitive, or a frozen object is a silent no-op under sloppy but a `TypeError` under strict; only a
    fresh array or plain object literal is guaranteed writable.
    """
    for node in parsed.walk():
        if isinstance(node, JsMemberExpression) and is_member_write_target(node):
            if not _fresh_writable_base(node.object):
                return True
    return False


def _fresh_writable_base(base: Node | None) -> bool:
    """
    Whether *base* is an object or array literal whose members are all writable data slots — an array
    literal, or an object literal that declares no accessor and installs no custom prototype (either could
    route a member write through a setter or an inherited non-writable). Every other base — an identifier,
    a member, a call, `this`, a primitive literal, or a function literal (whose `name`/`length` are
    non-writable) — may target a non-writable property and is not provably safe.
    """
    inner = strip_parens(base)
    if isinstance(inner, JsArrayExpression):
        return True
    return isinstance(inner, JsObjectExpression) and not object_member_access_runs_accessor(inner)


def _has_block_function(parsed: JsScript) -> bool:
    """
    R5 — whether the body contains a block-level function declaration, one whose owning statement list is a
    block or a switch case rather than a function body or the script top level. Sloppy Annex-B semantics
    hoist such a name into the enclosing function scope; strict scopes it to the block.
    """
    for node in parsed.walk():
        if not isinstance(node, JsFunctionDeclaration):
            continue
        parent = node.parent
        if isinstance(parent, JsSwitchCase):
            return True
        if isinstance(parent, JsBlockStatement) and not isinstance(parent.parent, FUNCTION_NODES):
            return True
    return False


def _has_mapped_arguments(parsed: JsScript) -> bool:
    """
    R6 — whether the body contains a function with a mapped `arguments` object that it references. A regular
    or generator function with a simple parameter list (all plain identifiers) gets an `arguments` object
    whose elements alias the parameters under sloppy but are an independent copy under strict; a default,
    rest, or destructuring parameter already unmaps it, so those do not diverge.
    """
    for node in parsed.walk():
        if not isinstance(node, (JsFunctionExpression, JsFunctionDeclaration)):
            continue
        if not node.params or not all(isinstance(param, JsIdentifier) for param in node.params):
            continue
        if _references_own_arguments(node):
            return True
    return False


def _references_own_arguments(func: Node) -> bool:
    """
    Whether *func* references its own `arguments` object. The receiver scope is the argument scope: an arrow
    inherits the enclosing `arguments` and is descended, a nested regular or generator function has its own
    and is not, so `walk_receiver_scope` attributes each `arguments` use to the function that owns it.
    """
    return any(
        isinstance(node, JsIdentifier) and node.name == 'arguments' and is_use_position(node)
        for node in walk_receiver_scope(func)
    )


def _reads_poison_pill(parsed: JsScript) -> bool:
    """
    R7 — whether the body reads a `caller`, `callee`, or `arguments` member, a poison-pill accessor that
    throws a `TypeError` under strict. A statically named property (`f.caller`, `f['caller']`) is inspected;
    a fully dynamic computed key is a documented residual left to the surrounding checks.
    """
    for node in parsed.walk():
        if isinstance(node, JsMemberExpression) and _member_name(node) in _POISON_PILL_PROPERTIES:
            return True
    return False


def _member_name(member: JsMemberExpression) -> str | None:
    """
    The statically known property name *member* designates — the identifier of a dot access or the value of
    a string-literal computed access — or `None` for a non-literal computed key.
    """
    prop = member.property
    if member.computed:
        return prop.value if isinstance(prop, JsStringLiteral) else None
    return prop.name if isinstance(prop, JsIdentifier) else None
