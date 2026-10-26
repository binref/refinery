"""
Undo function flattening. The obfuscation moves the body of a function into a flat function at the
top of the program and leaves the function a wrapper that calls the flat function with its
arguments and with an object whose members stand for every name the body read, wrote or called:

    function flat([value], O) {
      O.total += value;
      return O.c(value);
    }
    function add(...args) {
      var O = {
        get total() { return total; },
        set total(v) { total = v; },
        c(...a) { return twice(...a); },
      };
      return flat(args, O);
    }

A newer form passes the object first, `flat(O, args)`, and in strict code the flat function has no
parameters and unpacks its `arguments` instead:

    var [[value], O] = arguments;

The pass reads the wrapper, the object and the flat function together, writes every access through
the object as the access on the name its member stands for
(`refinery.lib.scripts.js.deobfuscation.nameproxy`), and puts the body back into the wrapper, with
the parameters the flat function unpacked:

    function add(...[value]) {
      total += value;
      return twice(value);
    }

The wrapper keeps its `length` of 0 where something may read it; where nothing can
(`refinery.lib.scripts.js.deobfuscation.parameters.function_length_unobserved`), the parameters
are written `(value)` right away. An async function keeps a function of its own, whose promise
settles when it did, and the flat function moves into the wrapper without the object instead:

    async function delayed(...args) {
      async function flat([value]) { await null; return twice(value); }
      return flat(args);
    }
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    _remove_from_parent,
    _replace_in_parent,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    Scope,
    SemanticModel,
    arguments_aliasing_changes,
    arguments_name_their_function,
    crosses_dynamic_scope,
    is_direct_eval_call,
    references_new_target,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    references_receiver_this,
)
from refinery.lib.scripts.js.deobfuscation.nameproxy import NameProxy
from refinery.lib.scripts.js.deobfuscation.parameters import (
    ParameterList,
    function_length_unobserved,
    parameter_list,
    unpacking_moves_into_parameters,
)
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSpreadElement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
)
from refinery.lib.scripts.js.strict import directive_prologue, strict_mode_at


@dataclass
class _Flattened:
    """
    A wrapper read with its flat function and that function's name: the call between the two, the
    declaration of the object literal, the literal and whether the call passes it first, the array
    pattern the flat function binds the arguments to and its parameter for the object, the
    unpacking of `arguments` that stands for the two in strict code together with its read of
    `arguments`, the statements of the flat body after that unpacking, the scope of the wrapper,
    whether the flat function is nested into the wrapper rather than merged with it, and the
    bindings of the wrapper's scope the flat body does not see there: the object, and where it is
    merged, the rest parameter and the wrapper's own `arguments`.
    """
    wrapper: JsFunctionDeclaration | JsFunctionExpression
    flat: JsFunctionDeclaration
    flat_name: str
    call: JsCallExpression
    declaration: JsVariableDeclaration
    literal: JsObjectExpression
    object_first: bool
    pattern: JsArrayPattern
    parameter: JsIdentifier
    pair: JsArrayPattern | None
    source: JsIdentifier | None
    statements: list[Statement]
    wrapper_scope: Scope
    nested: bool
    removed: list[Binding]


class _Restoration(ABC):
    """
    An edit that puts the body of a function moved out of a wrapper back into the wrapper. The
    function it was moved into, the holder, stays in the body of the program until every edit of
    the pass is made, which then removes all of them at once.
    """

    @property
    @abstractmethod
    def wrapper(self) -> JsFunctionDeclaration | JsFunctionExpression:
        ...

    @property
    @abstractmethod
    def holder(self) -> JsFunctionDeclaration:
        ...

    @abstractmethod
    def apply(self) -> None:
        ...


@dataclass
class _Forwarded(_Restoration):
    """
    A function the obfuscation left a forwarder, `function F() { return G(...arguments); }`, with
    the parameters it takes over from `G`.
    """
    forwarder: JsFunctionDeclaration
    target: JsFunctionDeclaration
    parameters: list[Expression]

    @property
    def wrapper(self) -> JsFunctionDeclaration:
        return self.forwarder

    @property
    def holder(self) -> JsFunctionDeclaration:
        return self.target

    def apply(self) -> None:
        body = self.forwarder.body
        moved = self.target.body
        assert body is not None and moved is not None
        set_child_list(self.forwarder, 'params', self.parameters)
        set_child_list(body, 'body', list(moved.body))


@dataclass
class _Plan(_Restoration):
    """
    The edit decided for one wrapper: each access through the object with the expression that
    takes its place, and how the flat body moves.
    """
    reading: _Flattened
    substitutions: list[tuple[JsMemberExpression, Expression]]

    @property
    def wrapper(self) -> JsFunctionDeclaration | JsFunctionExpression:
        return self.reading.wrapper

    @property
    def holder(self) -> JsFunctionDeclaration:
        return self.reading.flat

    def apply(self) -> None:
        """
        Make the edit. The flat function stays in the body of the program until every plan of the
        pass is made, which then removes all of them at once.
        """
        for member, stand_in in self.substitutions:
            _replace_in_parent(member, stand_in)
        self._move()

    @abstractmethod
    def _move(self) -> None:
        ...


@dataclass
class _Merge(_Plan):
    """
    The flat body becomes the body of the wrapper, whose parameter list becomes *parameters*.
    """
    parameters: ParameterList

    def _move(self) -> None:
        reading = self.reading
        body = reading.wrapper.body
        assert body is not None
        set_child_list(reading.wrapper, 'params', self.parameters.build())
        set_child_list(body, 'body', reading.statements)


@dataclass
class _Nest(_Plan):
    """
    The flat function moves into the wrapper in place of the object, and neither it nor the call
    passes the object any more.
    """

    def _move(self) -> None:
        reading = self.reading
        body = reading.wrapper.body
        assert body is not None
        call = reading.call
        set_child_list(call, 'arguments', [call.arguments[1 if reading.object_first else 0]])
        if reading.pair is not None:
            set_child_list(reading.pair, 'elements', [reading.pattern])
        else:
            set_child_list(reading.flat, 'params', [reading.pattern])
        _remove_from_parent(reading.declaration)
        set_child_list(body, 'body', [reading.flat, *body.body])


def _ancestry(node: Node | None) -> Iterator[Node]:
    while node is not None:
        yield node
        node = node.parent


def _apart(plans: list[_Restoration]) -> list[_Restoration]:
    """
    The plans to make in one pass: each in turn, unless its wrapper or its flat function holds one
    of a plan taken before it or lies inside one. A plan was decided on the tree as it stands, and
    an edit inside what another plan moves or reads waits for the next pass.
    """
    taken: list[_Restoration] = []
    ends: set[int] = set()
    around: set[int] = set()
    for plan in plans:
        own = (plan.wrapper, plan.holder)
        if any(id(end) in around for end in own):
            continue
        if any(id(above) in ends for end in own for above in _ancestry(end)):
            continue
        for end in own:
            ends.add(id(end))
            around.update(id(above) for above in _ancestry(end))
        taken.append(plan)
    return taken


def _moving_function(
    binding: Binding | None,
    callee: JsIdentifier,
    wrapper: JsFunctionDeclaration | JsFunctionExpression,
    root: JsScript,
    model: SemanticModel,
    options: object,
) -> JsFunctionDeclaration | None:
    """
    The function *binding* names, where its body may move into *wrapper* and *callee* is the only
    way to it: a function declared once, at the top of the program, under that name, no generator,
    and async where the wrapper is; nothing writes the name, exports it or reaches it by
    reflection, and no host reaches it; it holds no `with` and no direct `eval`, and runs in the
    mode of the wrapper.
    """
    if binding is None or len(binding.declarations) != 1:
        return None
    name = binding.declarations[0]
    function = name.parent
    if (
        not isinstance(function, JsFunctionDeclaration)
        or function.id is not name
        or function.parent is not root
        or function.generator
        or function.is_async != wrapper.is_async
        or function.body is None
        or wrapper.body is None
    ):
        return None
    if (
        model.references(binding) != [callee]
        or binding.writes
        or binding.dynamic_refs
        or binding.exported
        or model.reflection_can_reach(binding)
        or a_host_reaches_the_binding(model, binding, options)
    ):
        return None
    if strict_mode_at(function.body) != strict_mode_at(wrapper.body):
        return None
    for node in function.walk():
        if is_direct_eval_call(node) or isinstance(node, JsWithStatement):
            return None
    return function


def _wrapper_scope_holds(
    wrapper: JsFunctionDeclaration | JsFunctionExpression,
    wrapper_scope: Scope,
    model: SemanticModel,
    merged: bool,
) -> bool:
    """
    Whether a body moved into *wrapper* finds its names where the text says: no `with` and no direct
    `eval` reach the wrapper's scope. A body *merged* with the wrapper also runs without a frame of
    its own, which only `caller` can tell, so the program spells none (`spells_caller`).
    """
    if crosses_dynamic_scope(wrapper_scope):
        return False
    if model.direct_eval_declares_below(wrapper, model.root_scope):
        return False
    return not merged or not model.spells_caller()


def _names_land(
    moving: JsFunctionDeclaration,
    wrapper_scope: Scope,
    model: SemanticModel,
    removed: list[Binding],
    own: Binding | None = None,
    skipped: JsIdentifier | None = None,
    barred: str | None = None,
) -> bool:
    """
    Whether every name the function *moving* reads and does not declare, but *own* and the read
    *skipped*, finds from inside the wrapper, whose bindings *removed* it no longer sees, the
    binding it finds where it stands; none spells *barred*.
    """
    for node in moving.walk():
        if not isinstance(node, JsIdentifier) or node is skipped or not model.is_reference(node):
            continue
        found = model.resolve(node)
        if found is not None and (found is own or found.declared_within(moving)):
            continue
        if node.name == barred:
            return False
        if model.lookup(node.name, wrapper_scope, exclude=removed) is not found:
            return False
    return True


def _read(
    wrapper: JsFunctionDeclaration | JsFunctionExpression,
    root: JsScript,
    model: SemanticModel,
    options: object,
) -> _Flattened | None:
    """
    The wrapper *wrapper* read with its flat function, or `None` where it is not one. The wrapper
    takes one rest parameter, and its body declares the object and returns the call of the flat
    function with the two, which is the only use of each; the flat function is declared once, at
    the top of the program, and that call is the only way to it. Neither is a generator, and
    both are async or neither is.
    """
    params = wrapper.params
    body = wrapper.body
    if (
        wrapper.generator
        or len(params) != 1
        or not isinstance(rest := params[0], JsRestElement)
        or not isinstance(rest_name := rest.argument, JsIdentifier)
        or body is None
        or len(statements := body.body) != 2
        or not isinstance(declaration := statements[0], JsVariableDeclaration)
        or declaration.kind is not JsVarKind.VAR
        or len(declaration.declarations) != 1
        or not isinstance(declarator := declaration.declarations[0], JsVariableDeclarator)
        or not isinstance(object_name := declarator.id, JsIdentifier)
        or not isinstance(literal := declarator.init, JsObjectExpression)
        or not isinstance(statement := statements[1], JsReturnStatement)
        or not isinstance(call := statement.argument, JsCallExpression)
        or call.optional
        or not isinstance(callee := call.callee, JsIdentifier)
        or len(call.arguments) != 2
    ):
        return None
    first, second = call.arguments
    if not isinstance(first, JsIdentifier) or not isinstance(second, JsIdentifier):
        return None
    rest_binding = model.binding_of(rest_name)
    object_binding = model.binding_of(object_name)
    if rest_binding is None or object_binding is None:
        return None
    if model.resolve(first) is rest_binding and model.resolve(second) is object_binding:
        object_first = False
    elif model.resolve(first) is object_binding and model.resolve(second) is rest_binding:
        object_first = True
    else:
        return None
    passed_object, passed_rest = (first, second) if object_first else (second, first)
    if (
        model.references(rest_binding) != [passed_rest]
        or model.references(object_binding) != [passed_object]
        or rest_binding.declarations != [rest_name]
        or object_binding.declarations != [object_name]
    ):
        return None
    flat = _moving_function(model.resolve(callee), callee, wrapper, root, model, options)
    if flat is None or flat.id is None or flat.body is None:
        return None
    flat_statements = list(flat.body.body)
    pair = None
    source = None
    if flat.params:
        if len(flat.params) != 2:
            return None
        parameter, pattern = flat.params if object_first else reversed(flat.params)
    else:
        rest_of_body = flat_statements[len(directive_prologue(flat.body)):]
        if (
            not rest_of_body
            or not isinstance(unpacking := rest_of_body[0], JsVariableDeclaration)
            or unpacking.kind is not JsVarKind.VAR
            or len(unpacking.declarations) != 1
            or not isinstance(declarator := unpacking.declarations[0], JsVariableDeclarator)
            or not isinstance(pair := declarator.id, JsArrayPattern)
            or not isinstance(source := declarator.init, JsIdentifier)
            or source.name != 'arguments'
            or len(pair.elements) != 2
        ):
            return None
        parameter, pattern = pair.elements if object_first else reversed(pair.elements)
        flat_statements = rest_of_body[1:]
    if not isinstance(pattern, JsArrayPattern) or not isinstance(parameter, JsIdentifier):
        return None
    if (wrapper_scope := model.function_scope(wrapper)) is None:
        return None
    nested = flat.is_async
    removed = [object_binding]
    if not nested:
        removed.append(rest_binding)
        if (own_arguments := wrapper_scope.bindings.get('arguments')) is not None:
            removed.append(own_arguments)
    return _Flattened(
        wrapper=wrapper,
        flat=flat,
        flat_name=flat.id.name,
        call=call,
        declaration=declaration,
        literal=literal,
        object_first=object_first,
        pattern=pattern,
        parameter=parameter,
        pair=pair,
        source=source,
        statements=flat_statements,
        wrapper_scope=wrapper_scope,
        nested=nested,
        removed=removed,
    )


def _lands(
    name: str,
    accessor: JsIdentifier,
    member: Node,
    reading: _Flattened,
    model: SemanticModel,
) -> bool:
    """
    Whether the name *name*, written in place of the access *member*, means what the identifier
    *accessor* in the member of the object means: no binding of the flat function takes it, it is
    not the name of a flat function nested into the wrapper, and from inside the wrapper it finds
    the binding the member finds.
    """
    landed = model.lookup(name, model.scope_of(member))
    if landed is not None and landed.declared_within(reading.flat):
        return False
    if reading.nested and name == reading.flat_name:
        return False
    found = model.lookup(name, reading.wrapper_scope, exclude=reading.removed)
    return found is model.resolve(accessor)


def _call_order_holds(accessor: JsIdentifier, call: JsCallExpression, cache: ModelCache) -> bool:
    """
    Whether calling the name *accessor* names where *call* calls the member standing for it computes
    the same: the member reads the name after the arguments run and the call on the name before
    them, so either the name holds its one value before the call, or no argument can change it.
    """
    target = cache.model.resolve(accessor)
    if (
        target is not None
        and not target.dynamic_refs
        and cache.dominance.binding_established_before(target, call)
    ):
        return True
    return all(
        cache.effects.is_side_effect_free(
            argument,
            None,
            call_established=cache.call_established,
            discarded=True,
            reads_may_throw=True,
            read_established=cache.read_established,
            coercions_may_write=True,
        )
        for argument in call.arguments
    )


def _plan(
    wrapper: JsFunctionDeclaration | JsFunctionExpression,
    root: JsScript,
    cache: ModelCache,
    options: object,
) -> _Plan | None:
    """
    The edit that puts the flat function of *wrapper* back into it, or `None` where the body would
    not compute in the wrapper what it computes where it stands. The flat function runs in the mode
    of the wrapper; it reads no `arguments` but the unpacking of the strict form, and holds no
    `with` and no direct `eval`; no `with` and no direct `eval` reach the wrapper either. A body
    merged with the wrapper reads no `this` and no `new.target`, which the call of the wrapper gives
    it, where a nested flat function is called as it was. Every name the flat function reads that
    it does not declare finds from inside the wrapper the binding it finds where it stands, and none
    is the name of a nested flat function. The object parameter is declared once, and every use of
    it is an access through the object that
    `refinery.lib.scripts.js.deobfuscation.nameproxy.NameProxy.stand_in` writes on a name that
    lands where the member's name is (`_lands`), with no call through a getter, which would pass
    the object as `this`, and with a call through a method only where the order of the name and
    the arguments does not matter (`_call_order_holds`). Where the call passes the arguments first,
    the pattern binds them before the object exists, and an access in the pattern stays. For a
    merge, the unpacking of the strict form has to mean what the parameter list means
    (`refinery.lib.scripts.js.deobfuscation.parameters.unpacking_moves_into_parameters`), and the
    parameter list keeps the `length` of 0 the wrapper has wherever something may read it.
    """
    model = cache.model
    reading = _read(wrapper, root, model, options)
    if reading is None:
        return None
    flat = reading.flat
    proxy = NameProxy.read(reading.literal, model)
    if proxy is None:
        return None
    if not reading.nested and (references_receiver_this(flat) or references_new_target(flat)):
        return None
    for node in walk_receiver_scope(flat):
        if (
            isinstance(node, JsIdentifier)
            and node.name == 'arguments'
            and node is not reading.source
            and model.is_reference(node)
        ):
            return None
    if not _wrapper_scope_holds(wrapper, reading.wrapper_scope, model, merged=not reading.nested):
        return None
    parameter = model.binding_of(reading.parameter)
    if parameter is None or parameter.declarations != [reading.parameter]:
        return None
    if not _names_land(
        flat,
        reading.wrapper_scope,
        model,
        reading.removed,
        own=parameter,
        skipped=reading.source,
        barred=reading.flat_name if reading.nested else None,
    ):
        return None
    substitutions: list[tuple[JsMemberExpression, Expression]] = []
    for reference in model.references(parameter):
        member = reference.parent
        if not isinstance(member, JsMemberExpression) or member.object is not reference:
            return None
        if not reading.object_first and member.is_descendant_of(reading.pattern):
            return None
        stand_in = proxy.stand_in(member)
        if stand_in is None or stand_in.receiver:
            return None
        late = stand_in.late
        if late is not None and not _call_order_holds(stand_in.names[0][1], late, cache):
            return None
        if not all(
            _lands(written.name, accessor, member, reading, model)
            for written, accessor in stand_in.names
        ):
            return None
        substitutions.append((member, stand_in.node))
    if reading.nested:
        return _Nest(reading, substitutions)
    if (
        reading.pair is not None
        and not unpacking_moves_into_parameters(model, reading.pattern, flat, [parameter])
    ):
        return None
    length = None if function_length_unobserved(model, wrapper, options) else 0
    parameters = parameter_list(reading.pattern.elements, wrapper, length)
    if parameters is None:
        return None
    return _Merge(reading, substitutions, parameters)


def _forwarded(
    wrapper: JsFunctionDeclaration | JsFunctionExpression,
    root: JsScript,
    cache: ModelCache,
    options: object,
) -> _Forwarded | None:
    """
    The edit that puts the parameters and the body of `G` back into the forwarder *wrapper*,
    `function F() { return G(...arguments); }`, or `None` where `F` would not compute what it
    computes now. `F` is a plain function declared at the top of the program, and `G` may move into
    it (`_moving_function`, `_wrapper_scope_holds`, `_names_land`). The call hands `G` the arguments
    of `F` and no receiver, so `G` may read its own `arguments` but no `this` and no `new.target`,
    and may not reach itself through `arguments`. The spread runs the iteration of an array, which
    the program must leave as the language has it. `F` takes the parameters of `G` as they are
    where every call of `F` is shown, and otherwise keeps its `length` of 0
    (`refinery.lib.scripts.js.deobfuscation.parameters.parameter_list`), where its `arguments`
    object still aliases the parameters exactly where that of `G` did
    (`refinery.lib.scripts.js.analysis.model.arguments_aliasing_changes`).
    """
    model = cache.model
    body = wrapper.body
    if (
        not isinstance(wrapper, JsFunctionDeclaration)
        or wrapper.parent is not root
        or wrapper.generator
        or wrapper.is_async
        or wrapper.params
        or body is None
    ):
        return None
    statements = body.body[len(directive_prologue(body)):]
    if (
        len(statements) != 1
        or not isinstance(statement := statements[0], JsReturnStatement)
        or not isinstance(call := statement.argument, JsCallExpression)
        or call.optional
        or not isinstance(callee := call.callee, JsIdentifier)
        or len(call.arguments) != 1
        or not isinstance(spread := call.arguments[0], JsSpreadElement)
        or not isinstance(source := spread.argument, JsIdentifier)
        or source.name != 'arguments'
    ):
        return None
    wrapper_scope = model.function_scope(wrapper)
    if wrapper_scope is None:
        return None
    own_arguments = wrapper_scope.bindings.get('arguments')
    if own_arguments is None or model.resolve(source) is not own_arguments:
        return None
    target = _moving_function(model.resolve(callee), callee, wrapper, root, model, options)
    if target is None or target.body is None:
        return None
    if (
        references_receiver_this(target)
        or references_new_target(target)
        or arguments_name_their_function(target)
    ):
        return None
    if not _wrapper_scope_holds(wrapper, wrapper_scope, model, merged=True):
        return None
    if not _names_land(target, wrapper_scope, model, [own_arguments]):
        return None
    if not cache.trust_at(call).chain(list):
        return None
    if function_length_unobserved(model, wrapper, options):
        parameters = list(target.params)
    elif (built := parameter_list(target.params, target, 0)) is not None:
        parameters = built.build()
    else:
        return None
    strict = strict_mode_at(target.body)
    if arguments_aliasing_changes(target, target.params, parameters, strict=strict):
        return None
    return _Forwarded(wrapper, target, parameters)


class JsFunctionUnflattening(ScriptLevelTransformer):
    """
    Put the body of a flattened function back into its wrapper.
    """

    def _process_script(self, node: JsScript) -> None:
        cache = model_cache(self, node)
        plans: list[_Restoration] = []
        with cache.pinned():
            for function in node.walk():
                if not isinstance(function, (JsFunctionDeclaration, JsFunctionExpression)):
                    continue
                plan = _plan(function, node, cache, self.options)
                if plan is None:
                    plan = _forwarded(function, node, cache, self.options)
                if plan is not None:
                    plans.append(plan)
        taken = _apart(plans)
        if not taken:
            return
        for plan in taken:
            plan.apply()
        moved = {id(plan.holder) for plan in taken}
        kept = [statement for statement in node.body if id(statement) not in moved]
        set_child_list(node, 'body', kept)
        self.mark_changed()
