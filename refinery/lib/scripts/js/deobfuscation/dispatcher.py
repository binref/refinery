"""
The dispatcher obfuscation moves the functions of a program into the table of one routing function
and turns every call into a call of that router: a key names the table entry, two flags say whether
the router empties the payload, calls the entry or hands it out, and the arguments travel in a
payload array the entry unpacks. This transformer reads the router as the template the obfuscation
writes, statement by statement, every name checked through the model to be the binding the template
means:

    function dispatcher(name, flag, returnType, lengths = {...}) {
      var output;
      var table = {key: function () { var [a, b] = payload; ... }, ...};
      if (flag === clearFlag) { payload = []; }
      if (flag === createFlag) {
        function factory() {
          var standIn = function (...args) { payload = args; return table[name].apply(this); };
          var length = lengths[name];
          if (length) { helper(standIn, length); }
          return standIn;
        }
        output = cache[name] || (cache[name] = factory());
      } else {
        output = table[name]();
      }
      if (returnType === wrapFlag) { return { wrapKey: output }; } else { return output; }
    }

Each table entry becomes a function of its own whose parameters are its unpacking, every dispatch
becomes a call of it or a reference to it, and the router goes, with the payload, the cache and the
length helper where nothing else references them. Everything is decided before the first edit.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto
from functools import partial
from typing import TYPE_CHECKING, Callable, NamedTuple, TypeVar

from refinery.lib.scripts import BodyEdit, Node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import (
    enclosing_operator,
    is_direct_eval_call,
    is_invocation_target,
    is_member_write_target,
    references_new_target,
    references_own_arguments,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    access_key,
    fresh_name,
    integer_literal,
    is_valid_identifier,
    make_string_literal,
    make_undefined_expression,
    property_key,
    references_receiver_this,
    remove_declarator,
)
from refinery.lib.scripts.js.deobfuscation.parameters import (
    ParameterList,
    parameter_list,
    unpacking_moves_into_parameters,
)
from refinery.lib.scripts.js.model import (
    Expression,
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsThisExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    is_async_function,
    is_generator_function,
    strip_parens,
    wraps_return,
)

if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.cache import ModelCache
    from refinery.lib.scripts.js.analysis.effects import EffectModel
    from refinery.lib.scripts.js.analysis.model import Binding, Scope, SemanticModel

_N = TypeVar('_N', bound=Node)
_T = TypeVar('_T')


class _Unreadable:
    """
    What a dispatch argument this pass cannot read as a fixed string is reported as, kept apart from
    the `None` an absent argument gives: an argument that is not there is one the dispatcher sees as
    `undefined` and compares unequal to every flag, while one that is there and unreadable may be
    any of them and may run something on the way.
    """


_UNREADABLE = _Unreadable()


def _string_argument(
    call: JsCallExpression | JsNewExpression,
    index: int,
) -> str | None | _Unreadable:
    """
    The string the argument of *call* at *index* certainly evaluates to, `None` where the call has
    no such argument, and `_UNREADABLE` where it has one this pass cannot read as a fixed string.
    """
    if len(call.arguments) <= index:
        return None
    argument = strip_parens(call.arguments[index])
    if isinstance(argument, JsStringLiteral) and argument.value is not None:
        return argument.value
    return _UNREADABLE


class _Role(Enum):
    """
    The part a name plays in the template. The first ten are declared by the template itself; the
    last three are only referenced there and declared by the program around it.
    """
    NAME = auto()
    FLAG = auto()
    RETURN_TYPE = auto()
    LENGTHS = auto()
    OUTPUT = auto()
    TABLE = auto()
    FACTORY = auto()
    STAND_IN = auto()
    ARGUMENTS = auto()
    LENGTH = auto()
    PAYLOAD = auto()
    CACHE = auto()
    HELPER = auto()


_OUTER_ROLES = (_Role.PAYLOAD, _Role.CACHE, _Role.HELPER)


class _NotTheTemplate(Exception):
    """
    Raised where the function `_TemplateReader` reads departs from the template.
    """


def _require(condition: bool) -> None:
    if not condition:
        raise _NotTheTemplate


def _present(value: _T | None) -> _T:
    if value is None:
        raise _NotTheTemplate
    return value


def _as(node: Node | None, kind: type[_N]) -> _N:
    if not isinstance(node, kind):
        raise _NotTheTemplate
    return node


def _plain_body(function: JsFunctionDeclaration | JsFunctionExpression) -> list:
    _require(not wraps_return(function))
    return _as(function.body, JsBlockStatement).body


def _only_statement(statement: Node | None) -> Node:
    block = _as(statement, JsBlockStatement)
    _require(len(block.body) == 1)
    return block.body[0]


def _declarator(statement: Node, *, initialized: bool) -> JsVariableDeclarator:
    declaration = _as(statement, JsVariableDeclaration)
    _require(declaration.kind == JsVarKind.VAR and len(declaration.declarations) == 1)
    declarator = _as(declaration.declarations[0], JsVariableDeclarator)
    _require((declarator.init is not None) is initialized)
    return declarator


def _assignment(statement: Node) -> tuple[Node | None, Node | None]:
    expression = strip_parens(_as(statement, JsExpressionStatement).expression)
    expression = _as(expression, JsAssignmentExpression)
    _require(expression.operator == '=')
    return expression.left, expression.right


def _call(node: Node | None, count: int) -> JsCallExpression:
    call = _as(strip_parens(node), JsCallExpression)
    _require(not call.optional and len(call.arguments) == count)
    return call


def _is_data_property(prop: JsProperty) -> bool:
    return not prop.method and prop.kind == JsPropertyKind.INIT and property_key(prop) is not None


@dataclass
class _Dispatcher:
    """
    A router read as the template: its declaration and binding, its table entries by key, the two
    flags of the second parameter, the flag of the third and the key it wraps the result under, the
    three bindings outside it the template uses, with the template's own references to them, and
    the lengths the default of its fourth parameter records by key.
    """
    declaration: JsFunctionDeclaration
    binding: Binding
    entries: dict[str, JsFunctionExpression]
    clear_flag: str
    create_flag: str
    wrap_flag: str
    wrap_key: str
    payload: Binding
    cache: Binding
    helper: Binding
    template_references: set[Node]
    lengths: dict[str, int]

    def stand_in_length(self, key: str) -> int:
        """
        The `length` of the stand-in the router hands out for *key*: the length recorded for it,
        which the length helper gives the stand-in, and 0 where none is, which the stand-in has.
        """
        return self.lengths.get(key, 0)


class _TemplateReader:
    """
    Reads one function declaration as the template, statement by statement, recording each name
    under the role it plays: where the template declares it and every place it references it. The
    model is asked only once the whole shape has been read, whether each role is one binding and
    no two roles are the same one, so a function that is not the template costs no analysis.
    """

    def __init__(self, function: JsFunctionDeclaration):
        self.function = function
        self.declared: dict[_Role, JsIdentifier] = {}
        self.referenced: dict[_Role, list[JsIdentifier]] = defaultdict(list)
        self.entries: dict[str, JsFunctionExpression] = {}
        self.lengths: dict[str, int] = {}
        body = _plain_body(function)
        self._read_parameters()
        _require(len(body) == 5)
        self._declare(_Role.OUTPUT, _declarator(body[0], initialized=False).id)
        self._read_table(_declarator(body[1], initialized=True))
        self.clear_flag = self._read_clear_branch(body[2])
        self.create_flag = self._read_create_branch(body[3])
        _require(self.clear_flag != self.create_flag)
        self.wrap_flag, self.wrap_key = self._read_wrap_branch(body[4])

    def _declare(self, role: _Role, node: Node | None) -> None:
        self.declared[role] = _as(node, JsIdentifier)

    def _reference(self, role: _Role, node: Node | None) -> None:
        self.referenced[role].append(_as(strip_parens(node), JsIdentifier))

    def _read_comparison(self, test: Node | None, role: _Role) -> str:
        comparison = _as(strip_parens(test), JsBinaryExpression)
        _require(comparison.operator == '===')
        self._reference(role, comparison.left)
        return _present(_as(strip_parens(comparison.right), JsStringLiteral).value)

    def _read_lookup(self, node: Node | None, role: _Role) -> None:
        lookup = _as(strip_parens(node), JsMemberExpression)
        _require(lookup.computed and not lookup.optional)
        self._reference(role, lookup.object)
        self._reference(_Role.NAME, lookup.property)

    def _read_parameters(self) -> None:
        parameters = self.function.params
        _require(len(parameters) == 4)
        self._declare(_Role.NAME, parameters[0])
        self._declare(_Role.FLAG, parameters[1])
        self._declare(_Role.RETURN_TYPE, parameters[2])
        lengths = _as(parameters[3], JsAssignmentPattern)
        self._declare(_Role.LENGTHS, lengths.left)
        for prop in _as(lengths.right, JsObjectExpression).properties:
            prop = _as(prop, JsProperty)
            _require(_is_data_property(prop))
            self.lengths[_present(property_key(prop))] = _present(integer_literal(prop.value))

    def _read_table(self, declarator: JsVariableDeclarator) -> None:
        self._declare(_Role.TABLE, declarator.id)
        table = _as(declarator.init, JsObjectExpression)
        _require(bool(table.properties))
        for prop in table.properties:
            prop = _as(prop, JsProperty)
            _require(_is_data_property(prop) and not prop.shorthand)
            key = _present(property_key(prop))
            _require(key not in self.entries)
            entry = _as(prop.value, JsFunctionExpression)
            _require(not entry.params)
            self.entries[key] = entry

    def _read_clear_branch(self, statement: Node) -> str:
        branch = _as(statement, JsIfStatement)
        _require(branch.alternate is None)
        flag = self._read_comparison(branch.test, _Role.FLAG)
        target, value = _assignment(_only_statement(branch.consequent))
        self._reference(_Role.PAYLOAD, target)
        _require(not _as(value, JsArrayExpression).elements)
        return flag

    def _read_create_branch(self, statement: Node) -> str:
        branch = _as(statement, JsIfStatement)
        flag = self._read_comparison(branch.test, _Role.FLAG)
        block = _as(branch.consequent, JsBlockStatement)
        _require(len(block.body) == 2)
        factory, hand_out = block.body
        self._read_factory(_as(factory, JsFunctionDeclaration))
        target, value = _assignment(hand_out)
        self._reference(_Role.OUTPUT, target)
        cached = _as(strip_parens(value), JsLogicalExpression)
        _require(cached.operator == '||')
        self._read_lookup(cached.left, _Role.CACHE)
        store = _as(strip_parens(cached.right), JsAssignmentExpression)
        _require(store.operator == '=')
        self._read_lookup(store.left, _Role.CACHE)
        self._reference(_Role.FACTORY, _call(store.right, 0).callee)
        target, value = _assignment(_only_statement(branch.alternate))
        self._reference(_Role.OUTPUT, target)
        self._read_lookup(_call(value, 0).callee, _Role.TABLE)
        return flag

    def _read_factory(self, factory: JsFunctionDeclaration) -> None:
        self._declare(_Role.FACTORY, factory.id)
        _require(not factory.params)
        steps = _plain_body(factory)
        _require(len(steps) == 4)
        stand_in = _declarator(steps[0], initialized=True)
        self._declare(_Role.STAND_IN, stand_in.id)
        forward = _as(stand_in.init, JsFunctionExpression)
        _require(forward.id is None and len(forward.params) == 1)
        self._declare(_Role.ARGUMENTS, _as(forward.params[0], JsRestElement).argument)
        forwarding = _plain_body(forward)
        _require(len(forwarding) == 2)
        target, value = _assignment(forwarding[0])
        self._reference(_Role.PAYLOAD, target)
        self._reference(_Role.ARGUMENTS, value)
        apply = _call(_as(forwarding[1], JsReturnStatement).argument, 1)
        _require(isinstance(strip_parens(apply.arguments[0]), JsThisExpression))
        method = _as(strip_parens(apply.callee), JsMemberExpression)
        _require(not method.optional and access_key(method) == 'apply')
        self._read_lookup(method.object, _Role.TABLE)
        length = _declarator(steps[1], initialized=True)
        self._declare(_Role.LENGTH, length.id)
        self._read_lookup(length.init, _Role.LENGTHS)
        setter = _as(steps[2], JsIfStatement)
        _require(setter.alternate is None)
        self._reference(_Role.LENGTH, setter.test)
        helper = _call(_as(_only_statement(setter.consequent), JsExpressionStatement).expression, 2)
        self._reference(_Role.HELPER, helper.callee)
        self._reference(_Role.STAND_IN, helper.arguments[0])
        self._reference(_Role.LENGTH, helper.arguments[1])
        self._reference(_Role.STAND_IN, _as(steps[3], JsReturnStatement).argument)

    def _read_wrap_branch(self, statement: Node) -> tuple[str, str]:
        branch = _as(statement, JsIfStatement)
        flag = self._read_comparison(branch.test, _Role.RETURN_TYPE)
        wrapped = _as(_only_statement(branch.consequent), JsReturnStatement)
        wrapper = _as(strip_parens(wrapped.argument), JsObjectExpression)
        _require(len(wrapper.properties) == 1)
        prop = _as(wrapper.properties[0], JsProperty)
        _require(_is_data_property(prop))
        self._reference(_Role.OUTPUT, prop.value)
        plain = _as(_only_statement(branch.alternate), JsReturnStatement)
        self._reference(_Role.OUTPUT, plain.argument)
        return flag, _present(property_key(prop))

    def dispatcher(self, model: SemanticModel) -> _Dispatcher:
        """
        The router this reader read, once the model says every role is the one binding the template
        means: every reference the template writes for a name it declares resolves to that
        declaration, each name it only references is one binding declared outside the router, the
        router's name is declared by the router alone, and no two roles, nor any role and the
        router, are the same binding.
        """
        bindings: dict[_Role, Binding] = {}
        for role, declaration in self.declared.items():
            binding = bindings[role] = _present(model.binding_of(declaration))
            references = self.referenced[role]
            _require(all(model.resolve(reference) is binding for reference in references))
        for role in _OUTER_ROLES:
            first, *others = self.referenced[role]
            binding = bindings[role] = _present(model.resolve(first))
            _require(all(model.resolve(reference) is binding for reference in others))
            _require(not binding.declared_within(self.function))
            _require(not binding.supplied_by_host)
        own = _present(model.binding_of(_as(self.function.id, JsIdentifier)))
        _require(len(own.declarations) == 1)
        names = _present(model.function_names(self.function))
        _require(names.bindings == (own,))
        _require(len({own, *bindings.values()}) == len(bindings) + 1)
        return _Dispatcher(
            declaration=self.function,
            binding=own,
            entries=self.entries,
            clear_flag=self.clear_flag,
            create_flag=self.create_flag,
            wrap_flag=self.wrap_flag,
            wrap_key=self.wrap_key,
            payload=bindings[_Role.PAYLOAD],
            cache=bindings[_Role.CACHE],
            helper=bindings[_Role.HELPER],
            template_references={
                reference for role in _OUTER_ROLES for reference in self.referenced[role]
            },
            lengths=self.lengths,
        )


class _Unpacking(NamedTuple):
    """
    The unpacking an entry begins with: its array pattern and its read of the payload.
    """
    pattern: JsArrayPattern
    source: JsIdentifier


@dataclass
class _Entry:
    """
    A table entry that can move out of the router: the function and, where its first statement
    unpacks the payload, that unpacking, which becomes its parameter list.
    """
    function: JsFunctionExpression
    unpacking: _Unpacking | None

    def parameters(self, length: int | None) -> ParameterList | None:
        """
        The parameter list of the recovered function with the `length` *length*, any where it is
        `None`, or `None` where no list of that length binds what the unpacking binds.
        """
        elements = [] if self.unpacking is None else self.unpacking.pattern.elements
        return parameter_list(elements, self.function, length)

    def recovered(self, name: str, parameters: ParameterList) -> JsFunctionDeclaration:
        body = self.function.body
        assert body is not None
        statements = list(body.body)
        if self.unpacking is not None:
            statements = statements[1:]
        return JsFunctionDeclaration(
            id=JsIdentifier(name=name),
            params=parameters.build(),
            body=JsBlockStatement(body=statements),
            generator=is_generator_function(self.function),
            is_async=is_async_function(self.function),
        )


def _read_unpacking(statements: list, payload: Binding, model: SemanticModel) -> _Unpacking | None:
    """
    The unpacking *statements* begin with: a `var` of one array pattern initialized by the payload.
    """
    if not statements:
        return None
    first = statements[0]
    if (
        not isinstance(first, JsVariableDeclaration)
        or first.kind != JsVarKind.VAR
        or len(first.declarations) != 1
    ):
        return None
    declarator = first.declarations[0]
    if (
        not isinstance(declarator, JsVariableDeclarator)
        or not isinstance(pattern := declarator.id, JsArrayPattern)
        or not isinstance(source := declarator.init, JsIdentifier)
        or model.resolve(source) is not payload
    ):
        return None
    return _Unpacking(pattern, source)


def _read_entry(
    function: JsFunctionExpression,
    dispatcher: _Dispatcher,
    model: SemanticModel,
) -> _Entry | None:
    """
    The table entry *function* as one that can move out of the router, or `None` where moving it
    could change what it computes. An entry that moves keeps its body but is called by its own
    name, outside the router, with its unpacking as parameters, so it must not tell any of that:
    it reads no `this`, no own `arguments`, no `new.target`, no direct `eval`, and no name the
    router declares. Its unpacking means what a parameter list means
    (`refinery.lib.scripts.js.deobfuscation.parameters.unpacking_moves_into_parameters`).
    """
    body = function.body
    if function.id is not None or not isinstance(body, JsBlockStatement):
        return None
    unpacking = _read_unpacking(body.body, dispatcher.payload, model)
    if unpacking is not None and not unpacking_moves_into_parameters(model, unpacking.pattern, function):
        return None
    if (
        references_receiver_this(function)
        or references_own_arguments(function)
        or references_new_target(function)
    ):
        return None
    for node in function.walk():
        if is_direct_eval_call(node):
            return None
        if not isinstance(node, JsIdentifier) or not model.is_reference(node):
            continue
        binding = model.lookup(node.name, model.scope_of(node), cross_dynamic=True)
        if (
            binding is not None
            and binding.declared_within(dispatcher.declaration)
            and not binding.declared_within(function)
        ):
            return None
    return _Entry(function, unpacking)


@dataclass
class _Dispatch:
    """
    One dispatch read: the expression it replaces, the reference to the router it consumes, and the
    key it selects. It denotes the selected function where *arguments* is `None` and a call of it
    with *arguments* otherwise; *payload* is the payload reference of the assignment in front that
    the replacement takes away. A call whose result is called as a method of the wrapper keeps the
    wrapper around it under *receiver*, which is the receiver that call sees.
    """
    node: Node
    reference: JsIdentifier
    key: str
    arguments: list[Expression] | None
    payload: JsIdentifier | None = None
    receiver: str | None = None

    def replacement(self, name: str) -> Expression:
        if self.arguments is None:
            return JsIdentifier(name=name)
        call = JsCallExpression(callee=JsIdentifier(name=name), arguments=self.arguments)
        if self.receiver is None:
            return call
        return JsMemberExpression(
            object=JsObjectExpression(properties=[
                JsProperty(key=make_string_literal(self.receiver), value=call)
            ]),
            property=make_string_literal(self.receiver),
            computed=True,
        )


class _PayloadInFront(NamedTuple):
    """
    An assignment of an array to the payload paired with the dispatch after it: the pair itself, the
    payload reference it assigns, and the elements it assigns.
    """
    pair: JsSequenceExpression
    target: JsIdentifier
    elements: list[Expression | None]


def _payload_in_front(
    expression: Node,
    payload: Binding,
    model: SemanticModel,
) -> _PayloadInFront | None:
    """
    The assignment of an array to the payload that *expression* follows in a pair, or `None` where
    it follows none.
    """
    pair = enclosing_operator(expression)
    if (
        not isinstance(pair, JsSequenceExpression)
        or len(pair.expressions) != 2
        or strip_parens(pair.expressions[1]) is not expression
    ):
        return None
    store = pair.expressions[0]
    if (
        isinstance(store, JsAssignmentExpression)
        and store.operator == '='
        and isinstance(target := store.left, JsIdentifier)
        and model.resolve(target) is payload
        and isinstance(elements := store.right, JsArrayExpression)
    ):
        return _PayloadInFront(pair, target, elements.elements)
    return None


def _reached_only_through(
    model: SemanticModel,
    binding: Binding,
    accounted: set[Node],
) -> bool:
    """
    Whether *binding* is not exported, every reference to it is one of *accounted*, and no lookup by
    name at runtime can reach it.
    """
    if binding.exported:
        return False
    if not all(reference in accounted for reference in model.references(binding)):
        return False
    return not model.reflection_can_reach(binding)


def _name_base(key: str) -> str:
    for name in (key, F'_{key}'):
        if is_valid_identifier(name):
            return name
    return 'f'


def _choose_names(
    model: SemanticModel,
    scope: Scope,
    dispatcher: _Dispatcher,
    dispatches: list[_Dispatch],
) -> dict[str, str]:
    """
    The name each recovered function is declared with in *scope*, by key. A key that is a valid
    name is its own, otherwise it is prefixed with an underscore, otherwise it is `f`, and a
    numbered suffix is added until the name is free: no other recovered function takes it, no
    binding of *scope* other than the router has it, declaring it would capture no use within
    *scope*, and no dispatch rewritten to it sees a nearer binding of it. A key read off the global
    object as a string is not considered, since the obfuscation makes up its keys at random.
    """
    exclude = (dispatcher.binding,)
    bases = {key: _name_base(key) for key in dispatcher.entries}
    captured = model.captured_names(set(bases.values()), scope, exclude=exclude)
    capturing = {name: name in captured for name in bases.values()}
    sites: dict[str, list[_Dispatch]] = defaultdict(list)
    for dispatch in dispatches:
        sites[dispatch.key].append(dispatch)
    chosen: dict[str, str] = {}
    used: set[str] = set()

    def taken(name: str, key: str) -> bool:
        if name in used:
            return True
        bound = scope.bindings.get(name)
        if bound is not None and bound is not dispatcher.binding:
            return True
        if name not in capturing:
            capturing[name] = model.would_capture({name}, scope, exclude=exclude)
        if capturing[name]:
            return True
        return any(model.is_shadowed(name, site.reference, scope) for site in sites[key])

    for key, base in bases.items():
        name = chosen[key] = fresh_name(base, partial(taken, key=key))
        used.add(name)
    return chosen


def _removable_declarators(
    cache: ModelCache,
    binding: Binding,
    template_initializer: Callable[[Node], bool] | None = None,
) -> list[JsVariableDeclarator]:
    """
    The `var` declarators of *binding* that can go once nothing references it: those without an
    initializer, those whose initializer runs nothing, and those the template writes.
    """
    removable: list[JsVariableDeclarator] = []
    for declaration in binding.declarations:
        declarator = declaration.parent
        if not isinstance(declarator, JsVariableDeclarator) or declarator.id is not declaration:
            continue
        statement = declarator.parent
        if not isinstance(statement, JsVariableDeclaration) or statement.kind != JsVarKind.VAR:
            continue
        initializer = declarator.init
        if (
            initializer is None
            or template_initializer is not None and template_initializer(initializer)
            or cache.effects.is_side_effect_free(
                initializer,
                discarded=True,
                reads_may_throw=True,
                read_established=cache.read_established,
            )
        ):
            removable.append(declarator)
    return removable


def _is_object_create_null(node: Node, effects: EffectModel) -> bool:
    """
    Check if *node* is `Object.create(null)` of a program that neither binds `Object` nor writes its
    `create`, so that the call runs nothing.
    """
    if not isinstance(node, JsCallExpression):
        return False
    if len(node.arguments) != 1 or not isinstance(node.arguments[0], JsNullLiteral):
        return False
    callee = node.callee
    if not isinstance(callee, JsMemberExpression):
        return False
    if not isinstance(callee.object, JsIdentifier) or callee.object.name != 'Object':
        return False
    if access_key(callee) != 'create':
        return False
    return not effects.global_key_written('Object', 'create')


def _depth(node: Node) -> int:
    depth = 0
    cursor: Node | None = node
    while cursor is not None:
        depth += 1
        cursor = cursor.parent
    return depth


def _a_hole_reads_undefined(cache: ModelCache) -> bool:
    """
    Whether a payload position written with no element in it reads `undefined`, which is what
    spelling it out as `undefined` at the call site claims. A hole is not an element whose value is
    `undefined`: the callee reaches it by reading that index off the payload array, so what it finds
    is whatever `Array.prototype` answers there, and a file that wrote that prototype answers
    something else.
    """
    return cache.effects.chain_roots_unwritten(list)


def _read_dispatch(
    reference: Node,
    dispatcher: _Dispatcher,
    entries: dict[str, _Entry],
    cache: ModelCache,
) -> _Dispatch | None:
    """
    The dispatch *reference* is the callee of, or `None` where it is not one this pass reads. The
    key selects the entry and the flags behind it what the dispatch denotes: the create flag the
    entry itself, the clear flag a call of it with the payload emptied, and any other flag a call
    with what the payload holds, which is only known where the dispatch is the second half of a pair
    assigning it. The wrap flag puts the result under the wrap key, so a dispatch spelling it is
    read only together with the access on that key, and a `new` dispatch only with it, since `new`
    hands back what the router returned only where that is an object. Every argument after the
    third is dropped, so it must run nothing, and a create dispatch takes none: the router reads a
    fourth argument as its table of lengths there.
    """
    dispatch = reference.parent
    if (
        not isinstance(reference, JsIdentifier)
        or not isinstance(dispatch, (JsCallExpression, JsNewExpression))
        or dispatch.callee is not reference
        or isinstance(dispatch, JsCallExpression) and dispatch.optional
    ):
        return None
    key = _string_argument(dispatch, 0)
    flag = _string_argument(dispatch, 1)
    kind = _string_argument(dispatch, 2)
    if not isinstance(key, str) or key not in entries:
        return None
    if isinstance(flag, _Unreadable) or isinstance(kind, _Unreadable):
        return None
    wrapped = kind == dispatcher.wrap_flag
    expression: Node = dispatch
    holder = enclosing_operator(dispatch)
    if (
        isinstance(holder, JsMemberExpression)
        and strip_parens(holder.object) is dispatch
        and not holder.optional
        and access_key(holder) == dispatcher.wrap_key
    ):
        expression = holder
    accessed = expression is not dispatch
    if wrapped is not accessed or is_member_write_target(expression):
        return None
    if isinstance(dispatch, JsNewExpression) and not wrapped:
        return None
    if not all(
        cache.effects.is_side_effect_free(
            argument,
            discarded=True,
            reads_may_throw=True,
            read_established=cache.read_established,
        )
        for argument in dispatch.arguments[3:]
    ):
        return None
    in_front = _payload_in_front(expression, dispatcher.payload, cache.model)
    if flag == dispatcher.create_flag:
        if in_front is not None or len(dispatch.arguments) > 3:
            return None
        return _Dispatch(expression, reference, key, None)
    receiver = dispatcher.wrap_key if wrapped and is_invocation_target(expression) else None
    if flag == dispatcher.clear_flag:
        if in_front is not None:
            return None
        return _Dispatch(expression, reference, key, [], receiver=receiver)
    if in_front is None:
        if entries[key].unpacking is not None:
            return None
        return _Dispatch(expression, reference, key, [], receiver=receiver)
    if None in in_front.elements and not _a_hole_reads_undefined(cache):
        return None
    arguments: list[Expression] = [
        make_undefined_expression() if element is None else element
        for element in in_front.elements
    ]
    return _Dispatch(in_front.pair, reference, key, arguments, payload=in_front.target)


class JsDispatcherUnwrapper(ScopeProcessingTransformer):
    """
    Unwrap every router that is the template: recover its table entries as functions of their own,
    rewrite every dispatch into a call of one or a reference to one, and remove the router with the
    payload, the cache and the length helper where nothing else references them. Where any of that
    cannot be done without changing what the program computes, the router stays whole.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        for function in list(body):
            if not isinstance(function, JsFunctionDeclaration):
                continue
            dispatcher = self._read_template(function)
            if dispatcher is not None:
                self._unwrap(scope, dispatcher)

    def _read_template(self, function: JsFunctionDeclaration) -> _Dispatcher | None:
        assert self._root is not None
        try:
            reader = _TemplateReader(function)
            return reader.dispatcher(model_cache(self, self._root).model)
        except _NotTheTemplate:
            return None

    def _unwrap(self, scope: Node, dispatcher: _Dispatcher) -> None:
        """
        Decide the whole unwrap on the tree as it stands, then make it in one go. No model is asked
        anything after the first edit.
        """
        assert self._root is not None
        cache = model_cache(self, self._root)
        model = cache.model
        entries: dict[str, _Entry] = {}
        for key, function in dispatcher.entries.items():
            entry = _read_entry(function, dispatcher, model)
            if entry is None:
                return
            entries[key] = entry
        dispatches: list[_Dispatch] = []
        for reference in model.references(dispatcher.binding):
            dispatch = _read_dispatch(reference, dispatcher, entries, cache)
            if dispatch is None:
                return
            dispatches.append(dispatch)
        if not _reached_only_through(
            model,
            dispatcher.binding,
            {dispatch.reference for dispatch in dispatches},
        ):
            return
        payload_references = set(dispatcher.template_references)
        for entry in entries.values():
            if entry.unpacking is not None:
                payload_references.add(entry.unpacking.source)
        for dispatch in dispatches:
            if dispatch.payload is not None:
                payload_references.add(dispatch.payload)
        for binding, references in (
            (dispatcher.payload, payload_references),
            (dispatcher.cache, dispatcher.template_references),
        ):
            if not _reached_only_through(model, binding, references):
                return
        if (body_scope := model.scope_of(scope)) is None:
            return
        if any(
            model.direct_eval_declares_below(dispatch.node, body_scope)
            for dispatch in dispatches
        ):
            return
        handed_out = {dispatch.key for dispatch in dispatches if dispatch.arguments is None}
        parameters: dict[str, ParameterList] = {}
        for key, entry in entries.items():
            length = dispatcher.stand_in_length(key) if key in handed_out else None
            if (decided := entry.parameters(length)) is None:
                return
            parameters[key] = decided
        names = _choose_names(model, body_scope, dispatcher, dispatches)
        removals = _removable_declarators(cache, dispatcher.payload)
        removals.extend(_removable_declarators(
            cache,
            dispatcher.cache,
            partial(_is_object_create_null, effects=cache.effects),
        ))
        helpers: list[Node] = []
        if _reached_only_through(
            model,
            dispatcher.helper,
            dispatcher.template_references,
        ):
            helpers = [
                declaration.parent for declaration in dispatcher.helper.declarations
                if isinstance(declaration.parent, JsFunctionDeclaration)
                and declaration.parent.id is declaration
                and model.binding_of(declaration) is dispatcher.helper
            ]
        for dispatch in sorted(dispatches, key=lambda dispatch: _depth(dispatch.node)):
            _replace_in_parent(dispatch.node, dispatch.replacement(names[dispatch.key]))
        edit = BodyEdit(scope, 'body')
        edit.splice(
            dispatcher.declaration,
            [entry.recovered(names[key], parameters[key]) for key, entry in entries.items()],
        )
        edit.apply()
        for declarator in removals:
            remove_declarator(declarator)
        for helper in helpers:
            _remove_from_parent(helper)
        self.mark_changed()
