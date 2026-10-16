"""
Where a JavaScript program may give a function a conversion of its own from code that does not name
the function. Converting a function (`String(W)`, `W + ''`) consults its `Symbol.toPrimitive`, then
its `toString` and `valueOf`, each through its prototype chain, and a program changes the answer by
giving the function one of these methods of its own or a new prototype.

`refinery.lib.scripts.js.analysis.effects.EffectModel.function_object_untouched` follows a function
through the names that hold it and refuses wherever one hands it on. A function handed on may still
never receive such a method: `ConversionInstalls` scans the whole program once for every install
that could reach a function, so a function handed on that no install reaches still converts to the
text it was written with. A key known only at runtime is no evidence of an install. A key the run
decodes later is, which is why a fold resting on the absence of evidence waits for a tree the run
has settled; `ConversionSettlement` is the record of that wait.
"""
from __future__ import annotations

import weakref

from typing import TYPE_CHECKING, Callable, Iterable, Iterator, NamedTuple, Sequence, TypeVar, cast

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.intrinsics import GLOBAL_OBJECT
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    BindingKind,
    ReferenceNode,
    Role,
    _property_key_name,
    arguments_name_their_function,
    constructed_class,
    element_positions,
    enclosing_operator,
    is_member_write_target,
    read_is_only_tested,
    receiver_owner,
    reference_role,
    references_new_target,
)
from refinery.lib.scripts.js.model import (
    CONVERSION_INSTALL_METHODS,
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsMethodDefinition,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
    JsPropertyDefinition,
    JsRegExpLiteral,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsTemplateLiteral,
    JsThisExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    static_property_key,
    static_string,
    strip_parens,
)

if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.effects import EffectModel

_T = TypeVar('_T')

CONVERSION_KEYS = frozenset({'toString', 'valueOf', '__proto__'})
"""
The keys a write installs a conversion under: an own `toString` or `valueOf`, or a new prototype
through `__proto__`. `Symbol.toPrimitive` is no string; a member read named `toPrimitive` stands
for it whatever its object.
"""

RECEIVER_INSTALL_METHODS = frozenset({'__defineGetter__', '__defineSetter__'})
"""
The methods of `refinery.lib.scripts.js.model.CONVERSION_INSTALL_METHODS` that install on their
receiver. Every other one installs on its first argument, and `Reflect.set` also on its fourth.
"""

NON_FUNCTION_BUILDERS = frozenset({
    'Array',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'Date',
    'RegExp',
    'Error',
    'TypeError',
    'RangeError',
    'SyntaxError',
    'ReferenceError',
    'EvalError',
    'URIError',
    'ArrayBuffer',
    'DataView',
    'Uint8Array',
    'Int8Array',
    'Uint16Array',
    'Int16Array',
    'Uint32Array',
    'Int32Array',
    'Float32Array',
    'Float64Array',
    'Uint8ClampedArray',
    'BigInt64Array',
    'BigUint64Array',
    'Promise',
    'String',
    'Number',
    'Boolean',
})
"""
Built-ins whose result is never a function, whether they are called or constructed.
"""

_NAME_DEPTH = 8
"""
How many names a reader follows through the values they are given. A reader that reaches the limit
answers as if the name could hold anything: a key may spell a conversion, a receiver may hold any
function. The limit bounds a chain of names each holding the previous one.
"""


class _ArgumentAt(NamedTuple):
    """
    An element of the `arguments` of *function*: the one at *position*, or any one when it is
    `None`. A key reader follows it the way it follows a name.
    """
    function: JsFunctionDeclaration | JsFunctionExpression
    position: int | None


_VALUE_FREE_OF_FUNCTIONS = (
    JsObjectExpression,
    JsArrayExpression,
    JsStringLiteral,
    JsNumericLiteral,
    JsBooleanLiteral,
    JsNullLiteral,
    JsRegExpLiteral,
    JsTemplateLiteral,
    JsUnaryExpression,
    JsBinaryExpression,
    JsUpdateExpression,
)


class ConversionSettlement:
    """
    The record one deobfuscation run keeps of the conversions it could not fold yet. A function that
    is handed on, with no evidence that an install reaches it, folds only on the tree the run has
    settled: the one the pipeline reached its fixpoint on, where every key the run can decode has
    been decoded. A question asked on any other tree is refused, and the record notes the tree it
    was asked on. When the pipeline reaches its fixpoint on a tree a question was refused on, the
    run settles that tree and runs again. A change in that run leaves the settled tree behind,
    since it may let the run decode a key that spells an install, so the questions asked after it
    wait for the next fixpoint.
    """

    def __init__(self):
        self.version: int | None = None
        self.waiting: int | None = None

    def settled(self, version: int) -> bool:
        """
        Whether the tree at *version* is the one the run settled.
        """
        return version == self.version

    def defer(self, version: int) -> None:
        """
        Record that a question asked on the tree at *version* was refused until a settled tree.
        """
        self.waiting = version

    def waits_on(self, version: int) -> bool:
        """
        Whether a question was refused on the tree at *version*, the last tree it was asked on.
        """
        return version == self.waiting

    def settle(self, version: int) -> None:
        """
        Declare that the pipeline reached its fixpoint on the tree at *version*.
        """
        self.version = version
        self.waiting = None


def _is_direct_callee(node: Node) -> bool:
    """
    Whether *node*, through any parentheses, is the callee of a call.
    """
    call = enclosing_operator(node)
    return isinstance(call, JsCallExpression) and strip_parens(call.callee) is node


def _stores_under_its_key(member: JsMemberExpression) -> bool:
    """
    Whether *member* is the target of a write that stores a value under its key, which a `delete`
    of it does not.
    """
    if not is_member_write_target(member):
        return False
    governor = enclosing_operator(member)
    return not (isinstance(governor, JsUnaryExpression) and governor.operator == 'delete')


def _spread_out(arguments: Sequence[Node]) -> tuple[list[Node], bool]:
    """
    The arguments a call passes as far as their positions are known, every spread of an array
    literal written out in place, and whether a spread of anything else hides the arguments after
    them.
    """
    spread: list[Node] = []
    for argument in arguments:
        stripped = strip_parens(argument)
        if not isinstance(stripped, JsSpreadElement):
            spread.append(argument if stripped is None else stripped)
            continue
        array = strip_parens(stripped.argument)
        if not isinstance(array, JsArrayExpression):
            return spread, True
        for element in array.elements:
            element = strip_parens(element)
            if element is None or isinstance(element, JsSpreadElement):
                return spread, True
            spread.append(element)
    return spread, False


def _destructured_key(binding: Binding) -> str | None:
    """
    The key a destructuring pattern takes the value of *binding* from, or `None`.
    """
    if not binding.declarations:
        return None
    parent = binding.declarations[0].parent
    if isinstance(parent, JsAssignmentPattern):
        parent = parent.parent
    if isinstance(parent, JsProperty) and isinstance(parent.parent, JsObjectPattern):
        return _property_key_name(parent)
    return None


def _entry_position(binding: Binding) -> tuple[JsArrayPattern, int] | None:
    """
    The array pattern that declares *binding* and its position in it, the way a loop over
    `Object.entries` names a key and its value: `[k, v]`.
    """
    if not binding.declarations:
        return None
    declaration = binding.declarations[0]
    pattern = declaration.parent
    if not isinstance(pattern, JsArrayPattern):
        return None
    for index, element in enumerate(pattern.elements):
        if element is declaration:
            return pattern, index
    return None


class ConversionInstalls:
    """
    The conversion installs of one script, scanned when its
    `refinery.lib.scripts.js.analysis.effects.EffectModel` is built: every place that may give a
    function a `toString`, `valueOf` or `Symbol.toPrimitive` of its own, or a new prototype.
    `reach` holds the function literals one of them may reach, or `None` when one may reach any
    function. An install counts when the program certainly makes it:

    - a write, but no `delete`, under a conversion key on a receiver that may hold a function;
    - an installer call (`refinery.lib.scripts.js.model.CONVERSION_INSTALL_METHODS`, also through
      `Reflect.set`) whose target may hold a function and which spells a conversion key, sets a
      prototype, or copies from a source spelling one;
    - a copy, onto a receiver that may hold a function, from a source the scan cannot read: an
      `assign` or `defineProperties` call, or a write or `defineProperty` under a key the scan
      cannot read whose value is read off another object under the same key, directly, through
      names, through `bind`, as its descriptor, or beside the key in a `[key, value]` entry. It
      counts only when the program gives some object an own conversion method a copy could carry.

    Any function may be reached when the program has a reflection surface, reads an installer or
    `Reflect` as a value other than through a name every read of which calls or tests it, or
    destructures an installer into such a name, or passes the target of an installer call through
    a spread the scan cannot write out.

    A key, a source or a receiver is read through the values its names are given, a parameter
    through the calls of its function the text shows
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.values_through_calls`), and a key also
    through the arguments those calls pass where it reads the function's own `arguments`. A key
    known only at runtime is no evidence. The readers remember their answers, a key per name and
    the others per name and depth, so a name reused for many writes is read once, and no answer
    depends on which question came first. The effect model that holds the scan is held back only
    weakly, so the two leave memory together.
    """

    def __init__(self, effects: EffectModel):
        self._effects = cast('EffectModel', weakref.proxy(effects))
        self._model = effects.model
        self._keys: dict[Binding | _ArgumentAt, bool | None] = {}
        self._sources: dict[tuple[Binding, int], bool | None] = {}
        self._may_hold: dict[tuple[Binding, int], bool] = {}
        self._held: dict[tuple[Binding, int], frozenset[Node] | None] = {}
        self._fresh_receivers: dict[Node, bool] = {}
        self._fresh_prototypes: dict[Binding, bool] = {}
        self._installer_aliases, self._installers_escape = self._collect_installer_aliases()
        self.reach = self._scan()

    def may_reach(self, function: Node) -> bool:
        """
        Whether some install may give *function* a conversion of its own.
        """
        return self.reach is None or function in self.reach

    def installer_of_call(self, call: JsCallExpression) -> str | None:
        """
        The installer *call* runs, by its method name (`Reflect.set` for that one), or `None`.
        """
        callee = strip_parens(call.callee)
        if isinstance(callee, JsMemberExpression):
            return self._installer_key(callee)
        if isinstance(callee, JsIdentifier):
            binding = self._model.resolve(callee)
            if binding is not None:
                return self._installer_aliases.get(binding)
        return None

    def install_spelled(self, call: JsCallExpression, installer: str, target: int) -> bool | None:
        """
        What the installer call *call* spells for the value at argument *target*, or for its
        receiver when *target* is -1: `True` a conversion key or a new prototype, `False` another
        key or a position it does not install on, `None` a key or a source known only at runtime.
        A spread of an array literal is read as the arguments it writes out.
        """
        arguments, hidden = _spread_out(call.arguments)

        def argument(index: int) -> Node | None:
            return arguments[index] if index < len(arguments) else None

        def unknown_past(index: int) -> bool:
            return hidden and index >= len(arguments)

        if installer == 'setPrototypeOf':
            return target == 0
        if installer == 'defineProperty':
            if target != 0:
                return False
            return None if unknown_past(1) else self.spells_key(argument(1))
        if installer == 'Reflect.set':
            if target not in (0, 3):
                return False
            return None if unknown_past(1) else self.spells_key(argument(1))
        if installer in ('assign', 'defineProperties'):
            if target != 0:
                return False
            answers = [self._spells_source(source) for source in arguments[1:]]
            if any(answers):
                return True
            if hidden or any(answer is None for answer in answers):
                return None
            return False
        if installer in RECEIVER_INSTALL_METHODS:
            if target != -1:
                return False
            return None if unknown_past(0) else self.spells_key(argument(0))
        return False

    def spells_member_key(self, key: Node | None, computed: bool) -> bool | None:
        """
        Whether the key of a member, a property or a class member spells a conversion key, in the
        sense of `spells_key`; a key that is not computed is its own name, quoted or not.
        """
        if computed:
            return self.spells_key(key)
        name = key.name if isinstance(key, JsIdentifier) else static_string(key)
        return name in CONVERSION_KEYS

    def spells_key(self, node: Node | None) -> bool | None:
        """
        Whether the key expression *node* spells a conversion key: `True`, `False` when it spells
        another key, `None` when it is known only at runtime. A member read named `toPrimitive`
        counts whatever its object, and so does a name destructured from that key. A conditional is
        read through its branches the way a name is read through its values (`_key_of_name`), and
        an element of a function's own `arguments` through the arguments its calls pass there.
        """
        answer: bool | None = False
        for atom in self._key_atoms(node):
            if isinstance(atom, (Binding, _ArgumentAt)):
                atom = self._key_of_name(atom)
            if atom is True:
                return True
            if atom is None:
                answer = None
        return answer

    def _key_atoms(self, node: Node | None) -> Iterator[Binding | _ArgumentAt | bool | None]:
        """
        What the key expression *node* may evaluate to, as `spells_key` reads it without following
        names: an answer of its own, or the name or the element of `arguments` whose values it
        takes.
        """
        node = strip_parens(node)
        if node is None:
            yield None
            return
        text = static_string(node)
        if text is not None:
            yield text in CONVERSION_KEYS
        elif isinstance(node, (JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
            yield False
        elif isinstance(node, JsMemberExpression):
            key = static_property_key(node)
            if key == 'toPrimitive':
                yield True
            elif key is not None and self._effects.trusted_intrinsic(node.object) == 'Symbol':
                yield False
            else:
                yield self._argument_read(node)
        elif isinstance(node, JsSequenceExpression):
            yield from self._key_atoms(node.expressions[-1] if node.expressions else None)
        elif isinstance(node, JsConditionalExpression):
            yield from self._key_atoms(node.consequent)
            yield from self._key_atoms(node.alternate)
        elif isinstance(node, JsIdentifier):
            yield self._model.resolve(node)
        else:
            yield None

    def _argument_read(self, member: JsMemberExpression) -> Binding | _ArgumentAt | None:
        """
        What the key *member* reads when it takes an element of a function's own `arguments`: the
        parameter the function names at that position, which the element starts out as and a
        sloppy function's element keeps mirroring, or else the element itself; `None` for any
        other member.
        """
        receiver = strip_parens(member.object)
        if not isinstance(receiver, JsIdentifier):
            return None
        binding = self._model.resolve(receiver)
        if binding is None or binding.kind is not BindingKind.ARGUMENTS:
            return None
        function = binding.scope.node
        if not isinstance(function, (JsFunctionDeclaration, JsFunctionExpression)):
            return None
        positions = element_positions(member)
        if positions is None:
            return _ArgumentAt(function, None)
        if not positions:
            return None
        position = positions.start
        if position < len(function.params):
            parameter = function.params[position]
            if isinstance(parameter, JsIdentifier):
                return self._model.binding_of(parameter)
        return _ArgumentAt(function, position)

    def _key_of_name(self, name: Binding | _ArgumentAt) -> bool | None:
        """
        `spells_key` for a key the name or the element of `arguments` *name* holds: `True` when
        some value of it, or of a name those values lead to within `_NAME_DEPTH` names, spells a
        conversion key, or when the names lead on past that; `False` when every value read spells
        another key and every name read lists all its values; `None` otherwise. Each name is read
        once, so a cycle of names adds nothing the names in it do not hold, and the answer is
        remembered per name.
        """
        if name not in self._keys:
            self._keys[name] = self._read_key_of_name(name)
        return self._keys[name]

    def _read_key_of_name(self, name: Binding | _ArgumentAt) -> bool | None:
        answer: bool | None = False
        seen = {name}
        level = [name]
        for _ in range(_NAME_DEPTH):
            following: list[Binding | _ArgumentAt] = []
            for source in level:
                atoms: Iterable[Binding | _ArgumentAt | bool | None]
                if source is not name and source in self._keys:
                    atoms = (self._keys[source],)
                elif isinstance(source, Binding) and _destructured_key(source) == 'toPrimitive':
                    return True
                else:
                    if isinstance(source, Binding):
                        values, complete = self._model.values_through_calls(source)
                    else:
                        values, complete = self._model.arguments_through_calls(source.function, source.position)
                    if not complete or not values:
                        answer = None
                    atoms = (atom for value in values for atom in self._key_atoms(value))
                for atom in atoms:
                    if isinstance(atom, (Binding, _ArgumentAt)):
                        if atom not in seen:
                            seen.add(atom)
                            following.append(atom)
                    elif atom is True:
                        return True
                    elif atom is None:
                        answer = None
            if not following:
                return answer
            level = following
        return True

    def _spells_source(self, node: Node | None, depth: int = 0) -> bool | None:
        """
        Whether a source handed to `assign` or `defineProperties` spells a conversion key: `True`,
        `False`, or `None` for a source whose keys are unknown. An object literal is read with its
        spreads; a name through its values and the writes made through it.
        """
        node = strip_parens(node)
        if isinstance(node, JsObjectExpression):
            unknown = False
            for prop in node.properties:
                if isinstance(prop, JsSpreadElement):
                    spread = self._spells_source(prop.argument, depth + 1)
                    if spread:
                        return True
                    if spread is None:
                        unknown = True
                    continue
                if not isinstance(prop, JsProperty):
                    unknown = True
                    continue
                spelled = self.spells_member_key(prop.key, prop.computed)
                if spelled:
                    return True
                if spelled is None:
                    unknown = True
            return None if unknown else False
        if not isinstance(node, JsIdentifier) or depth >= _NAME_DEPTH:
            return None
        binding = self._model.resolve(node)
        if binding is None:
            return None

        def source_spelled() -> bool | None:
            values, complete = self._model.values_through_calls(binding)
            answers = [self._spells_source(value, depth + 1) for value in values]
            if any(answers):
                return True
            for read in binding.reads:
                member = enclosing_operator(read)
                if (
                    isinstance(member, JsMemberExpression)
                    and strip_parens(member.object) is read
                    and _stores_under_its_key(member)
                    and self.spells_member_key(member.property, member.computed)
                ):
                    return True
            if (
                complete
                and values
                and self._effects.binding_is_immutable_container(binding)
                and all(answer is False for answer in answers)
            ):
                return False
            return None

        return self._remembered(self._sources, (binding, depth), source_spelled)

    def _may_hold_function(self, node: Node | None, depth: int = 0) -> bool:
        """
        Whether *node* may evaluate to a function. It certainly does not when it is a literal other
        than a function, an operator yielding a primitive, the global object, the result of a
        built-in in `NON_FUNCTION_BUILDERS`, a `prototype` the language gave a function
        (`_prototype_is_fresh`), a `this` only a constructor call supplies (`_this_is_fresh`), or a
        name every value of which certainly holds none.
        """
        node = strip_parens(node)
        if node is None:
            return False
        if isinstance(node, _VALUE_FREE_OF_FUNCTIONS):
            return False
        if isinstance(node, JsSequenceExpression):
            return bool(node.expressions) and self._may_hold_function(node.expressions[-1], depth)
        if isinstance(node, JsLogicalExpression):
            return self._may_hold_function(node.left, depth) or self._may_hold_function(node.right, depth)
        if isinstance(node, JsConditionalExpression):
            return self._may_hold_function(node.consequent, depth) or self._may_hold_function(node.alternate, depth)
        if isinstance(node, JsAssignmentExpression) and node.operator == '=':
            return self._may_hold_function(node.right, depth)
        if isinstance(node, JsThisExpression):
            return not self._this_is_fresh(node)
        if isinstance(node, (JsNewExpression, JsCallExpression)):
            callee = strip_parens(node.callee)
            if (
                isinstance(node, JsCallExpression)
                and isinstance(callee, JsMemberExpression)
                and static_property_key(callee) in ('call', 'apply')
                and self._effects.trusted_intrinsic(callee.object) in NON_FUNCTION_BUILDERS
            ):
                return False
            return self._effects.trusted_intrinsic(node.callee) not in NON_FUNCTION_BUILDERS
        if isinstance(node, JsMemberExpression) and static_property_key(node) == 'prototype':
            return not self._prototype_is_fresh(node, depth)
        if not isinstance(node, JsIdentifier):
            return True
        if self._effects.intrinsic_of(node) is GLOBAL_OBJECT:
            return False
        if depth >= _NAME_DEPTH:
            return True
        binding = self._model.resolve(node)
        if binding is None:
            return True

        def may_hold() -> bool:
            values, complete = self._model.values_through_calls(binding)
            if not complete or not values:
                return True
            return any(self._may_hold_function(value, depth + 1) for value in values)

        return self._remembered(self._may_hold, (binding, depth), may_hold)

    def _held_functions(self, node: Node | None, depth: int = 0) -> frozenset[Node] | None:
        """
        The function literals *node* may evaluate to, or `None` when it may be any function.
        """
        node = strip_parens(node)
        if node is None:
            return frozenset()
        if isinstance(node, FUNCTION_NODES):
            return frozenset({node})
        if isinstance(node, (JsClassExpression, JsClassDeclaration)):
            return frozenset()
        if isinstance(node, JsSequenceExpression):
            parts = node.expressions[-1:]
        elif isinstance(node, JsLogicalExpression):
            parts = [node.left, node.right]
        elif isinstance(node, JsConditionalExpression):
            parts = [node.consequent, node.alternate]
        elif isinstance(node, JsAssignmentExpression) and node.operator == '=':
            parts = [node.right]
        elif isinstance(node, JsIdentifier):
            return self._functions_held_by_name(node, depth)
        else:
            return None if self._may_hold_function(node, depth) else frozenset()
        return self._union_of_held(parts, depth)

    def _functions_held_by_name(self, node: JsIdentifier, depth: int) -> frozenset[Node] | None:
        if self._effects.intrinsic_of(node) is GLOBAL_OBJECT:
            return frozenset()
        if depth >= _NAME_DEPTH:
            return None
        binding = self._model.resolve(node)
        if binding is None:
            return None

        def held() -> frozenset[Node] | None:
            values, complete = self._model.values_through_calls(binding)
            if not complete or not values:
                return None
            return self._union_of_held(values, depth + 1)

        return self._remembered(self._held, (binding, depth), held)

    def _union_of_held(self, parts: Iterable[Node | None], depth: int) -> frozenset[Node] | None:
        held: frozenset[Node] = frozenset()
        for part in parts:
            more = self._held_functions(part, depth)
            if more is None:
                return None
            held |= more
        return held

    def _this_is_fresh(self, node: JsThisExpression) -> bool:
        """
        Whether `this` at *node* is an object a constructor call has just built: the receiver of a
        class constructor whose class extends nothing or a built-in in `NON_FUNCTION_BUILDERS`, or
        of a plain function only `new` reaches (`_only_constructed`). The function must not reach
        itself without its name: its body names neither `new.target` nor its own `arguments` beyond
        index and length, and the program spells no `caller`. The answer is the function's, so it is
        remembered per function.
        """
        owner = receiver_owner(node)
        if not isinstance(owner, (JsFunctionDeclaration, JsFunctionExpression)):
            return False
        fresh = self._fresh_receivers.get(owner)
        if fresh is None:
            fresh = self._fresh_receivers[owner] = self._receiver_is_fresh(owner)
        return fresh

    def _receiver_is_fresh(self, owner: JsFunctionDeclaration | JsFunctionExpression) -> bool:
        """
        `_this_is_fresh` for every `this` of the function *owner*.
        """
        if owner.generator or owner.is_async:
            return False
        if self._model.spells_caller() or arguments_name_their_function(owner):
            return False
        if references_new_target(owner):
            return False
        if isinstance(owner.parent, JsMethodDefinition):
            cls = constructed_class(owner)
            if cls is None:
                return False
            return cls.super_class is None or self._effects.trusted_intrinsic(cls.super_class) in NON_FUNCTION_BUILDERS
        if isinstance(owner, JsFunctionDeclaration):
            names = self._model.function_names(owner)
            return names is not None and all(
                self._only_constructed(name, names.reads_of(name)) for name in names.bindings
            )
        if isinstance(owner.id, JsIdentifier):
            own = self._model.binding_of(owner.id)
            if own is not None and not self._only_constructed(own):
                return False
        return self._only_constructed(self._model.name_holding(owner))

    def _only_constructed(
        self, binding: Binding | None, reads: list[ReferenceNode] | None = None,
    ) -> bool:
        """
        Whether every read of the name *binding*, which holds a function, constructs with it, reads
        its `prototype`, is the right of `instanceof`, or is a test; and the function cannot be
        reached another way: the name is neither exported, nor written at entry, nor reached through
        a handed object or by reflection, and no `constructor` property escapes in the program
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.constructors_may_escape`). *reads*
        are the reads through which the name reaches the function, all of its reads by default
        (`refinery.lib.scripts.js.analysis.model.FunctionNames.reads_of`).
        """
        if (
            binding is None
            or binding.exported
            or binding.written_at_entry
            or binding.reachable_through_a_handed_object
        ):
            return False
        if self._model.constructors_may_escape() or self._model.reflection_can_reach(binding):
            return False
        for read in binding.reads if reads is None else reads:
            parent = enclosing_operator(read)
            if isinstance(parent, JsNewExpression) and strip_parens(parent.callee) is read:
                continue
            if (
                isinstance(parent, JsMemberExpression)
                and strip_parens(parent.object) is read
                and static_property_key(parent) == 'prototype'
            ):
                continue
            if (
                isinstance(parent, JsBinaryExpression)
                and parent.operator == 'instanceof'
                and strip_parens(parent.right) is read
            ):
                continue
            if read_is_only_tested(read):
                continue
            return False
        return True

    def _prototype_is_fresh(self, member: JsMemberExpression, depth: int) -> bool:
        """
        Whether `X.prototype` at *member* is the object the language gave the function `X`: `X`
        holds only function or class literals and no write through `X`'s own name replaces
        `X.prototype`, or `X` is a trusted built-in other than `Function`. The answer is the name's,
        so it is remembered per name.
        """
        owner = strip_parens(member.object)
        trusted = self._effects.trusted_intrinsic(owner)
        if trusted is not None:
            return trusted != 'Function'
        if not isinstance(owner, JsIdentifier) or depth >= _NAME_DEPTH:
            return False
        binding = self._model.resolve(owner)
        if binding is None:
            return False
        fresh = self._fresh_prototypes.get(binding)
        if fresh is None:
            fresh = self._fresh_prototypes[binding] = self._prototype_of_is_fresh(binding)
        return fresh

    def _prototype_of_is_fresh(self, binding: Binding) -> bool:
        """
        `_prototype_is_fresh` for the `prototype` of every function the name *binding* holds.
        """
        values, complete = self._model.values_through_calls(binding)
        if not complete or not values:
            return False
        if not all(isinstance(strip_parens(value), (*FUNCTION_NODES, JsClassDeclaration, JsClassExpression)) for value in values):
            return False
        for read in binding.reads:
            outer = enclosing_operator(read)
            if (
                isinstance(outer, JsMemberExpression)
                and strip_parens(outer.object) is read
                and static_property_key(outer) == 'prototype'
                and is_member_write_target(outer)
            ):
                return False
        return True

    def _is_global_reflect(self, node: Node | None) -> bool:
        node = strip_parens(node)
        return (
            isinstance(node, JsIdentifier)
            and node.name == 'Reflect'
            and self._model.is_reference(node)
            and self._model.resolve(node) is None
        )

    def _installer_key(self, member: JsMemberExpression) -> str | None:
        """
        The installer the member read *member* names, or `None`.
        """
        key = static_property_key(member)
        if key in CONVERSION_INSTALL_METHODS:
            return key
        if key == 'set' and self._is_global_reflect(member.object):
            return 'Reflect.set'
        return None

    def _calls_or_tests_only(self, binding: Binding) -> bool:
        """
        Whether every read of *binding* calls it or only tests it, and nothing reaches the name
        without a read.
        """
        if (
            binding.exported
            or binding.written_at_entry
            or binding.reachable_through_a_handed_object
            or self._model.reflection_can_reach(binding)
        ):
            return False
        return all(_is_direct_callee(read) or read_is_only_tested(read) for read in binding.reads)

    def _installer_alias(self, member: JsMemberExpression) -> Binding | None:
        """
        The name the installer read *member* is stored into, when it is that name's one value and
        every read of the name calls or tests it.
        """
        alias = self._model.name_holding(member)
        if alias is None or strip_parens(self._model.singular_value(alias)) is not member:
            return None
        return alias if self._calls_or_tests_only(alias) else None

    def _pattern_alias(self, prop: JsProperty) -> Binding | None:
        """
        The name the destructuring property *prop* binds an installer to, when every read of the
        name calls or tests it.
        """
        target = strip_parens(prop.value)
        if isinstance(target, JsAssignmentPattern):
            target = strip_parens(target.left)
        if not isinstance(target, JsIdentifier):
            return None
        alias = self._model.binding_of(target)
        if alias is None:
            alias = self._model.resolve(target)
        if alias is None:
            return None
        return alias if self._calls_or_tests_only(alias) else None

    def _collect_installer_aliases(self) -> tuple[dict[Binding, str], bool]:
        """
        The names that hold an installer and are only called or tested, by the installer they hold,
        and whether an installer is read another way: as a value that is no such name's one value,
        or destructured into a name that is read another way. Destructuring `Reflect` hands it on
        as well.
        """
        aliases: dict[Binding, str] = {}
        escape = False
        for node in self._model.root.walk():
            if isinstance(node, JsMemberExpression):
                key = self._installer_key(node)
                if (
                    key is None
                    or is_member_write_target(node)
                    or _is_direct_callee(node)
                    or read_is_only_tested(node)
                ):
                    continue
                alias = self._installer_alias(node)
            elif isinstance(node, JsProperty) and isinstance(node.parent, JsObjectPattern):
                key = _property_key_name(node)
                if key == 'Reflect':
                    escape = True
                    continue
                if key is None or key not in CONVERSION_INSTALL_METHODS:
                    continue
                alias = self._pattern_alias(node)
            else:
                continue
            if alias is None:
                escape = True
            else:
                aliases[alias] = key
        return aliases, escape

    def _is_copy_write(self, member: JsMemberExpression) -> bool:
        """
        Whether the write through *member* stores, under a key the scan cannot read, a value read
        off another object under the same key (`_copies_under`).
        """
        store = enclosing_operator(member)
        if not isinstance(store, JsAssignmentExpression) or strip_parens(store.left) is not member:
            return False
        key = strip_parens(member.property)
        if not member.computed or not isinstance(key, JsIdentifier):
            return False
        binding = self._model.resolve(key)
        return binding is not None and self._copies_under(store.right, binding)

    def _copies_under(self, value: Node | None, key: Binding, depth: int = 0) -> bool:
        """
        Whether *value* is read off another object under the name *key* holds: `s[k]`, a copy of
        that bound with `bind`, its descriptor `Object.getOwnPropertyDescriptor(s, k)`, a name
        holding one of these, or the value beside *key* in a `[key, value]` entry.
        """
        value = strip_parens(value)
        if isinstance(value, JsMemberExpression):
            other = strip_parens(value.property)
            return value.computed and isinstance(other, JsIdentifier) and self._model.resolve(other) is key
        if isinstance(value, JsCallExpression):
            callee = strip_parens(value.callee)
            if not isinstance(callee, JsMemberExpression):
                return False
            method = static_property_key(callee)
            if method == 'bind':
                return self._copies_under(callee.object, key, depth)
            if method == 'getOwnPropertyDescriptor' and len(value.arguments) > 1:
                other = strip_parens(value.arguments[1])
                return isinstance(other, JsIdentifier) and self._model.resolve(other) is key
            return False
        if not isinstance(value, JsIdentifier) or depth >= _NAME_DEPTH:
            return False
        binding = self._model.resolve(value)
        if binding is None:
            return False
        entry = _entry_position(binding)
        if entry is not None and entry[1] == 1 and _entry_position(key) == (entry[0], 0):
            return True
        values, _ = self._model.values_through_calls(binding)
        return any(self._copies_under(other, key, depth + 1) for other in values)

    def _gives_an_own_conversion(self, node: Node) -> bool:
        """
        Whether *node* gives some object an own conversion method a copy could carry: the key of an
        object literal's property, of a class method or of a class field, a member write, or an
        install spelling a conversion key.
        """
        if isinstance(node, JsProperty):
            return (
                isinstance(node.parent, JsObjectExpression)
                and self.spells_member_key(node.key, node.computed) is True
            )
        if isinstance(node, (JsMethodDefinition, JsPropertyDefinition)):
            return self.spells_member_key(node.key, node.computed) is True
        if isinstance(node, JsMemberExpression):
            return _stores_under_its_key(node) and self.spells_member_key(node.property, node.computed) is True
        if isinstance(node, JsCallExpression):
            installer = self.installer_of_call(node)
            return installer is not None and any(
                self.install_spelled(node, installer, target) is True for target in (-1, 0, 3)
            )
        return False

    def _gives_some_object_an_own_conversion(self) -> bool:
        """
        Whether the program gives some object an own conversion method (`_gives_an_own_conversion`).
        """
        return any(self._gives_an_own_conversion(node) for node in self._model.root.walk())

    def _reads_reflect_as_a_value(self, node: JsIdentifier) -> bool:
        if not self._is_global_reflect(node) or reference_role(node) is not Role.READ:
            return False
        if read_is_only_tested(node):
            return False
        parent = enclosing_operator(node)
        return not (
            isinstance(parent, JsMemberExpression)
            and strip_parens(parent.object) is node
            and static_property_key(parent) is not None
        )

    def _scan(self) -> frozenset[Node] | None:
        """
        The function literals some install may reach, or `None` when one may reach any function.
        """
        if self._installers_escape or self._model.has_reflection_surface():
            return None
        sites: list[Node | None] = []
        copies: list[Node | None] = []
        for node in self._model.root.walk():
            if isinstance(node, JsIdentifier):
                if self._reads_reflect_as_a_value(node):
                    return None
            elif isinstance(node, JsMemberExpression):
                if is_member_write_target(node):
                    if not _stores_under_its_key(node):
                        continue
                    spelled = self.spells_member_key(node.property, node.computed)
                    if spelled is True:
                        sites.append(node.object)
                    elif spelled is None and self._is_copy_write(node):
                        copies.append(node.object)
                elif static_property_key(node) == 'Reflect' and not read_is_only_tested(node):
                    return None
            elif isinstance(node, JsCallExpression):
                if self._collect_install_sites(node, sites, copies):
                    return None
        if copies and self._gives_some_object_an_own_conversion():
            sites.extend(copies)
        return self._union_of_held(sites, 0)

    def _collect_install_sites(
        self,
        call: JsCallExpression,
        sites: list[Node | None],
        copies: list[Node | None],
    ) -> bool:
        """
        Add the receivers the installer call *call* installs a conversion on to *sites*, and those
        it copies onto from a source the scan cannot read to *copies*. Answers whether the call may
        install on any function: a spread hides which value it installs on.
        """
        installer = self.installer_of_call(call)
        if installer is None:
            return False
        if installer in RECEIVER_INSTALL_METHODS:
            callee = strip_parens(call.callee)
            if isinstance(callee, JsMemberExpression) and self.install_spelled(call, installer, -1) is True:
                sites.append(callee.object)
            return False
        arguments, hidden = _spread_out(call.arguments)
        for target in (0, 3) if installer == 'Reflect.set' else (0,):
            if target >= len(arguments):
                if hidden:
                    return True
                continue
            spelled = self.install_spelled(call, installer, target)
            if spelled is True:
                sites.append(arguments[target])
            elif spelled is None and target == 0 and self._copies_a_source(installer, arguments, hidden):
                copies.append(arguments[target])
        return False

    def _copies_a_source(self, installer: str, arguments: list[Node], hidden: bool) -> bool:
        """
        Whether the installer call with *arguments*, whose key or source the scan cannot read,
        copies from another object: `assign` and `defineProperties` always do, `defineProperty` and
        `Reflect.set` when the value they store is read off another object under their key.
        """
        if installer in ('assign', 'defineProperties'):
            return True
        if hidden or len(arguments) < 3:
            return False
        key = strip_parens(arguments[1])
        if not isinstance(key, JsIdentifier):
            return False
        binding = self._model.resolve(key)
        return binding is not None and self._copies_under(arguments[2], binding)

    @staticmethod
    def _remembered(
        memo: dict[tuple[Binding, int], _T],
        key: tuple[Binding, int],
        compute: Callable[[], _T],
    ) -> _T:
        """
        The answer *compute* gives for a name read at a depth, remembered in *memo* under both. How
        many more names a reader may follow decides its answer, so only a question at the same depth
        shares it; and a reader that follows a name goes one step deeper, so no question is asked
        again while it is being answered.
        """
        if key in memo:
            return memo[key]
        answer = memo[key] = compute()
        return answer
