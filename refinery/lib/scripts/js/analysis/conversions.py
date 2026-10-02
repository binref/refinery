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
decodes later is, which is why a fold resting on the absence of evidence waits until the run has
settled; `ConversionSettlement` is the record of that wait.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Iterable, TypeVar

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.intrinsics import GLOBAL_OBJECT
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    Role,
    _property_key_name,
    arguments_name_their_function,
    enclosing_operator,
    is_member_write_target,
    read_is_only_tested,
    reference_role,
    references_new_target,
)
from refinery.lib.scripts.js.model import (
    CONVERSION_INSTALL_METHODS,
    JsArrayExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsClassBody,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsMethodDefinition,
    JsMethodKind,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsRegExpLiteral,
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
    JsStringLiteral,
    JsTemplateLiteral,
    JsThisExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclarator,
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
How many names a reader follows through the values they are given before it answers that it does
not know. The limit bounds a chain of names each holding the previous one.
"""

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
    is handed on, with no evidence that an install reaches it, folds only once the run has settled:
    a key the run decodes later, from a constant table or a string array, may yet spell an install.
    While the run is open such a question is refused and `deferred` is set. A run that ends with a
    deferral settles the record and runs again over the same models, and every such question then
    folds.
    """

    def __init__(self):
        self.settled = False
        self.deferred = False

    def defer(self) -> None:
        """
        Record that a question was refused which the settled run would answer.
        """
        self.deferred = True

    def settle(self) -> None:
        """
        Declare that the run has decoded every key it can.
        """
        self.settled = True


def _is_direct_callee(node: Node) -> bool:
    """
    Whether *node*, through any parentheses, is the callee of a call.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, JsParenthesizedExpression):
        cursor, parent = parent, parent.parent
    return isinstance(parent, JsCallExpression) and parent.callee is cursor


def _receiver_owner(node: Node) -> Node | None:
    """
    The node that gives the `this` at *node* its value: the nearest regular function around it, or a
    class body, static block or field, which give it one of their own. Arrows are passed through.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, (JsFunctionDeclaration, JsFunctionExpression)):
            return cursor
        if isinstance(cursor, (JsClassBody, JsStaticBlock, JsPropertyDefinition)):
            return cursor
        cursor = cursor.parent
    return None


def _constructor_read_is_harmless(node: Node) -> bool:
    """
    Whether a read of a `constructor` property at *node* only constructs with it, compares it, reads
    its name, or tests it.
    """
    parent = enclosing_operator(node)
    if isinstance(parent, JsNewExpression) and strip_parens(parent.callee) is node:
        return True
    if isinstance(parent, JsMemberExpression) and strip_parens(parent.object) is node:
        return static_property_key(parent) == 'name' and not is_member_write_target(parent)
    if isinstance(parent, JsBinaryExpression) and parent.operator == 'instanceof':
        return True
    return read_is_only_tested(node)


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
      `assign` or `defineProperties` call, or a write `d[k] = s[k]`. It counts only when the program
      gives some object an own conversion method a copy could carry.

    Any function may be reached when the program has a reflection surface, reads an installer or
    `Reflect` as a value other than through a name every read of which calls or tests it, or
    destructures an installer into such a name.

    A key, a source or a receiver is read through the values its names are given, a parameter
    through the calls of its function the text shows
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.values_through_calls`). A key known only
    at runtime is no evidence. The readers remember their answer per name, so a name reused for many
    writes is read once.
    """

    def __init__(self, effects: EffectModel):
        self._effects = effects
        self._model = effects.model
        self._keys: dict[Binding, bool | None] = {}
        self._sources: dict[Binding, bool | None] = {}
        self._may_hold: dict[Binding, bool] = {}
        self._held: dict[Binding, frozenset[Node] | None] = {}
        self._constructors_escape: bool | None = None
        self._installer_aliases = self._collect_installer_aliases()
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
        What the installer call *call* spells for the value at argument *target*, or for its receiver
        when *target* is -1: `True` a conversion key or a new prototype, `False` another key or a
        position it does not install on, `None` a key or a source known only at runtime.
        """
        arguments = call.arguments
        if any(isinstance(argument, JsSpreadElement) for argument in arguments):
            return None
        if installer == 'setPrototypeOf':
            return target == 0
        if installer == 'defineProperty':
            if target != 0:
                return False
            return self.spells_key(arguments[1] if len(arguments) > 1 else None)
        if installer == 'Reflect.set':
            if target not in (0, 3):
                return False
            return self.spells_key(arguments[1] if len(arguments) > 1 else None)
        if installer in ('assign', 'defineProperties'):
            if target != 0:
                return False
            answers = [self._spells_source(source) for source in arguments[1:]]
            if any(answers):
                return True
            if any(answer is None for answer in answers):
                return None
            return False
        if installer in RECEIVER_INSTALL_METHODS:
            if target != -1:
                return False
            return self.spells_key(arguments[0] if arguments else None)
        return False

    def spells_member_key(self, key: Node | None, computed: bool) -> bool | None:
        """
        Whether the key of a member or a property spells a conversion key, in the sense of
        `spells_key`; a key that is not computed is its own name.
        """
        if not computed:
            return isinstance(key, JsIdentifier) and key.name in CONVERSION_KEYS
        return self.spells_key(key)

    def spells_key(self, node: Node | None, depth: int = 0) -> bool | None:
        """
        Whether the key expression *node* spells a conversion key: `True`, `False` when it spells
        another key, `None` when it is known only at runtime. A member read named `toPrimitive`
        counts whatever its object, and so does a name destructured from that key.
        """
        node = strip_parens(node)
        if node is None:
            return None
        text = static_string(node)
        if text is not None:
            return text in CONVERSION_KEYS
        if isinstance(node, (JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
            return False
        if isinstance(node, JsMemberExpression):
            key = static_property_key(node)
            if key == 'toPrimitive':
                return True
            if key is not None and self._effects.trusted_intrinsic(node.object) == 'Symbol':
                return False
            return None
        if not isinstance(node, JsIdentifier) or depth >= _NAME_DEPTH:
            return None
        binding = self._model.resolve(node)
        if binding is None:
            return None

        def key_spelled() -> bool | None:
            if _destructured_key(binding) == 'toPrimitive':
                return True
            values, complete = self._model.values_through_calls(binding)
            answers = [self.spells_key(value, depth + 1) for value in values]
            if any(answers):
                return True
            if complete and values and all(answer is False for answer in answers):
                return False
            return None

        return self._remembered(self._keys, binding, None, key_spelled)

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
                if prop.computed:
                    spelled = self.spells_member_key(prop.key, True)
                    if spelled:
                        return True
                    if spelled is None:
                        unknown = True
                    continue
                if _property_key_name(prop) in CONVERSION_KEYS:
                    return True
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
                    and is_member_write_target(member)
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

        return self._remembered(self._sources, binding, None, source_spelled)

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

        return self._remembered(self._may_hold, binding, True, may_hold)

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

        return self._remembered(self._held, binding, None, held)

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
        index and length, and the program spells no `caller`.
        """
        owner = _receiver_owner(node)
        if not isinstance(owner, (JsFunctionDeclaration, JsFunctionExpression)):
            return False
        if owner.generator or owner.is_async:
            return False
        if self._model.spells_caller() or arguments_name_their_function(owner):
            return False
        if references_new_target(owner):
            return False
        method = owner.parent
        if isinstance(method, JsMethodDefinition):
            if method.kind is not JsMethodKind.CONSTRUCTOR:
                return False
            body = method.parent
            cls = body.parent if body is not None else None
            if not isinstance(cls, (JsClassDeclaration, JsClassExpression)):
                return False
            return cls.super_class is None or self._effects.trusted_intrinsic(cls.super_class) in NON_FUNCTION_BUILDERS
        if isinstance(owner, JsFunctionDeclaration):
            if not isinstance(owner.id, JsIdentifier):
                return False
            return self._only_constructed(self._model.binding_of(owner.id))
        if isinstance(owner.id, JsIdentifier):
            own = self._model.binding_of(owner.id)
            if own is not None and not self._only_constructed(own):
                return False
        return self._only_constructed(self._model.name_holding(owner))

    def _only_constructed(self, binding: Binding | None) -> bool:
        """
        Whether every read of the name *binding*, which holds a function, constructs with it, reads
        its `prototype`, is the right of `instanceof`, or is a test; and the function cannot be
        reached another way: the name is neither exported, nor written at entry, nor reached through
        a handed object or by reflection, and no `constructor` property escapes in the program.
        """
        if (
            binding is None
            or binding.exported
            or binding.written_at_entry
            or binding.reachable_through_a_handed_object
        ):
            return False
        if self._constructors_may_escape() or self._model.reflection_can_reach(binding):
            return False
        for read in binding.reads:
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

    def _constructors_may_escape(self) -> bool:
        """
        Whether a constructor may run on a receiver of the program's choice: the program spells
        `"constructor"` in a string, reads a `constructor` property other than to construct with it,
        compare it, or read its name, or destructures one.
        """
        if self._constructors_escape is None:
            self._constructors_escape = any(self._lets_a_constructor_escape(node) for node in self._model.root.walk())
        return self._constructors_escape

    @staticmethod
    def _lets_a_constructor_escape(node: Node) -> bool:
        if isinstance(node, (JsStringLiteral, JsTemplateLiteral, JsBinaryExpression)):
            return static_string(node) == 'constructor'
        if isinstance(node, JsMemberExpression):
            return (
                static_property_key(node) == 'constructor'
                and not is_member_write_target(node)
                and not _constructor_read_is_harmless(node)
            )
        if isinstance(node, JsProperty) and isinstance(node.parent, JsObjectPattern):
            return node.computed or _property_key_name(node) in (None, 'constructor')
        return False

    def _prototype_is_fresh(self, member: JsMemberExpression, depth: int) -> bool:
        """
        Whether `X.prototype` at *member* is the object the language gave the function `X`: `X`
        holds only function or class literals and nothing writes `X.prototype` itself, or `X` is a
        trusted built-in other than `Function`.
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
        if binding.exported or self._model.reflection_can_reach(binding):
            return False
        return all(_is_direct_callee(read) or read_is_only_tested(read) for read in binding.reads)

    def _installer_alias(self, member: JsMemberExpression) -> Binding | None:
        """
        The name the installer read *member* is stored into, when it is that name's one value and
        every read of the name calls or tests it.
        """
        store = member.parent
        while isinstance(store, JsParenthesizedExpression):
            store = store.parent
        if not isinstance(store, (JsVariableDeclarator, JsAssignmentExpression)):
            return None
        alias = self._model.name_holding(member)
        if alias is None:
            return None
        values, complete = self._model.binding_values(alias)
        if not complete or len(values) != 1 or strip_parens(values[0]) is not member:
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

    def _collect_installer_aliases(self) -> dict[Binding, str]:
        aliases: dict[Binding, str] = {}
        for node in self._model.root.walk():
            if isinstance(node, JsMemberExpression):
                key = self._installer_key(node)
                if key is None or _is_direct_callee(node):
                    continue
                alias = self._installer_alias(node)
            elif isinstance(node, JsProperty) and isinstance(node.parent, JsObjectPattern):
                key = _property_key_name(node)
                if key is None or key not in CONVERSION_INSTALL_METHODS:
                    continue
                alias = self._pattern_alias(node)
            else:
                continue
            if alias is not None:
                aliases[alias] = key
        return aliases

    def _is_copy_write(self, member: JsMemberExpression) -> bool:
        """
        Whether the write through *member* stores a read of another object under the same key:
        `d[k] = s[k]`.
        """
        store = enclosing_operator(member)
        if not isinstance(store, JsAssignmentExpression) or strip_parens(store.left) is not member:
            return False
        key = strip_parens(member.property)
        value = strip_parens(store.right)
        if not member.computed or not isinstance(key, JsIdentifier):
            return False
        if not isinstance(value, JsMemberExpression) or not value.computed:
            return False
        other = strip_parens(value.property)
        return isinstance(other, JsIdentifier) and self._model.resolve(other) is self._model.resolve(key)

    def _gives_an_own_conversion(self, node: Node) -> bool:
        """
        Whether *node* gives some object an own conversion method a copy could carry: an object
        literal's or a class field's key, a member write, or an install spelling a conversion key.
        """
        if isinstance(node, JsProperty) and isinstance(node.parent, JsObjectExpression):
            if node.computed:
                return self.spells_member_key(node.key, True) is True
            return _property_key_name(node) in CONVERSION_KEYS
        if isinstance(node, JsPropertyDefinition):
            return self.spells_member_key(node.key, node.computed) is True
        if isinstance(node, JsMemberExpression) and is_member_write_target(node):
            return self.spells_member_key(node.property, node.computed) is True
        if isinstance(node, JsCallExpression):
            installer = self.installer_of_call(node)
            return installer is not None and any(
                self.install_spelled(node, installer, target) is True for target in (-1, 0, 3)
            )
        return False

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
        if self._model.has_reflection_surface():
            return None
        sites: list[Node | None] = []
        copies: list[Node | None] = []
        carrier = False
        for node in self._model.root.walk():
            if not carrier and self._gives_an_own_conversion(node):
                carrier = True
            if isinstance(node, JsIdentifier):
                if self._reads_reflect_as_a_value(node):
                    return None
            elif isinstance(node, JsMemberExpression):
                if is_member_write_target(node):
                    governor = enclosing_operator(node)
                    if isinstance(governor, JsUnaryExpression) and governor.operator == 'delete':
                        continue
                    spelled = self.spells_member_key(node.property, node.computed)
                    if spelled is True and self._may_hold_function(node.object):
                        sites.append(node.object)
                    elif spelled is None and self._is_copy_write(node) and self._may_hold_function(node.object):
                        copies.append(node.object)
                elif static_property_key(node) == 'Reflect':
                    if not read_is_only_tested(node):
                        return None
                elif self._installer_key(node) is not None:
                    if not _is_direct_callee(node) and not read_is_only_tested(node) and self._installer_alias(node) is None:
                        return None
            elif isinstance(node, JsProperty) and isinstance(node.parent, JsObjectPattern):
                if _property_key_name(node) in CONVERSION_INSTALL_METHODS and self._pattern_alias(node) is None:
                    return None
            elif isinstance(node, JsCallExpression):
                self._collect_install_sites(node, sites, copies)
        if carrier:
            sites.extend(copies)
        return self._union_of_held(sites, 0)

    def _collect_install_sites(
        self,
        call: JsCallExpression,
        sites: list[Node | None],
        copies: list[Node | None],
    ) -> None:
        installer = self.installer_of_call(call)
        if installer is None:
            return
        arguments = call.arguments
        if installer in RECEIVER_INSTALL_METHODS:
            callee = strip_parens(call.callee)
            if not isinstance(callee, JsMemberExpression):
                return
            receiver = callee.object
            if self._may_hold_function(receiver) and self.install_spelled(call, installer, -1) is True:
                sites.append(receiver)
            return
        for target in (0, 3) if installer == 'Reflect.set' else (0,):
            if target < len(arguments) and self._may_hold_function(arguments[target]):
                if self.install_spelled(call, installer, target) is True:
                    sites.append(arguments[target])
        if (
            installer in ('assign', 'defineProperties')
            and arguments
            and self._may_hold_function(arguments[0])
            and self.install_spelled(call, installer, 0) is None
        ):
            copies.append(arguments[0])

    @staticmethod
    def _remembered(memo: dict[Binding, _T], binding: Binding, unknown: _T, compute: Callable[[], _T]) -> _T:
        """
        The answer *compute* gives for *binding*, remembered in *memo*. A question about the binding
        asked while its answer is being computed, through a cycle of names, is answered *unknown*.
        """
        if binding in memo:
            return memo[binding]
        memo[binding] = unknown
        answer = memo[binding] = compute()
        return answer
