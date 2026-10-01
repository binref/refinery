"""
Fold the two self-checks an obfuscator inserts that read the source text of a function.

The line-break check tests a function's text for a line break. The obfuscator writes its whole
output on one line, so the check never trips on its input, while a deobfuscation that prints the
function over several lines makes it trip:

    var N = function () {
        const T = function () { const R = new RegExp('\\n'); return R.test(N); };
        if (T()) { while (true) {} }
    };

The hash guard runs a copy `G` of a function only while a hash of `G`'s text, with spaces, line
breaks and `;,{}().[]` removed, equals a constant. Any rewrite of `G` changes the hash:

    function F() {
        var h = F.P || (F.P = HASH(G, 7878154));
        if (h === 3355300757180592) { return G(...arguments); } else { while (true) {} }
    }

`HASH` is the public cyrb53 hash. An older form hashes `TEXT(G)`, the text with a separate helper,
and wraps the whole program in one such guard.

Both checks are decided on the text the parser kept for the function, which is what the engine
answers for it as long as the program gave the function no property of its own
(`refinery.lib.scripts.js.analysis.effects.EffectModel.function_object_untouched`) and the
prototypes it reads are the built-ins. A hash helper is recognized only where it equals its template
up to the changes other transforms make, so the hash computed here is the one the file computes.
"""
from __future__ import annotations

import functools
import re

from typing import Callable, Iterator, NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    _clone_node,
    _replace_in_parent,
    canonical,
    set_child,
    set_child_list,
    set_value,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    build_semantic_model,
    enclosing_operator,
    is_constructed_or_invoked,
    is_invocation_target,
    statement_list_of,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_MEMBERS,
    ScriptLevelTransformer,
    remove_declarator,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsDoWhileStatement,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
    static_property_key,
    static_string,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.numbers import exact_integer
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.utf16 import to_code_units

_STRIPPED_PATTERN = r' |\n|;|,|\{|\}|\(|\)|\.|\[|\]'
"""
The regular expression every hash helper removes from a function's text before hashing it.
"""


class _Template(NamedTuple):
    """
    A helper as the obfuscator writes it, and the free names in its text that stand for the other
    helpers it calls.
    """
    text: str
    placeholders: frozenset[str] = frozenset()


_HASH_TEMPLATE = _Template(
    'function HASH(str, seed) {'
    ' var h1 = 0xdeadbeef ^ seed; var h2 = 0x41c6ce57 ^ seed;'
    ' for (var i = 0, ch; i < str.length; i++) {'
    ' ch = str.charCodeAt(i); h1 = IMUL(h1 ^ ch, 2654435761); h2 = IMUL(h2 ^ ch, 1597334677); }'
    ' h1 = IMUL(h1 ^ (h1 >>> 16), 2246822507) ^ IMUL(h2 ^ (h2 >>> 13), 3266489909);'
    ' h2 = IMUL(h2 ^ (h2 >>> 16), 2246822507) ^ IMUL(h1 ^ (h1 >>> 13), 3266489909);'
    ' return 4294967296 * (2097151 & h2) + (h1 >>> 0); }',
    frozenset({'IMUL'}),
)
"""
The cyrb53 hash as the obfuscator writes it, `IMUL` standing for its 32-bit multiplication.
"""

_TEXT_HASH_TEMPLATE = _Template(
    'function TEXTHASH(fnObject, seed, regex = new RegExp("'
    + _STRIPPED_PATTERN.replace('\\', '\\\\')
    + '", "g")) { var fnStringed = fnObject.toString().replace(regex, ""); return HASH(fnStringed, seed); }',
    frozenset({'HASH'}),
)
"""
The helper that hashes a function's stripped text, `HASH` standing for `_HASH_TEMPLATE`.
"""

_TEXT_TEMPLATE = _Template(F'function TEXT(x) {{ return x.toString().replace(/{_STRIPPED_PATTERN}/g, ""); }}')
"""
The older helper that strips a function's text, for the older hash guard to hash with
`_HASH_TEMPLATE`.
"""

_POLYFILL_TEMPLATE = _Template(
    'function POLYFILL(opA, opB) { opB |= 0; var result = (opA & 0x003fffff) * opB;'
    ' if (opA & 0xffc00000) { result += (opA & 0xffc00000) * opB | 0; } return result | 0; }'
)
"""
The 32-bit multiplication the obfuscator falls back to where `Math.imul` is missing.
"""

_LOOPS = (
    JsWhileStatement,
    JsDoWhileStatement,
    JsForStatement,
    JsForInStatement,
    JsForOfStatement,
)


def _integer(node: Node | None) -> int | None:
    """
    The value of the numeric literal *node* when it is a finite integer.
    """
    node = strip_parens(node)
    return exact_integer(node.value) if isinstance(node, JsNumericLiteral) else None


class _Shape(NamedTuple):
    """
    The normal form of a function: whether it is a generator, whether it is `async`, and the
    canonical forms of its parameters and of its body.
    """
    generator: bool
    is_async: bool
    params: tuple[object, ...]
    body: object


class _NormalForm:
    """
    The form a function is compared to a template in. Its own names are renamed in the order they
    appear, a name of an outer helper the template refers to becomes that helper's placeholder,
    parentheses go, a computed key that is a fixed name becomes a dotted one, the body of an `if`
    or a loop becomes a block, a `var` or `let` declaration becomes the assignments it makes, and a
    sequence or a call of an empty function in statement position becomes one statement per
    operand. Those are the changes minifying, moving declarations and the other transforms of the
    obfuscator make to a helper.
    """

    def __init__(self, model: SemanticModel, placeholders: dict[int, str], empty: set[int]):
        self.model = model
        self.placeholders = placeholders
        self.empty = empty

    def of(self, function: JsFunctionNode) -> _Shape | None:
        renames: dict[int, str] = {}
        own: dict[int, str] = {}
        for node in function.walk():
            if not isinstance(node, JsIdentifier):
                continue
            binding = self.model.resolve(node) or self.model.binding_of(node)
            if binding is None:
                if self.model.is_reference(node):
                    renames[id(node)] = F'#free:{node.name}'
                continue
            if id(binding) in self.placeholders:
                renames[id(node)] = self.placeholders[id(binding)]
            elif id(binding) in self.empty:
                renames[id(node)] = '#empty'
            elif binding.scope.node is function or binding.scope.node.is_descendant_of(function):
                renames[id(node)] = own.setdefault(id(binding), F'#v{len(own)}')
            else:
                renames[id(node)] = '#outer'
        clone = _clone_node(function)
        for original, copy in zip(function.walk(), clone.walk()):
            if type(original) is not type(copy):
                return None
            if id(original) in renames:
                set_value(copy, 'name', renames[id(original)])
        self._normalize(clone)
        return _Shape(
            bool(getattr(clone, 'generator', False)),
            bool(getattr(clone, 'is_async', False)),
            tuple(canonical(parameter) for parameter in clone.params),
            None if clone.body is None else canonical(clone.body),
        )

    def _normalize(self, root: Node) -> None:
        for node in list(root.walk()):
            if isinstance(node, JsParenthesizedExpression) and node.expression is not None:
                _replace_in_parent(node, node.expression)
        for node in list(root.walk()):
            if isinstance(node, JsMemberExpression) and node.computed:
                key = static_property_key(node)
                if key is not None and key.isidentifier():
                    set_value(node, 'computed', False)
                    set_child(node, 'property', JsIdentifier(name=key))
            if isinstance(node, (JsIfStatement, *_LOOPS)):
                for field in ('consequent', 'alternate', 'body'):
                    child = getattr(node, field, None)
                    if child is not None and not isinstance(child, JsBlockStatement):
                        block = JsBlockStatement()
                        set_child(node, field, block)
                        set_child_list(block, 'body', [child])
        for node in list(root.walk()):
            if isinstance(node, JsForStatement) and isinstance(node.init, JsVariableDeclaration):
                assignments = self._assignments(node.init)
                if assignments is None:
                    continue
                if not assignments:
                    set_child(node, 'init', None)
                elif len(assignments) == 1:
                    set_child(node, 'init', assignments[0])
                else:
                    set_child(node, 'init', JsSequenceExpression(expressions=assignments))
        for node in list(root.walk()):
            if not isinstance(node, JsBlockStatement):
                continue
            body: list[Node] = []
            for statement in node.body:
                assignments = None
                if isinstance(statement, JsVariableDeclaration):
                    assignments = self._assignments(statement)
                if assignments is None:
                    body.extend(self._split(statement))
                    continue
                for assignment in assignments:
                    body.extend(self._split(JsExpressionStatement(expression=assignment)))
            set_child_list(node, 'body', body)

    @staticmethod
    def _assignments(declaration: JsVariableDeclaration) -> list[Expression] | None:
        if declaration.kind not in (JsVarKind.VAR, JsVarKind.LET):
            return None
        result: list[Expression] = []
        for declarator in declaration.declarations:
            if not isinstance(declarator.id, JsIdentifier):
                return None
            if declarator.init is None:
                continue
            result.append(JsAssignmentExpression(left=declarator.id, operator='=', right=declarator.init))
        return result

    def _split(self, statement: Node) -> list[Node]:
        if not isinstance(statement, JsExpressionStatement):
            return [statement]
        expression = statement.expression
        if isinstance(expression, JsSequenceExpression):
            parts = expression.expressions
        elif (
            isinstance(expression, JsCallExpression)
            and isinstance(expression.callee, JsIdentifier)
            and expression.callee.name == '#empty'
        ):
            parts = expression.arguments
        else:
            return [statement]
        result: list[Node] = []
        for part in parts:
            result.extend(self._split(JsExpressionStatement(expression=part)))
        return result


def _rename_free(form: object, names: frozenset[str]) -> object:
    if isinstance(form, tuple):
        return tuple(_rename_free(item, names) for item in form)
    if isinstance(form, str) and form.startswith('#free:') and form[6:] in names:
        return form[6:]
    return form


@functools.lru_cache(maxsize=None)
def _template_form(template: _Template) -> _Shape:
    """
    The normal form of *template*. Each of its placeholders is renamed to itself, which only a call
    of a helper recognized for it takes in the form of a function: a call of a global the program
    never declares keeps its spelling as a free name, so a function calling an undeclared `IMUL`
    does not match the hash.
    """
    script = JsParser(template.text).parse()
    function = script.body[0]
    assert isinstance(function, JsFunctionDeclaration)
    form = _NormalForm(build_semantic_model(script), {}, set()).of(function)
    assert form is not None
    return form._replace(
        params=tuple(_rename_free(parameter, template.placeholders) for parameter in form.params),
        body=_rename_free(form.body, template.placeholders),
    )


def _empty_functions_called(model: SemanticModel, function: Node) -> set[int]:
    """
    The names *function* calls that hold one function with no parameters and an empty body, the
    wrapper the obfuscator puts around a sequence of statements, by the identity of their binding.
    """
    empty: set[int] = set()
    for node in function.walk():
        if not isinstance(node, JsCallExpression) or not isinstance(node.callee, JsIdentifier):
            continue
        binding = model.resolve(node.callee)
        value = None if binding is None else model.singular_value(binding)
        if isinstance(value, FUNCTION_NODES) and not value.params and statement_list_of(value) == []:
            empty.add(id(binding))
    return empty


class _Hashed(NamedTuple):
    """
    A hash call the pass recognized: the name of the function whose text it hashes, the seed, the
    call, and the names holding the helpers it runs.
    """
    subject: JsIdentifier
    seed: int
    call: JsCallExpression
    helpers: tuple[Binding, ...]


class _HelperRecognizer:
    """
    Recognizes the hash helpers of one script, each function once.
    """

    def __init__(self, model: SemanticModel, effects: EffectModel):
        self.model = model
        self.effects = effects
        self.memo: dict[tuple[str, int, bool], bool] = {}

    def function_held_by(self, name: Node | None) -> tuple[Binding | None, JsFunctionNode | None]:
        """
        The binding *name* resolves to and the one function it holds.
        """
        name = strip_parens(name)
        if not isinstance(name, JsIdentifier):
            return None, None
        binding = self.model.resolve(name)
        if binding is None or binding.dynamic_refs or binding.exported:
            return None, None
        value = self.model.singular_value(binding)
        if not isinstance(value, FUNCTION_NODES):
            return None, None
        return binding, value

    def _remembered(self, kind: str, subject: object, es2015: bool, decide: Callable[[], bool]) -> bool:
        key = (kind, id(subject), es2015)
        known = self.memo.get(key)
        if known is None:
            known = self.memo[key] = decide()
        return known

    def _matches(self, function: JsFunctionNode, template: _Template, placeholders: dict[int, str]) -> bool:
        """
        Whether *function* has the normal form of *template*, the names in *placeholders* standing
        for the template's placeholders. A function with another number of parameters is refused
        before its form is built, which costs a copy of the whole function.
        """
        shape = _template_form(template)
        if len(function.params) != len(shape.params):
            return False
        empty = _empty_functions_called(self.model, function)
        return _NormalForm(self.model, placeholders, empty).of(function) == shape

    def _outer_calls(self, function: Node) -> Iterator[tuple[JsCallExpression, Binding]]:
        for node in function.walk():
            if not isinstance(node, JsCallExpression) or not isinstance(node.callee, JsIdentifier):
                continue
            binding = self.model.resolve(node.callee)
            if binding is None:
                continue
            scope = binding.scope.node
            if scope is function or scope.is_descendant_of(function):
                continue
            yield node, binding

    def multiplication(self, binding: Binding, es2015: bool) -> bool:
        """
        Whether *binding* holds `Math.imul` or a fallback the template allows. Under *es2015* the
        engine has `Math.imul`, so the fallback never runs and need not match.
        """
        return self._remembered('imul', binding, es2015, lambda: self._multiplication(binding, es2015))

    def _multiplication(self, binding: Binding, es2015: bool) -> bool:
        if binding.dynamic_refs or binding.exported:
            return False
        value = strip_parens(self.model.singular_value(binding))
        if not isinstance(value, JsLogicalExpression) or value.operator != '||':
            return False
        method = strip_parens(value.left)
        if not isinstance(method, JsMemberExpression) or static_property_key(method) != 'imul':
            return False
        if self.effects.trusted_intrinsic(method.object) != 'Math':
            return False
        fallback = strip_parens(value.right)
        if not isinstance(fallback, FUNCTION_NODES):
            _, fallback = self.function_held_by(fallback)
        if fallback is None:
            return False
        return es2015 or self._matches(fallback, _POLYFILL_TEMPLATE, {})

    def hash(self, function: JsFunctionNode, es2015: bool = False) -> bool:
        """
        Whether *function* is the cyrb53 helper.
        """
        return self._remembered('hash', function, es2015, lambda: self._hash(function, es2015))

    def _hash(self, function: JsFunctionNode, es2015: bool) -> bool:
        placeholders: dict[int, str] = {}
        for _, binding in self._outer_calls(function):
            value = self.model.singular_value(binding)
            if isinstance(value, FUNCTION_NODES) and not value.params and statement_list_of(value) == []:
                continue
            if not self.multiplication(binding, es2015):
                return False
            placeholders[id(binding)] = 'IMUL'
        return self._matches(function, _HASH_TEMPLATE, placeholders) and self.effects.trusted_prototype(str)

    def text_hash(self, function: JsFunctionNode) -> bool:
        """
        Whether *function* is the helper that hashes a function's stripped text.
        """
        return self._remembered('text_hash', function, False, lambda: self._text_hash(function))

    def _text_hash(self, function: JsFunctionNode) -> bool:
        placeholders: dict[int, str] = {}
        for call, binding in self._outer_calls(function):
            _, value = self.function_held_by(call.callee)
            if value is None or not self.hash(value, es2015=True):
                return False
            placeholders[id(binding)] = 'HASH'
        return (
            self._matches(function, _TEXT_HASH_TEMPLATE, placeholders)
            and self.effects.trusted_intrinsic_name('RegExp')
            and self.effects.trusted_prototype(str)
        )

    def text(self, function: JsFunctionNode) -> bool:
        """
        Whether *function* is the older helper that strips a function's text.
        """
        return self._remembered('text', function, False, lambda: self._text(function))

    def _text(self, function: JsFunctionNode) -> bool:
        return (
            self._matches(function, _TEXT_TEMPLATE, {})
            and self.effects.trusted_intrinsic_name('RegExp')
            and self.effects.trusted_prototype(str)
        )

    def hashed(self, call: Node | None) -> _Hashed | None:
        """
        The hash call *call* is, when it runs recognized helpers on one name.
        """
        call = strip_parens(call)
        if not isinstance(call, JsCallExpression) or len(call.arguments) != 2:
            return None
        seed = _integer(call.arguments[1])
        if seed is None:
            return None
        helper_name, helper = self.function_held_by(call.callee)
        if helper_name is None or not isinstance(helper, JsFunctionDeclaration):
            return None
        subject = strip_parens(call.arguments[0])
        if isinstance(subject, JsIdentifier):
            if not self.text_hash(helper):
                return None
            return _Hashed(subject, seed, call, (helper_name,))
        if isinstance(subject, JsCallExpression) and len(subject.arguments) == 1:
            text_name, text = self.function_held_by(subject.callee)
            if text_name is None or text is None or not self.text(text) or not self.hash(helper):
                return None
            name = strip_parens(subject.arguments[0])
            if not isinstance(name, JsIdentifier):
                return None
            return _Hashed(name, seed, call, (helper_name, text_name))
        return None


def _to_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _imul(a: int, b: int) -> int:
    return _to_int32((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))


def cyrb53(text: str, seed: int) -> int:
    """
    The cyrb53 hash of *text* read as UTF-16 code units, as `_HASH_TEMPLATE` computes it.
    """
    h1 = _to_int32(0xDEADBEEF ^ seed)
    h2 = _to_int32(0x41C6CE57 ^ seed)
    for unit in to_code_units(text):
        code = ord(unit)
        h1 = _imul(h1 ^ code, 2654435761)
        h2 = _imul(h2 ^ code, 1597334677)
    h1 = _to_int32(_imul(h1 ^ ((h1 & 0xFFFFFFFF) >> 16), 2246822507) ^ _imul(h2 ^ ((h2 & 0xFFFFFFFF) >> 13), 3266489909))
    h2 = _to_int32(_imul(h2 ^ ((h2 & 0xFFFFFFFF) >> 16), 2246822507) ^ _imul(h1 ^ ((h1 & 0xFFFFFFFF) >> 13), 3266489909))
    return 4294967296 * (2097151 & h2) + (h1 & 0xFFFFFFFF)


def _regexp_statics_observable(model: SemanticModel, root: JsScript) -> bool:
    """
    Whether the program may read the match statics of `RegExp`, such as `RegExp.$1`, which the
    `replace` in a hash helper sets: a reflection surface may, and so may any use of `RegExp` other
    than as the callee of `new RegExp(…)` or `RegExp(…)` or as the tag of a template, which builds
    a regular expression and reads none of them. So may any read of a `constructor`, which reaches
    `RegExp` from every regular expression without naming it: `/x/.constructor.$1`.
    """
    if model.has_reflection_surface() or model.has_opaque_global_write():
        return True
    for node in root.walk():
        if isinstance(node, JsMemberExpression) and static_property_key(node) == 'constructor':
            return True
        if isinstance(node, JsIdentifier):
            if node.name != 'RegExp' or not model.is_reference(node) or model.resolve(node) is not None:
                continue
        elif not isinstance(node, JsMemberExpression) or model.may_name_a_global(node) != 'RegExp':
            continue
        if not is_constructed_or_invoked(node):
            return True
    return False


def _helper_names(model: SemanticModel, function: Node, found: dict[int, Binding]) -> None:
    """
    Every name outside *function* that it calls, and that the functions those names hold call in
    turn, including the fallback a `Math.imul || fallback` name holds: the names a hash call needs
    in place before it runs.
    """
    for node in function.walk():
        if not isinstance(node, JsCallExpression) or not isinstance(node.callee, JsIdentifier):
            continue
        binding = model.resolve(node.callee)
        if binding is None or id(binding) in found:
            continue
        scope = binding.scope.node
        if scope is function or scope.is_descendant_of(function):
            continue
        found[id(binding)] = binding
        value = strip_parens(model.singular_value(binding))
        if isinstance(value, JsLogicalExpression):
            value = strip_parens(value.right)
            if isinstance(value, JsIdentifier):
                fallback = model.resolve(value)
                if fallback is None:
                    continue
                found[id(fallback)] = fallback
                value = model.singular_value(fallback)
        if isinstance(value, FUNCTION_NODES):
            _helper_names(model, value, found)


class JsSelfCheckFolding(ScriptLevelTransformer):
    """
    Fold every line-break check and hash guard the module describes whose answer the input text
    decides: the call of a line-break check becomes `false`, and the test of a hash guard becomes
    `true`. Every other shape is left as it is.
    """

    def _process_script(self, node: JsScript):
        cache = model_cache(self, node)
        model = cache.model
        effects = cache.effects
        dominance = cache.dominance
        folds: list[tuple[Node, bool]] = []
        for function in node.walk():
            if isinstance(function, FUNCTION_NODES):
                calls = self._line_break_checks(model, effects, dominance, function)
                folds.extend((call, False) for call in calls)
        recognizer = _HelperRecognizer(model, effects)
        decided: list[JsVariableDeclarator] = []
        for guard in node.walk():
            if not isinstance(guard, JsIfStatement):
                continue
            declarator = self._decided_hash(model, effects, dominance, recognizer, guard)
            if declarator is not None and guard.test is not None:
                folds.append((guard.test, True))
                decided.append(declarator)
        if not folds:
            return
        statics = bool(decided) and _regexp_statics_observable(model, node)
        for site, value in folds:
            _replace_in_parent(site, JsBooleanLiteral(value=value))
        for declarator in decided:
            declaration = declarator.parent
            if statics and declaration is not None and declarator.init is not None:
                _replace_in_parent(declaration, JsExpressionStatement(expression=declarator.init))
            else:
                remove_declarator(declarator)
        self.mark_changed()

    def _line_break_checks(
        self,
        model: SemanticModel,
        effects: EffectModel,
        dominance: DominanceModel,
        check: JsFunctionNode,
    ) -> list[JsCallExpression]:
        """
        The calls of *check* a line-break check answers `false` for: *check* tests the text of one
        function for a line break, that text has none, and the call runs after *check* is in place.
        """
        subject = self._line_break_subject(model, effects, check)
        if subject is None:
            return []
        binding = model.resolve(subject)
        if binding is None or not binding.is_hoisted or binding.dynamic_refs or binding.exported:
            return []
        value = model.singular_value(binding)
        if not isinstance(value, FUNCTION_NODES) or value.source_text is None or '\n' in value.source_text:
            return []
        if not effects.function_object_untouched(value, (subject,)) or not effects.read_chain_intact(type(value)):
            return []
        declarator = check.parent
        if not isinstance(declarator, JsVariableDeclarator) or not isinstance(declarator.id, JsIdentifier):
            return []
        name = model.binding_of(declarator.id)
        if name is None or model.singular_value(name) is not check:
            return []
        calls = []
        for read in name.reads:
            call = enclosing_operator(read)
            if (
                isinstance(call, JsCallExpression)
                and is_invocation_target(read)
                and not call.arguments
                and dominance.binding_established_before(name, call)
            ):
                calls.append(call)
        return calls

    @staticmethod
    def _line_break_subject(model: SemanticModel, effects: EffectModel, check: JsFunctionNode) -> JsIdentifier | None:
        """
        The name whose text *check* tests for a line break: *check* has no parameters, its call
        answers what its body returns rather than a promise or a generator for it, and its body
        constructs `RegExp` from a line break and returns what its `test` answers for that name,
        through a constant or directly.
        """
        if check.params or wraps_return(check):
            return None
        body = statement_list_of(check)
        if not body or len(body) > 2:
            return None
        last = body[-1]
        if not isinstance(last, JsReturnStatement):
            return None
        test = strip_parens(last.argument)
        if not isinstance(test, JsCallExpression) or test.optional or len(test.arguments) != 1:
            return None
        method = strip_parens(test.callee)
        if not isinstance(method, JsMemberExpression) or method.optional or static_property_key(method) != 'test':
            return None
        subject = strip_parens(test.arguments[0])
        if not isinstance(subject, JsIdentifier):
            return None
        receiver = strip_parens(method.object)
        if len(body) == 2:
            first = body[0]
            if not isinstance(first, JsVariableDeclaration) or len(first.declarations) != 1:
                return None
            declarator = first.declarations[0]
            if not isinstance(receiver, JsIdentifier) or not isinstance(declarator.id, JsIdentifier):
                return None
            binding = model.resolve(receiver)
            if binding is None or binding is not model.binding_of(declarator.id) or len(binding.reads) != 1:
                return None
            if model.singular_value(binding) is not declarator.init:
                return None
            receiver = strip_parens(declarator.init)
        if not isinstance(receiver, JsNewExpression) or len(receiver.arguments) != 1:
            return None
        if effects.trusted_intrinsic(receiver.callee) != 'RegExp':
            return None
        if static_string(receiver.arguments[0]) != '\n':
            return None
        return subject

    def _decided_hash(
        self,
        model: SemanticModel,
        effects: EffectModel,
        dominance: DominanceModel,
        recognizer: _HelperRecognizer,
        guard: JsIfStatement,
    ) -> JsVariableDeclarator | None:
        """
        The declarator of the hash the test of *guard* compares, when that hash equals the constant
        it is compared to. The declaration has to be a statement of its own, which the hash call it
        evaluates can replace, and no importer may read the name it declares.
        """
        test = strip_parens(guard.test)
        if not isinstance(test, JsBinaryExpression) or test.operator not in ('==', '==='):
            return None
        name = strip_parens(test.left)
        expected = _integer(test.right)
        if not isinstance(name, JsIdentifier) or expected is None:
            return None
        binding = model.resolve(name)
        if (
            binding is None
            or binding.reads != [name]
            or binding.writes
            or binding.dynamic_refs
            or binding.exported
            or len(binding.declarations) != 1
        ):
            return None
        declarator = binding.declarations[0].parent
        if not isinstance(declarator, JsVariableDeclarator) or declarator.id is not binding.declarations[0]:
            return None
        declaration = declarator.parent
        if not isinstance(declaration, JsVariableDeclaration) or len(declaration.declarations) != 1:
            return None
        holder = declaration.parent
        if holder is None or not any(statement is declaration for statement in statement_list_of(holder) or ()):
            return None
        hashed = recognizer.hashed(self._hash_call(model, effects, dominance, declarator.init))
        if hashed is None or not dominance.binding_established_before(binding, name):
            return None
        subject_binding, subject = recognizer.function_held_by(hashed.subject)
        if subject_binding is None or subject is None or subject.source_text is None:
            return None
        helpers: dict[int, Binding] = {}
        for helper in hashed.helpers:
            helpers[id(helper)] = helper
            helper_function = model.singular_value(helper)
            if helper_function is not None:
                _helper_names(model, helper_function, helpers)
        helpers[id(subject_binding)] = subject_binding
        if not all(dominance.binding_established_before(helper, hashed.call) for helper in helpers.values()):
            return None
        if not effects.function_object_untouched(subject, (hashed.subject,)):
            return None
        if not effects.read_chain_intact(type(subject)):
            return None
        if cyrb53(re.sub(_STRIPPED_PATTERN, '', subject.source_text), hashed.seed) != expected:
            return None
        return declarator

    @staticmethod
    def _hash_call(
        model: SemanticModel,
        effects: EffectModel,
        dominance: DominanceModel,
        init: Node | None,
    ) -> Node | None:
        """
        The hash call *init* makes: *init* itself, or the call it keeps in a property of the one
        function `F` a name holds, as `F.P || (F.P = call)`. The key `P` has to be one a function
        object does not have before the program writes it: `F.name || …` answers the name, and the
        call never runs.
        """
        init = strip_parens(init)
        if isinstance(init, JsCallExpression):
            return init
        if not isinstance(init, JsLogicalExpression) or init.operator != '||':
            return None
        read = strip_parens(init.left)
        store = strip_parens(init.right)
        if not isinstance(read, JsMemberExpression) or not isinstance(store, JsAssignmentExpression):
            return None
        write = strip_parens(store.left)
        if store.operator != '=' or not isinstance(write, JsMemberExpression) or read.optional:
            return None
        key = static_property_key(read)
        if key is None or key in FUNCTION_MEMBERS or static_property_key(write) != key:
            return None
        owner = strip_parens(read.object)
        other = strip_parens(write.object)
        if not isinstance(owner, JsIdentifier) or not isinstance(other, JsIdentifier):
            return None
        binding = model.resolve(owner)
        if binding is None or binding is not model.resolve(other):
            return None
        value = model.singular_value(binding)
        if not isinstance(value, FUNCTION_NODES) or not dominance.binding_established_before(binding, owner):
            return None
        if not effects.function_object_untouched(value, (owner, other)) or not effects.read_chain_intact(type(value)):
            return None
        return store.right
