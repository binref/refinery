"""
Resolves string concealment using the Scramble cipher. Scramble uses PBKDF2 key derivation
followed by multiple rounds of a permutation-based substitution cipher with CBC-like chaining.
Detection is structural: a class whose constructor calls pbkdf2Sync with 'sha256', assigns
this.masterKey and this.rounds, and exposes a decode method.
"""
from __future__ import annotations

import base64
import hashlib

from typing import NamedTuple, Sequence

from refinery.lib.fast.scramble import decrypt_round as _decrypt_round
from refinery.lib.scripts import Node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import SemanticModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    make_string_literal,
    names_this_realms_global_object,
    nothing_still_names,
    remove_declarator,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsClassBody,
    JsClassDeclaration,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsMethodDefinition,
    JsMethodKind,
    JsNewExpression,
    JsNumericLiteral,
    JsPropertyDefinition,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsThisExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    wraps_return,
)
from refinery.lib.scripts.js.numbers import exact_integer

_DEFAULT_ROUNDS = 3
_DEFAULT_ITERATIONS = 200000
_MAX_ROUNDS = 64
_MAX_ITERATIONS = 1000000
"""
The largest round and iteration counts a constructor may declare and still describe this cipher.
Both are read out of the program and both buy work directly: an iteration count is spent inside a
single `hashlib.pbkdf2_hmac` call that no timeout in this codebase can interrupt, and a round count
is a loop per decoded string. A sample naming `1e12` iterations is not configuring Scramble, it is
asking for a week of hashing, and taking the number at face value is what turns recognizing the
pattern into that.
"""


class ScrambleCipher:
    __slots__ = ('_master_key', '_rounds')

    def __init__(
        self,
        password: str,
        salt: str,
        iterations: int = _DEFAULT_ITERATIONS,
        rounds: int = _DEFAULT_ROUNDS,
    ):
        self._master_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), iterations, dklen=32,
        )
        self._rounds = rounds

    def decode(self, encoded: str) -> str:
        data = base64.b64decode(encoded)
        nonce = data[:16]
        ciphertext = data[16:]
        round_key = hashlib.sha256(self._master_key + nonce).digest()
        for r in range(self._rounds - 1, -1, -1):
            ciphertext = _decrypt_round(ciphertext, round_key, r)
        return ciphertext.decode('utf-8')


def _method_name(method: JsMethodDefinition) -> str | None:
    if method.kind == JsMethodKind.CONSTRUCTOR:
        return 'constructor'
    if method.key is None:
        return None
    if isinstance(method.key, JsIdentifier) and not method.computed:
        return method.key.name
    if isinstance(method.key, JsStringLiteral):
        return method.key.value
    return None


def _is_scramble_class(node: Node) -> bool:
    """
    Whether *node* is a class an instance of which decodes a string through a key its constructor
    derives. Only members an instance call reaches are read: a static member of either name is
    reached through the class and never through `instance.decode(x)`, and where two members answer
    to one name the later one is the member the instance has. A class with a field that is not
    `static` is declined: the field puts a property on every instance, with or without an
    initializer, and that property may be the `decode` the call reaches or state a method reads.
    """
    body: JsClassBody | None = getattr(node, 'body', None)
    if body is None:
        return False
    decode: JsMethodDefinition | None = None
    constructor: JsMethodDefinition | None = None
    for method in body.body:
        if isinstance(method, JsPropertyDefinition) and not method.is_static:
            return False
        if not isinstance(method, JsMethodDefinition) or method.is_static:
            continue
        name = _method_name(method)
        if name == 'decode' and method.kind is JsMethodKind.METHOD:
            decode = method
        elif name == 'constructor':
            constructor = method
    if decode is None or decode.value is None or wraps_return(decode.value):
        return False
    return constructor is not None and _constructor_has_pbkdf2(constructor)


def _constructor_has_pbkdf2(method: JsMethodDefinition) -> bool:
    fn = method.value
    if fn is None or fn.body is None:
        return False
    for node in fn.body.walk():
        if not isinstance(node, JsAssignmentExpression):
            continue
        if not _is_this_member(node.left, 'masterKey'):
            continue
        call = node.right
        if not isinstance(call, JsCallExpression) or len(call.arguments) < 5:
            continue
        last_arg = call.arguments[-1]
        return isinstance(last_arg, JsStringLiteral) and last_arg.value == 'sha256'
    return False


def _is_this_member(node: Node | None, name: str) -> bool:
    return (
        isinstance(node, JsMemberExpression)
        and isinstance(node.object, JsThisExpression)
        and access_key(node) == name
    )


def _declared_count(node: Node | None, largest: int) -> int | None:
    """
    A repetition count written into the constructor: a positive integer no larger than *largest*, or
    `None` when what is written there is something else. The lower bound is `hashlib.pbkdf2_hmac`'s
    own, which rejects a count below one by raising; the upper bound is what keeps the recognition
    itself bounded, since both counts are spent as work the moment they are believed.
    """
    if not isinstance(node, JsNumericLiteral):
        return None
    count = exact_integer(node.value)
    if count is None or not (1 <= count <= largest):
        return None
    return count


def _extract_constructor_params(method: JsMethodDefinition) -> tuple[int, int] | None:
    """
    The round and iteration counts the constructor configures, or `None` when it writes one this
    pass cannot honour. Refusing is the whole answer there and a default is not: the counts decide
    the key, so decoding with three rounds a class that declares some other number does not fail
    loudly, it prints a plausible string that the program never produces.
    """
    fn = method.value
    rounds = _DEFAULT_ROUNDS
    iterations = _DEFAULT_ITERATIONS
    if fn is None or fn.body is None:
        return rounds, iterations
    for node in fn.body.walk():
        if not isinstance(node, JsAssignmentExpression):
            continue
        if _is_this_member(node.left, 'rounds'):
            declared = _declared_count(node.right, _MAX_ROUNDS)
            if declared is None:
                return None
            rounds = declared
        elif _is_this_member(node.left, 'masterKey'):
            if not isinstance(node.right, JsCallExpression) or len(node.right.arguments) < 5:
                continue
            declared = _declared_count(node.right.arguments[2], _MAX_ITERATIONS)
            if declared is None:
                return None
            iterations = declared
    return rounds, iterations


def _get_class_params(class_node: JsClassDeclaration) -> tuple[int, int] | None:
    if class_node.body is None:
        return _DEFAULT_ROUNDS, _DEFAULT_ITERATIONS
    for method in class_node.body.body:
        if not isinstance(method, JsMethodDefinition):
            continue
        if _method_name(method) == 'constructor':
            return _extract_constructor_params(method)
    return _DEFAULT_ROUNDS, _DEFAULT_ITERATIONS


def _resolve_string(node: Node | None, scope_body: Sequence[Node]) -> str | None:
    if isinstance(node, JsStringLiteral):
        return node.value
    if not isinstance(node, JsIdentifier):
        return None
    name = node.name
    for stmt in scope_body:
        if isinstance(stmt, JsVariableDeclaration):
            for decl in stmt.declarations:
                if (
                    isinstance(decl, JsVariableDeclarator)
                    and isinstance(decl.id, JsIdentifier)
                    and decl.id.name == name
                    and isinstance(decl.init, JsStringLiteral)
                ):
                    return decl.init.value
    return None


class _InstanceInfo(NamedTuple):
    name: str
    password: str
    salt: str
    iterations: int
    rounds: int


class JsScrambleStringDecoder(ScriptLevelTransformer):
    """
    Detects Scramble cipher infrastructure, decrypts all encoded strings in Python, and replaces
    call sites with the decoded string literals.
    """

    def _process_script(self, node: JsScript) -> None:
        body = node.body
        class_node = self._find_scramble_class(body)
        if class_node is None or class_node.id is None:
            return
        instance = self._find_instance(body, class_node.id.name, class_node)
        if instance is None:
            return
        model = model_cache(self, node).model
        decode_names = self._find_decode_functions(model, body, instance.name)
        if not decode_names:
            return
        cipher = ScrambleCipher(
            instance.password,
            instance.salt,
            instance.iterations,
            instance.rounds,
        )
        count = self._substitute_calls(node, decode_names, cipher)
        if count <= 0:
            return
        self.mark_changed()
        self._remove_infrastructure(node, body, class_node, instance, decode_names)

    def _find_scramble_class(self, body: Sequence[Node]) -> JsClassDeclaration | None:
        for stmt in body:
            if (
                isinstance(stmt, JsClassDeclaration)
                and _is_scramble_class(stmt)
                and stmt.id is not None
                and isinstance(stmt.id, JsIdentifier)
            ):
                return stmt
        return None

    def _find_instance(
        self, body: Sequence[Node], class_name: str, class_node: JsClassDeclaration,
    ) -> _InstanceInfo | None:
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in stmt.declarations:
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                init = decl.init
                if not isinstance(init, JsNewExpression):
                    continue
                if not isinstance(init.callee, JsIdentifier):
                    continue
                if init.callee.name != class_name:
                    continue
                if len(init.arguments) < 2:
                    continue
                password = _resolve_string(init.arguments[0], body)
                salt = _resolve_string(init.arguments[1], body)
                if password is None or salt is None:
                    continue
                params = _get_class_params(class_node)
                if params is None:
                    continue
                rounds, iterations = params
                return _InstanceInfo(
                    name=decl.id.name,
                    password=password,
                    salt=salt,
                    iterations=iterations,
                    rounds=rounds,
                )
        return None

    def _find_decode_functions(
        self, model: SemanticModel, body: Sequence[Node], instance_name: str,
    ) -> set[str]:
        names: set[str] = set()
        for stmt in body:
            if isinstance(stmt, JsFunctionDeclaration):
                if self._is_decode_wrapper(stmt, instance_name) and stmt.id is not None:
                    names.add(stmt.id.name)
            elif isinstance(stmt, JsVariableDeclaration):
                for decl in stmt.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    if not isinstance(decl.init, JsFunctionExpression):
                        continue
                    if self._is_decode_wrapper(decl.init, instance_name):
                        names.add(decl.id.name)
        aliases = self._find_aliases(model, body, names)
        names.update(aliases)
        return names

    def _is_decode_wrapper(
        self, fn: JsFunctionDeclaration | JsFunctionExpression, instance_name: str,
    ) -> bool:
        if wraps_return(fn):
            return False
        if fn.body is None or len(fn.body.body) != 1:
            return False
        stmt = fn.body.body[0]
        if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
            return False
        call = stmt.argument
        if not isinstance(call, JsCallExpression):
            return False
        callee = call.callee
        return (
            isinstance(callee, JsMemberExpression)
            and isinstance(callee.object, JsIdentifier)
            and callee.object.name == instance_name
            and access_key(callee) == 'decode'
        )

    def _find_aliases(
        self, model: SemanticModel, body: Sequence[Node], known: set[str],
    ) -> set[str]:
        aliases: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, JsExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            if not isinstance(expr.right, JsIdentifier) or expr.right.name not in known:
                continue
            if isinstance(expr.left, JsIdentifier):
                aliases.add(expr.left.name)
            elif isinstance(expr.left, JsMemberExpression):
                name = self._resolve_global_property_name(model, expr.left, body)
                if name is not None:
                    aliases.add(name)
        return aliases

    @staticmethod
    def _resolve_global_property_name(
        model: SemanticModel, member: JsMemberExpression, body: Sequence[Node],
    ) -> str | None:
        """
        The global name *member* installs the decoder under, or `None` where it installs nothing:
        the base has to denote this realm's global object where it stands, which a declaration of
        the alias name takes away. A `self.d = decode` beneath a `var self = {}` puts the decoder on
        an ordinary object a later `self.d(...)` reads back, and taking it for a global installation
        deletes machinery that call still needs.
        """
        if not names_this_realms_global_object(model, member.object):
            return None
        key = access_key(member)
        if key is not None:
            return key
        if member.computed and isinstance(member.property, JsIdentifier):
            return _resolve_string(member.property, body)
        return None

    def _substitute_calls(
        self, root: Node, decode_names: set[str], cipher: ScrambleCipher,
    ) -> int:
        count = 0
        for node in list(root.walk()):
            if not isinstance(node, JsCallExpression):
                continue
            if not isinstance(node.callee, JsIdentifier):
                continue
            if node.callee.name not in decode_names:
                continue
            if len(node.arguments) != 1:
                continue
            arg = node.arguments[0]
            if not isinstance(arg, JsStringLiteral) or arg.value is None:
                continue
            try:
                decoded = cipher.decode(arg.value)
            except Exception:
                continue
            _replace_in_parent(node, make_string_literal(decoded))
            count += 1
        return count

    def _remove_infrastructure(
        self,
        root: JsScript,
        body: Sequence[Node],
        class_node: JsClassDeclaration,
        instance: _InstanceInfo,
        decode_names: set[str],
    ) -> None:
        """
        Delete the cipher class, the instance it is constructed into, and every decode function and
        alias that reaches it — but only once nothing outside them names any of it. A call whose
        argument the pass could not read is left standing, and deleting the function that call names
        would hand back a program throwing where it ran.
        """
        model = model_cache(self, root).model
        removals: list[Node] = [class_node]
        declarator_removals: list[JsVariableDeclarator] = []
        global_name_vars: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, JsExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            if not isinstance(expr.left, JsMemberExpression):
                continue
            if not isinstance(expr.right, JsIdentifier) or expr.right.name not in decode_names:
                continue
            name = self._resolve_global_property_name(model, expr.left, body)
            if name is not None and name in decode_names:
                removals.append(stmt)
                if isinstance(expr.left.property, JsIdentifier) and expr.left.computed:
                    global_name_vars.add(expr.left.property.name)
        for stmt in body:
            if isinstance(stmt, JsVariableDeclaration):
                for decl in stmt.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    if decl.id.name == instance.name or decl.id.name in decode_names:
                        declarator_removals.append(decl)
                    elif decl.id.name in global_name_vars:
                        declarator_removals.append(decl)
            elif isinstance(stmt, JsFunctionDeclaration):
                if stmt.id is not None and stmt.id.name in decode_names:
                    removals.append(stmt)
            elif isinstance(stmt, JsExpressionStatement):
                expr = stmt.expression
                if (
                    isinstance(expr, JsAssignmentExpression)
                    and expr.operator == '='
                    and isinstance(expr.left, JsIdentifier)
                    and expr.left.name in decode_names
                ):
                    removals.append(stmt)
        if not nothing_still_names(model, [*removals, *declarator_removals]):
            return
        for decl in declarator_removals:
            remove_declarator(decl)
        for stmt in removals:
            _remove_from_parent(stmt)
