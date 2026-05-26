"""
Resolves string concealment using the Scramble cipher. Scramble uses PBKDF2 key derivation
followed by multiple rounds of a permutation-based substitution cipher with CBC-like chaining.
Detection is structural: a class whose constructor calls pbkdf2Sync with 'sha256', assigns
this.masterKey and this.rounds, and exposes a decode method.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from typing import NamedTuple, Sequence

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    make_string_literal,
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
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsThisExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)

_DEFAULT_ROUNDS = 3
_DEFAULT_ITERATIONS = 200000


class _PRNG:
    __slots__ = ('_seeded', '_counter', '_buf', '_offset')

    def __init__(self, key: bytes):
        self._seeded = hashlib.sha256(key)
        self._counter = 0
        self._buf = b''
        self._offset = 0

    def _refill(self):
        h = self._seeded.copy()
        h.update(struct.pack('>Q', self._counter))
        self._counter += 1
        self._buf = h.digest()
        self._offset = 0

    def next_byte(self) -> int:
        if self._offset >= len(self._buf):
            self._refill()
        b = self._buf[self._offset]
        self._offset += 1
        return b

    def next_u32(self) -> int:
        return (
            (self.next_byte() << 24)
            | (self.next_byte() << 16)
            | (self.next_byte() << 8)
            | self.next_byte()
        ) & 0xFFFFFFFF


def _generate_inverse_permutation(seed: bytes) -> bytes:
    prng = _PRNG(seed)
    table = bytearray(range(256))
    for n in range(255, 0, -1):
        threshold = 0xFFFFFFFF - (0xFFFFFFFF % (n + 1))
        while True:
            rand = prng.next_u32()
            if rand <= threshold:
                break
        j = rand % (n + 1)
        table[n], table[j] = table[j], table[n]
    inv = bytearray(256)
    for i, v in enumerate(table):
        inv[v] = i
    return bytes(inv)


def _decrypt_round(data: bytes, key: bytes, round_idx: int) -> bytes:
    result = bytearray(len(data))
    prev = 0
    round_seeded = hashlib.sha256(key + b'%c' % round_idx)
    for i, byte in enumerate(data):
        h = round_seeded.copy()
        h.update(str(i).encode())
        inv = _generate_inverse_permutation(h.digest())
        result[i] = inv[byte] ^ prev
        prev = byte
    return bytes(result)


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
    body: JsClassBody | None = getattr(node, 'body', None)
    if body is None:
        return False
    has_decode = False
    has_pbkdf2 = False
    for method in body.body:
        if not isinstance(method, JsMethodDefinition):
            continue
        name = _method_name(method)
        if name == 'decode':
            has_decode = True
        elif name == 'constructor':
            has_pbkdf2 = _constructor_has_pbkdf2(method)
    return has_decode and has_pbkdf2


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


def _extract_constructor_params(method: JsMethodDefinition) -> tuple[int, int]:
    fn = method.value
    rounds = _DEFAULT_ROUNDS
    iterations = _DEFAULT_ITERATIONS
    if fn is None or fn.body is None:
        return rounds, iterations
    for node in fn.body.walk():
        if not isinstance(node, JsAssignmentExpression):
            continue
        if _is_this_member(node.left, 'rounds'):
            if isinstance(node.right, JsNumericLiteral) and isinstance(node.right.value, int):
                rounds = node.right.value
        elif _is_this_member(node.left, 'masterKey'):
            if not isinstance(node.right, JsCallExpression) or len(node.right.arguments) < 5:
                continue
            iters_arg = node.right.arguments[2]
            if isinstance(iters_arg, JsNumericLiteral) and isinstance(iters_arg.value, int):
                iterations = iters_arg.value
    return rounds, iterations


def _get_class_params(class_node: JsClassDeclaration) -> tuple[int, int]:
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
        decode_names = self._find_decode_functions(body, instance.name)
        if not decode_names:
            return
        cipher = ScrambleCipher(
            instance.password,
            instance.salt,
            instance.iterations,
            instance.rounds,
        )
        count = self._substitute_calls(node, decode_names, cipher)
        if count > 0:
            self.mark_changed()

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
                rounds, iterations = _get_class_params(class_node)
                return _InstanceInfo(
                    name=decl.id.name,
                    password=password,
                    salt=salt,
                    iterations=iterations,
                    rounds=rounds,
                )
        return None

    def _find_decode_functions(self, body: Sequence[Node], instance_name: str) -> set[str]:
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
        aliases = self._find_aliases(body, names)
        names.update(aliases)
        return names

    def _is_decode_wrapper(
        self, fn: JsFunctionDeclaration | JsFunctionExpression, instance_name: str,
    ) -> bool:
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

    def _find_aliases(self, body: Sequence[Node], known: set[str]) -> set[str]:
        aliases: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, JsExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            if not isinstance(expr.right, JsIdentifier) or expr.right.name not in known:
                continue
            if not isinstance(expr.left, JsIdentifier):
                continue
            aliases.add(expr.left.name)
        return aliases

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
            if not isinstance(arg, JsStringLiteral):
                continue
            try:
                decoded = cipher.decode(arg.value)
            except Exception:
                continue
            _replace_in_parent(node, make_string_literal(decoded))
            count += 1
        return count
