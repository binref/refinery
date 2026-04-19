"""
PowerShell SecureString decryption transformer.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _get_command_name,
    _make_string_literal,
)
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayLiteral,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1StringLiteral,
)


def _collect_key_bytes(node) -> bytes | None:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return _collect_key_bytes(node.expression)
    if isinstance(node, Ps1RangeExpression):
        if isinstance(node.start, Ps1IntegerLiteral) and isinstance(node.end, Ps1IntegerLiteral):
            a = node.start.value
            b = node.end.value
            r = range(min(a, b), max(a, b) + 1)
            if a > b:
                r = reversed(r)
            try:
                return bytes(bytearray(r))
            except (ValueError, OverflowError):
                return None
    if isinstance(node, Ps1ArrayLiteral):
        values = []
        for elem in node.elements:
            if not isinstance(elem, Ps1IntegerLiteral):
                return None
            values.append(elem.value)
        try:
            return bytes(bytearray(values))
        except (ValueError, OverflowError):
            return None
    return None


def _find_key_argument(cmd: Ps1CommandInvocation) -> bytes | None:
    for arg in cmd.arguments:
        if not isinstance(arg, Ps1CommandArgument):
            continue
        if arg.kind == Ps1CommandArgumentKind.NAMED:
            if arg.name.lower().startswith('ke') and arg.value is not None:
                return _collect_key_bytes(arg.value)
    for i, arg in enumerate(cmd.arguments):
        if not isinstance(arg, Ps1CommandArgument):
            continue
        if arg.kind != Ps1CommandArgumentKind.SWITCH:
            continue
        if not arg.name.lower().startswith('ke'):
            continue
        if i + 1 < len(cmd.arguments):
            next_arg = cmd.arguments[i + 1]
            if isinstance(next_arg, Ps1CommandArgument):
                if next_arg.kind == Ps1CommandArgumentKind.POSITIONAL and next_arg.value is not None:
                    return _collect_key_bytes(next_arg.value)
    return None


class Ps1SecureStringDecryptor(Transformer):

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        if len(node.elements) < 2:
            return None
        k = 0
        while k < len(node.elements) - 1:
            lhs = node.elements[k]
            rhs = node.elements[k + 1]
            if not isinstance(lhs.expression, Ps1StringLiteral):
                k += 1
                continue
            if not isinstance(rhs.expression, Ps1CommandInvocation):
                k += 1
                continue
            cmd = rhs.expression
            cmd_name = _get_command_name(cmd)
            if cmd_name is None or cmd_name.lower() != 'convertto-securestring':
                k += 1
                continue
            ciphertext = lhs.expression.value
            key = _find_key_argument(cmd)
            if key is None:
                k += 1
                continue
            try:
                from refinery.units.crypto.cipher.secstr import secstr
                unit = secstr(key=key)
                decrypted = unit(ciphertext.encode('utf-8'))
                plaintext = bytes(decrypted).decode('utf-8')
            except Exception:
                k += 1
                continue
            replacement = _make_string_literal(plaintext)
            new_element = Ps1PipelineElement(expression=replacement)
            new_element.parent = node
            replacement.parent = new_element
            node.elements = node.elements[:k] + [new_element] + node.elements[k + 2:]
            self.mark_changed()
        return None
