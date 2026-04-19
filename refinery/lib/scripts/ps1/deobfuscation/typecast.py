"""
PowerShell type cast simplification transforms.
"""
from __future__ import annotations

import string

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    collect_int_arguments,
    collect_string_arguments,
    make_string_literal,
    normalize_dotnet_type_name,
    string_value,
    unwrap_integer,
    unwrap_single_paren,
)
from refinery.lib.scripts.ps1.model import (
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1IntegerLiteral,
    Ps1TypeExpression,
)

_INTEGER_TYPE_NAMES = frozenset({
    'byte',
    'int',
    'int16',
    'int32',
    'int64',
    'long',
    'sbyte',
    'short',
    'uint16',
    'uint32',
    'uint64',
    'ushort',
})


class Ps1TypeCasts(Transformer):

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        if node.operator.lower() != '-as':
            return None
        if not isinstance(node.right, Ps1TypeExpression):
            return None
        cast = Ps1CastExpression(
            offset=node.offset,
            type_name=node.right.name,
            operand=node.left,
        )
        return self.visit_Ps1CastExpression(cast)

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        tn = normalize_dotnet_type_name(node.type_name)
        if tn in ('string', 'char[]'):
            if node.operand and string_value(node.operand) is not None:
                return node.operand
        if tn == 'string':
            if node.operand is not None:
                inner = unwrap_single_paren(node.operand)
                parts = collect_string_arguments(inner)
                if parts is not None and len(parts) > 1:
                    return make_string_literal(' '.join(parts))
        if tn in _INTEGER_TYPE_NAMES:
            result = unwrap_integer(node.operand)
            if result is not None:
                return Ps1IntegerLiteral(value=result.value, raw=str(result.value))
        if tn == 'char':
            result = unwrap_integer(node.operand)
            if result is not None:
                if result.value == 0:
                    return make_string_literal('')
                try:
                    ch = chr(result.value)
                except (ValueError, OverflowError):
                    return None
                return make_string_literal(ch)
        if tn == 'char[]':
            if node.operand is not None:
                inner = unwrap_single_paren(node.operand)
                int_values = collect_int_arguments(inner)
                if int_values is not None:
                    try:
                        result_bytes = bytes(int_values)
                        result = result_bytes.decode('ascii')
                        if not all(c in string.printable or c.isspace() for c in result):
                            return None
                    except (ValueError, UnicodeDecodeError, OverflowError):
                        return None
                    return make_string_literal(result)
        if tn == 'type':
            sv = string_value(node.operand) if node.operand else None
            if sv is not None:
                return Ps1TypeExpression(offset=node.offset, name=sv)
        return None
