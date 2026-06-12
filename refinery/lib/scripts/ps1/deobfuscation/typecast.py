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

_INTEGER_TYPE_BOUNDS = {
    'byte'   : (0, 0xFF),
    'int'    : (-0x80000000, 0x7FFFFFFF),
    'int16'  : (-0x8000, 0x7FFF),
    'int32'  : (-0x80000000, 0x7FFFFFFF),
    'int64'  : (-0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
    'long'   : (-0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
    'sbyte'  : (-0x80, 0x7F),
    'short'  : (-0x8000, 0x7FFF),
    'uint16' : (0, 0xFFFF),
    'uint32' : (0, 0xFFFFFFFF),
    'uint64' : (0, 0xFFFFFFFFFFFFFFFF),
    'ushort' : (0, 0xFFFF),
}


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
        return self.visit_Ps1CastExpression(cast) or cast

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        tn = normalize_dotnet_type_name(node.type_name)
        if tn == 'string':
            if node.operand and string_value(node.operand) is not None:
                return node.operand
            if node.operand is not None:
                inner = unwrap_single_paren(node.operand)
                parts = collect_string_arguments(inner)
                if parts is not None and len(parts) > 1:
                    return make_string_literal(' '.join(parts))
        bounds = _INTEGER_TYPE_BOUNDS.get(tn)
        if bounds is not None:
            lo, hi = bounds
            result = unwrap_integer(node.operand)
            if result is not None:
                if lo <= result.value <= hi:
                    return Ps1IntegerLiteral(value=result.value, raw=str(result.value))
            else:
                sv = string_value(node.operand) if node.operand else None
                if sv is not None:
                    sv = sv.strip()
                    try:
                        value = int(sv, 0)
                    except (ValueError, OverflowError):
                        value = None
                    if value is not None and lo <= value <= hi:
                        return Ps1IntegerLiteral(value=value, raw=str(value))
        if tn == 'char':
            result = unwrap_integer(node.operand)
            if result is not None and 0 <= result.value <= 0xFFFF:
                return make_string_literal(chr(result.value))
            return None
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
