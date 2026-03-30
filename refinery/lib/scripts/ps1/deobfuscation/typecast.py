"""
PowerShell type cast simplification transforms.
"""
from __future__ import annotations

import string

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _collect_int_arguments,
    _make_string_literal,
    _string_value,
    _unwrap_paren_to_array,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CastExpression,
    Ps1IntegerLiteral,
)


class Ps1TypeCasts(Transformer):

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        tn = node.type_name.lower().replace(' ', '')
        if tn in ('string', 'char[]'):
            if node.operand and _string_value(node.operand) is not None:
                return node.operand
        if tn == 'char':
            if isinstance(node.operand, Ps1IntegerLiteral):
                try:
                    ch = chr(node.operand.value)
                except (ValueError, OverflowError):
                    return None
                return _make_string_literal(ch)
        if tn == 'char[]':
            if node.operand is not None:
                inner = _unwrap_paren_to_array(node.operand)
                int_values = _collect_int_arguments(inner)
                if int_values is not None:
                    try:
                        result_bytes = bytes(int_values)
                        result = result_bytes.decode('ascii')
                        if not all(c in string.printable or c.isspace() for c in result):
                            return None
                    except (ValueError, UnicodeDecodeError, OverflowError):
                        return None
                    return _make_string_literal(result)
        return None
