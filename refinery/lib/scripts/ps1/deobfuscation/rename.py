"""
Rename obfuscated variable names to short sequential identifiers.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    _PS1_SKIP_VARIABLES,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    assignment_target_variables,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1ForEachLoop,
    Ps1ParameterDeclaration,
    Ps1ScopeModifier,
    Ps1Variable,
)


def _is_obfuscated_name(name: str) -> bool:
    return len(name) > 80


def _is_user_variable(var: Ps1Variable) -> bool:
    if var.scope != Ps1ScopeModifier.NONE:
        return False
    return var.name.lower() not in _PS1_SKIP_VARIABLES


class Ps1VariableRenaming(Transformer):
    """
    Rename obfuscated variable names to short sequential identifiers (var1, var2, ...).
    Only activates when ALL user-defined variables in the script have obfuscated names,
    preventing false positives on legitimate scripts.
    """

    def visit(self, node: Node):
        user_names: set[str] = set()
        for n in node.walk():
            if isinstance(n, Ps1Variable) and _is_user_variable(n):
                user_names.add(n.name.lower())
        if not user_names:
            return None
        if not all(_is_obfuscated_name(name) for name in user_names):
            return None
        mapping: dict[str, str] = {}
        counter = 0
        for n in node.walk_in_order():
            keys: list[str] = []
            if isinstance(n, Ps1AssignmentExpression):
                keys = [
                    var.name.lower()
                    for var in assignment_target_variables(n.target)
                    if _is_user_variable(var)
                ]
            elif isinstance(n, Ps1ForEachLoop):
                if isinstance(n.variable, Ps1Variable) and _is_user_variable(n.variable):
                    keys = [n.variable.name.lower()]
            elif isinstance(n, Ps1ParameterDeclaration):
                if isinstance(n.variable, Ps1Variable) and _is_user_variable(n.variable):
                    keys = [n.variable.name.lower()]
            for key in keys:
                if key not in mapping:
                    counter += 1
                    mapping[key] = F'var{counter}'
        for name in sorted(user_names):
            if name not in mapping:
                counter += 1
                mapping[name] = F'var{counter}'
        for n in node.walk():
            if isinstance(n, Ps1Variable) and _is_user_variable(n):
                key = n.name.lower()
                if key in mapping:
                    n.name = mapping[key]
                    n.braced = False
                    self.mark_changed()
        return None
