"""
Inline command aliases defined via Set-Alias / New-Alias.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    case_normalize_name,
    get_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1StringLiteral,
)

_ALIAS_COMMANDS = frozenset({'set-alias', 'sal', 'new-alias', 'nal'})


def _extract_alias_definition(cmd: Ps1CommandInvocation) -> tuple[str, str] | None:
    """
    Extract `(alias_name, target_command)` from a `Set-Alias` / `New-Alias`
    invocation. Handles:

    - Positional:  `sal aliasName targetCmd`
    - Named:       `Set-Alias -Name aliasName -Value targetCmd`
    - Mixed:       `Set-Alias aliasName -Value targetCmd`
    """
    alias_name: str | None = None
    target_name: str | None = None

    positional: list[str] = []
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind == Ps1CommandArgumentKind.POSITIONAL:
                if arg.value is None:
                    return None
                sv = string_value(arg.value)
                if sv is None:
                    return None
                positional.append(sv)
            elif arg.kind == Ps1CommandArgumentKind.NAMED:
                param = arg.name.lstrip('-').lower()
                if arg.value is None:
                    return None
                sv = string_value(arg.value)
                if sv is None:
                    return None
                if param in ('name', 'n'):
                    alias_name = sv
                elif param in ('value', 'v', 'definition', 'd'):
                    target_name = sv
        else:
            sv = string_value(arg)
            if sv is None:
                return None
            positional.append(sv)

    # Fill in from positional arguments
    if alias_name is None and len(positional) >= 1:
        alias_name = positional[0]
        positional = positional[1:]
    if target_name is None and len(positional) >= 1:
        target_name = positional[0]

    if alias_name is None or target_name is None:
        return None
    return alias_name, target_name


class Ps1AliasInlining(Transformer):
    """
    Replace command invocations that use aliases defined via Set-Alias / sal
    with their target command names.

    Alias definitions are intentionally kept in the AST: IEX inlining may
    parse new code in later iterations that references the same alias, so
    removing the definition prematurely would leave those references
    unresolved.
    """

    def visit(self, node: Node):
        aliases = self._collect_aliases(node)
        if not aliases:
            return None
        self._normalize_definitions(aliases)
        self._substitute(node, aliases)
        return None

    def _collect_aliases(self, root: Node) -> dict[str, tuple[Ps1CommandInvocation, str]]:
        """
        Collect alias definitions. Returns a mapping from `lower(alias_name)`
        to `(definition_cmd_node, target_command_name)`. Only aliases defined
        exactly once are included.
        """
        define_counts: dict[str, int] = {}
        definitions: dict[str, tuple[Ps1CommandInvocation, str]] = {}

        for node in root.walk():
            if not isinstance(node, Ps1CommandInvocation):
                continue
            name = get_command_name(node)
            if name is None or name.lower() not in _ALIAS_COMMANDS:
                continue
            result = _extract_alias_definition(node)
            if result is None:
                continue
            alias_name, target_name = result
            key = alias_name.lower()
            define_counts[key] = define_counts.get(key, 0) + 1
            definitions[key] = (node, target_name)

        return {
            key: val for key, val in definitions.items()
            if define_counts.get(key, 0) == 1
        }

    def _normalize_definitions(
        self,
        aliases: dict[str, tuple[Ps1CommandInvocation, str]],
    ):
        """
        Normalize the target command name inside alias definition arguments.
        """
        for _key, (defn_node, target_name) in aliases.items():
            normalized = case_normalize_name(target_name)
            if normalized == target_name:
                continue
            for arg in defn_node.arguments:
                literal = None
                if isinstance(arg, Ps1CommandArgument) and isinstance(arg.value, Ps1StringLiteral):
                    literal = arg.value
                elif isinstance(arg, Ps1StringLiteral):
                    literal = arg
                if literal is not None and literal.value.lower() == target_name.lower():
                    literal.value = normalized
                    literal.raw = normalized
                    self.mark_changed()
                    break

    def _substitute(
        self,
        root: Node,
        aliases: dict[str, tuple[Ps1CommandInvocation, str]],
    ):
        """
        Replace aliased command names with their targets.
        """
        for node in list(root.walk()):
            if not isinstance(node, Ps1CommandInvocation):
                continue
            name = get_command_name(node)
            if name is None:
                continue
            key = name.lower()
            info = aliases.get(key)
            if info is None:
                continue
            defn_node, target_name = info
            if node is defn_node:
                continue
            if node.name is None:
                continue
            normalized = case_normalize_name(target_name)
            node.name = Ps1StringLiteral(
                offset=node.name.offset,
                value=normalized,
                raw=normalized,
            )
            node.name.parent = node
            self.mark_changed()
