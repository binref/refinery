"""
Builtin case normalization: printing every reference to a builtin function the official
documentation spells it with.

AutoIt resolves function names without regard to case, so an obfuscator may spell a builtin any
way it likes and the call still resolves; the wide builtin table maps every lowercased name to
the official spelling, and this pass prints that one, so case-scrambling obfuscation leaves no
fingerprint in the output. Two shapes are rewritten: the direct callee of a call whose name the
table holds, and the string-literal first argument of a `Call` that names a builtin — the docs
say `Call` invokes builtins too, and no earlier pass resolves that name.

A spelling is rewritten only where it differs from the official one in ASCII case. Python's
`str.lower` also folds characters outside ASCII into ASCII letters — U+212A KELVIN SIGN becomes
`k` — and whether the engine folds them too is unpinned; the source spelling is right under
either answer, so the rewrite refuses such a name.

The callee rewrite changes only the printed spelling, never what the call resolves to, so it
carries no gate over what the tree holds, only the shadowing rule: a declared script function
owning the name keeps the call site's spelling, because printing a builtin's name there would
tell the reader the call is one. The `Call` argument is data the invoked function may read, so
its rewrite carries the same refusals the dynamic-name flattener reads — a script function of
the name `Call` shadows the builtin, an include may hide a `Func Call` no walk of the tree sees,
and a parse error leaves text no walk reads — and the same shadowing rule for the named
function. A registration builtin's string argument names a script function, never a builtin, and
no rule here reads it: only a `Call` holds a name this pass rewrites.

The pass runs in the final pipeline group, after every splice, fold, flatten, and alias rewrite
has produced its final call shapes, so nothing it prints is later re-shaped. Its edits change no
lowercased name and no declaration, so the scope snapshot the pass holds stays true mid-pass,
and every spelling it writes is one a later round refuses, so the group runs it once.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_value
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel
from refinery.lib.scripts.au3.functions import AUTOIT_FUNCTION_NAMES
from refinery.lib.scripts.au3.lexer import ascii_lower, encode_au3_string
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3Identifier,
    Au3Script,
    Au3StringLiteral,
)


class Au3BuiltinCaseNormalization(Transformer):
    """
    Prints every reference to a builtin function — a call's callee, or the name a `Call` holds —
    in the official documentation spelling.
    """

    self_converging = True

    def __init__(self):
        super().__init__()
        self._scopes = Au3ScopeModel({})

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._scopes = model_cache(self, node).scopes
        self.generic_visit(node)
        if not isinstance(node, Au3Call):
            return None
        callee = ast.direct_callee(node)
        if callee is None:
            return None
        if callee.name not in self._scopes.functions:
            self._normalize_callee(callee)
            if callee.name == 'call':
                self._normalize_call_name(node)
        return None

    def _normalize_callee(self, callee: Au3Identifier) -> None:
        official = _official_spelling(callee.raw)
        if official is None:
            return
        set_value(callee, 'raw', official)
        self.mark_changed()

    def _normalize_call_name(self, call: Au3Call) -> None:
        if self._scopes.holds_an_include or self._scopes.holds_a_parse_error:
            return
        if not call.arguments:
            return
        literal = ast.unwrap_parens(call.arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            return
        if literal.value.lower() in self._scopes.functions:
            return
        official = _official_spelling(literal.value)
        if official is None:
            return
        set_value(literal, 'value', official)
        set_value(literal, 'raw', encode_au3_string(official))
        self.mark_changed()


def _official_spelling(spelling: str) -> str | None:
    """
    The official spelling of the builtin *spelling* names where the two differ in ASCII case
    alone, or `None` where they are equal or no builtin is named. The lookup folds through
    `refinery.lib.scripts.au3.lexer.ascii_lower`, so a spelling that only a fold beyond ASCII case
    maps onto a builtin keeps a character no table key holds and names none.
    """
    official = AUTOIT_FUNCTION_NAMES.get(ascii_lower(spelling))
    if official is None or official == spelling:
        return None
    return official
