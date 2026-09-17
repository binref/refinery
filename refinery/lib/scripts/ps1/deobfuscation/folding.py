"""
PowerShell constant folding transforms.
"""
from __future__ import annotations

import base64
import codecs
import re

from typing import Iterator, NamedTuple, TypeGuard

from refinery.lib.scripts import Node, Transformer, canonical, reattach
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.effects import is_fault_free, may_be_dropped
from refinery.lib.scripts.ps1.analysis.values import (
    NULL,
    Ps1Constant,
    Ps1Fact,
    apply,
    apply_unary,
    coerced_text,
    collect_byte_array,
    collect_integers,
    collect_texts,
    convert,
    integer_at,
    integer_of,
    invariant_text,
    is_truthy,
    make_string_literal,
    pattern_at,
    read,
    read_operand,
    render,
    text_of,
    type_of,
    type_test,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import get_member_name, unwrap_parens
from refinery.lib.scripts.ps1.data import (
    ENCODING_MAP,
    SHAPE_MEMBERS,
    MemberLookup,
    instance_overloads,
    member_record,
    named_type,
    resolve_type,
    type_names,
)
from refinery.lib.scripts.ps1.deobfuscation.constants import PS1_ENV_CONSTANTS
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    StringMethodError,
    apply_format_string,
    apply_string_method,
    collect_format_arguments,
    detect_encoding_chain,
    dotnet_regex_replace,
    extract_foreach_scriptblock,
    is_pipeline_item,
    is_static_type_call,
    unwrap_single_paren,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import (
    substitute_field,
    substitute_list,
    substituted,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1RangeExpression,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)

_REGEX_OPTION_FLAGS: dict[str, int] = {
    'ignorecase'              : re.IGNORECASE,
    'multiline'               : re.MULTILINE,
    'singleline'              : re.DOTALL,
    'ignorepatternwhitespace' : re.VERBOSE,
    'none'                    : 0,
}

_REGEX_OPTION_INT: dict[int, int] = {
    1  : re.IGNORECASE,
    2  : re.MULTILINE,
    16 : re.DOTALL,
    32 : re.VERBOSE,
}

_RIGHT_TO_LEFT = 64
_MAX_STRING_EXPAND = 0x1000
_MAX_RANGES_EXPAND = 15

_CHAR = named_type('System.Char')
_INT32 = named_type('System.Int32')
_STRING = named_type('System.String')

#: The operators that read every operand as the text `[string]` of it produces, so that a constant
#: operand may be written as that text without changing what the operator does. Measured on both
#: sides of each: `'abc' -match [char]98` and `[char]98 -match 'b'` are both True, `[char]120
#: -replace 'x', 'y'` and `'x' -replace [char]120, 'y'` are both `y`, `[char]44 -split ','` is two
#: elements and `('a','b') -join [char]45` is `a-b`.
#:
#: `-f` is deliberately absent although a Char under it does contribute its text: what an operand
#: contributes there is decided by the format specifier, and `'{0:X}' -f 65` is `41` where the text
#: of the same operand is `65`. A comparison is absent for a stronger reason — `-eq` is decided by
#: its *left* operand's type, so `[char]65 -eq 65` and `'A' -eq 65` are not the same question.
#:
#: **`-split` is here on a narrower claim than the sentence above makes.** Its right operand may be
#: a collection, and only the first element of one is a pattern: the second is a *limit* and the
#: third the split options, so `'a,b,c' -split ',', 2` is emitted as `-Split ',', '2'` and the
#: number written as a limit comes back as text. That is measured to preserve the behaviour — the
#: parameter converts a String back to the count, and the corpus row for it reports no difference
#: through the host differential — but it is preserved by the *parameter's* conversion and not by
#: the rule stated here. An operand slot of `-split` that ever stops converting its text would
#: break silently, so a delimiter is what this set covers and a limit is what it happens to survive.
_TEXT_OPERATORS = frozenset({
    '-match', '-cmatch', '-imatch', '-notmatch', '-cnotmatch', '-inotmatch',
    '-like', '-clike', '-ilike', '-notlike', '-cnotlike', '-inotlike',
    '-replace', '-creplace', '-ireplace',
    '-split', '-csplit', '-isplit',
    '-join',
})

#: The whitespace `[Convert]::To<integer>(string)` strips, measured as `' 5 '` converting to 5. Only
#: the one-argument form strips anything: `[Convert]::ToInt32(' 5 ', 16)` throws.
_CONVERT_TRIM = ' \t\r\n'

#: What `[Convert]::To<integer>(string)` reads, which is neither what a cast reads nor what Python's
#: `int` does: an optional sign and decimal digits. Measured — `'+7'` is 7, `'007'` is 7 and `'-5'`
#: is -5, while `'0x10'`, `'1_0'`, `'0b1010'`, `'7.5'`, `'1e3'`, `'1,000'` and `''` each throw.
_CONVERT_SIGNED = re.compile(r'[+-]?[0-9]+\Z')

#: What `[Convert]::To<integer>(string, base)` reads for a base that is not ten: the digits of that
#: base and nothing else, and only base sixteen takes a `0x` prefix — `'0b1010'` at base two throws.
#: A sign throws and so does whitespace, so neither is written here.
_CONVERT_PATTERN: dict[int, re.Pattern[str]] = {
    2: re.compile(r'[01]+\Z'),
    8: re.compile(r'[0-7]+\Z'),
    16: re.compile(r'(?:0[xX])?[0-9a-fA-F]+\Z'),
}


def _is_static_regex_call(node: Ps1InvokeMember) -> bool:
    return is_static_type_call(node, 'system.text.regularexpressions.regex')


def _parse_regex_options(fact: Ps1Fact) -> tuple[int, bool] | None:
    """
    The Python `re` flags and the right-to-left switch a `RegexOptions` argument names, or `None`
    for one this does not recognize.

    The two spellings the enum accepts are its member names and its bit values, and neither is a
    text a value merely coerces to: a Char that renders as `m` names no option, and the number a
    flag is spelled with is the value rather than the digits — so the integer is read as the number
    its spelling names and not as the magnitude `0xFFFFFFFF` would give.
    """
    text = text_of(fact)
    if text is not None:
        flags = 0
        right_to_left = False
        for part in text.split(','):
            key = part.strip().lower()
            if not key:
                continue
            if key == 'righttoleft':
                right_to_left = True
                continue
            flag = _REGEX_OPTION_FLAGS.get(key)
            if flag is None:
                return None
            flags |= flag
        return flags, right_to_left
    value = integer_of(fact)
    if value is None:
        return None
    flags = 0
    for bit, flag in _REGEX_OPTION_INT.items():
        if value & bit:
            flags |= flag
    return flags, bool(value & _RIGHT_TO_LEFT)


def _iter_regex_matches(node: Ps1InvokeMember) -> Iterator[str] | None:
    """
    Yield matched strings from a call to

        [Regex]::Match/Matches(input, pattern[, options])

    Returns `None` if the arguments cannot be resolved.
    """
    if len(node.arguments) not in (2, 3):
        return None
    input = coerced_text(read(node.arguments[0]))
    pattern = coerced_text(read(node.arguments[1]))
    if input is None or pattern is None:
        return None
    if len(node.arguments) == 3:
        if (options := _parse_regex_options(read(node.arguments[2]))) is None:
            return None
        flags, right_to_left = options
    else:
        flags, right_to_left = 0, False
    try:
        matches = [m[0] for m in re.finditer(pattern, input, flags)]
    except re.error:
        return None
    if right_to_left:
        matches.reverse()
    return iter(matches)


def _compute_regex_matches(node: Ps1InvokeMember) -> list[str] | None:
    if it := _iter_regex_matches(node):
        return list(it)


def _compute_regex_match(node: Ps1InvokeMember) -> str | None:
    if it := _iter_regex_matches(node):
        return next(it, '')


def _integer(value: int) -> Ps1IntegerLiteral:
    return Ps1IntegerLiteral(raw=str(value))


def _foreach_extracts_value(sb: Ps1ScriptBlock) -> bool:
    """
    Check whether a ForEach scriptblock body is of the form `$_.Value`,
    `$_.Groups.Value`, or `$_.Groups.Captures.Groups.Value` — i.e. it
    extracts the string value from Match objects.
    """
    if sb.body is None or len(sb.body) != 1:
        return False
    stmt = sb.body[0]
    if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
        return False
    node = stmt.expression
    if not isinstance(node, Ps1Pipeline):
        expr = node
    elif len(node.elements) == 1 and node.elements[0].expression is not None:
        expr = node.elements[0].expression
    else:
        return False
    if not isinstance(expr, Ps1MemberAccess):
        return False
    member = expr.member if isinstance(expr.member, str) else None
    if member is None or member.lower() != 'value':
        return False
    inner = expr.object
    while isinstance(inner, Ps1MemberAccess):
        prop = inner.member if isinstance(inner.member, str) else None
        if prop is None or prop.lower() not in ('groups', 'captures'):
            return False
        inner = inner.object
    return is_pipeline_item(inner)


def _escape_for_expandable(text: str) -> str:
    """
    Escape characters that are special inside double-quoted strings.
    """
    return text.replace('`', '``').replace('$', '`$')


def _variable_raw(var: Ps1Variable) -> str:
    """
    Produce the braced variable reference for use inside an expandable string.
    """
    prefix = '@' if var.splatted else '$'
    scope = var.scope.value
    if scope:
        return F'{prefix}{{{scope}:{var.name}}}'
    return F'{prefix}{{{var.name}}}'


def _is_string_typed_variable(node: Expression | None) -> TypeGuard[Ps1Variable]:
    """
    Return `True` only for a variable whose value is provably a string, so that folding a `+`
    concatenation into an expandable string cannot change array/number `+` semantics. Environment
    variables are always strings in PowerShell.
    """
    return isinstance(node, Ps1Variable) and node.scope == Ps1ScopeModifier.ENV


def _variable_string_to_expandable(
    var: Ps1Variable,
    text: str,
    *,
    var_first: bool,
) -> Ps1ExpandableString:
    """
    Fold `$var + 'text'` or `'text' + $var` into a
    `refinery.lib.scripts.ps1.model.Ps1ExpandableString`.
    """
    escaped = _escape_for_expandable(text)
    var_raw = _variable_raw(var)
    text_part = Ps1StringLiteral(value=text, raw=F"'{text}'")
    if var_first:
        raw = F'"{var_raw}{escaped}"'
        parts = [var, text_part]
    else:
        raw = F'"{escaped}{var_raw}"'
        parts = [text_part, var]
    return Ps1ExpandableString(parts=parts, raw=raw)


def _resolve_index_values(index: Expression) -> int | list[int] | None:
    """
    The index or indices an expression names. A scalar and a collection are told apart because a
    read at one index yields the element and a read at several yields a collection of them, so the
    two are different values rather than one of length one.
    """
    single = integer_of(read(index))
    if single is not None:
        return single
    array = unwrap_to_array_literal(index)
    return None if array is None else collect_integers(array)


class _Selection(NamedTuple):
    """
    What reading a value out of a literal container yields, beside what building the container
    evaluated and the read then leaves behind.

    Indexing is one such read and `.Length` is another: the count carries nothing forward at all, so
    every element is dropped and every element has to be answered for.

    The two halves are answered together because they are one decision: the dropped elements are not
    only values but *work*, so a fold reporting only what it carries forward would drop them.
    `@(1, (Start-Process calc))[0]` is `1`, but the `Start-Process` still runs, so the fold has to
    answer for it.
    """
    carried: Expression
    dropped: list[Expression]


def _character(text: str, index: int) -> Expression | None:
    """
    The character at `index`, spelled as the `Char` it is. Measured: `'ABC'[0]` reports
    `System.Char` and `('abc'[0]) + 'x'` is `ax`, where a one-character String there would have made
    the same `+` a numeric addition on the other side of the operator.
    """
    if not -len(text) <= index < len(text):
        return None
    return render(Ps1Constant(_CHAR, text[index]))


def _index_into_string(s: str, indices: int | list[int]) -> _Selection | None:
    """
    A string is a value and not a container of expressions, so a character selected out of one
    leaves no evaluation behind, whatever the index.
    """
    if isinstance(indices, int):
        one = _character(s, indices)
        return None if one is None else _Selection(one, [])
    selected: list[Expression] = []
    for i in indices:
        element = _character(s, i)
        if element is None:
            return None
        selected.append(element)
    return _Selection(Ps1ArrayLiteral(elements=selected), [])


def _index_into_array(
    array: Ps1ArrayLiteral, indices: int | list[int],
) -> _Selection | None:
    """
    The element or elements a literal array yields for `indices`, beside the elements the selection
    leaves behind.

    **An index that repeats is refused rather than folded.** The selected elements are the array's
    own nodes, so `@(1, 2, 3)[0, 0]` would put one object in two slots of the result: `Node.parent`
    holds one holder, so a later `refinery.lib.scripts._replace_in_parent` rewrites one occurrence
    of two, a transformer visits it twice, and a walk counts whatever it carries twice.

    Copying the node instead would answer a different question — whether the element may be
    *evaluated* twice — and the answer is no for anything with an effect: `@($a.B(), 2)[0, 0]`
    builds the array once and calls `B` once, where the copy calls it twice. That question has no
    caller, because nothing in the corpus or the suite selects a repeated index out of an array
    literal, so it is refused here rather than answered. `_index_into_string` is unaffected: it
    builds a fresh literal per index out of a value that was never a node.
    """
    n = len(array.elements)
    if isinstance(indices, int):
        if not (-n <= indices < n):
            return None
        selected = [array.elements[indices]]
        carried = selected[0]
    else:
        selected = []
        for i in indices:
            if not (-n <= i < n):
                return None
            selected.append(array.elements[i])
        if len({id(element) for element in selected}) != len(selected):
            return None
        carried = Ps1ArrayLiteral(elements=list(selected))
    kept = {id(element) for element in selected}
    return _Selection(
        carried, [element for element in array.elements if id(element) not in kept])


def _lookup_hashtable(ht: Ps1HashLiteral, index: Expression) -> _Selection | None:
    """
    The value a literal hash table holds for `index`, beside every other part of the literal.

    Both halves of each pair are reported as dropped, keys included. PowerShell 5.1 rejects a bare
    subexpression key outright, so the shape that runs is an expandable string holding one, and
    telling that spelling apart from a plain name here would be a second rule about which parts of
    a literal are evaluated — where the whole literal plainly is.
    """
    key = read(index)
    if not isinstance(key, Ps1Constant):
        return None
    for pair_key, pair_value in ht.pairs:
        if _same_key(key, read(pair_key)):
            return _Selection(pair_value, [
                part
                for other_key, other_value in ht.pairs
                for part in (other_key, other_value)
                if part is not pair_value
            ])
    return None


def _same_key(one: Ps1Fact, other: Ps1Fact) -> bool:
    """
    Whether two values are the same hash table key. A key carries its type: measured,
    `@{ a = 1 }[[char]97]` and `@{ 1 = 'x' }['1']` each find nothing, and so does `$h[1L]` for a key
    written `1`, so a Char, a String and each integer width are different keys holding the same
    characters or the same number. Two Strings are the one case that is not identity — `@{ a = 1
    }['A']` is 1, because PowerShell hashes a String key case-insensitively.
    """
    one_text, other_text = text_of(one), text_of(other)
    if one_text is not None and other_text is not None:
        return one_text.lower() == other_text.lower()
    return isinstance(one, Ps1Constant) and one == other


def _pipeline_output(value: Expression | None) -> Expression | None:
    """
    What a pipeline hands to whoever consumes it. A pipeline that emits exactly one object passes
    that object along; it does not wrap it in a collection. Folding a single match out of
    `[regex]::Matches(...) | %{ $_.Value }` therefore yields the string, and an array literal of one
    element here would assign an array where PowerShell assigns a string. Two or more values are a
    collection either way and are left alone.
    """
    if isinstance(value, Ps1ArrayLiteral) and len(value.elements) == 1:
        return value.elements[0]
    return value


def _method_arguments(
    owner: Ps1TypeName, member: str, nodes: list[Expression],
) -> list[str | int] | None:
    """
    The arguments an instance call contributes to the emulated method, or `None` where the call may
    not be folded at all — a member the receiver's type carries no non-static overload of, an arity
    no overload has, or an argument whose value this cannot decide.

    **A method does not coerce its arguments the way an operator does.** An operator turns every
    operand into the text `[string]` of it produces; a method converts each argument to the
    *declared* type of the parameter it binds to, and the two disagree — measured,
    `'abc'.Substring([char]1)` is `bc`, where the Char converts to the number one, and its text
    would be a control character that throws.

    Which of the two an argument takes is read off the collected parameter types rather than
    guessed: a position every candidate overload declares an `Int32` for takes the number, and one
    none of them does takes the text. A position the candidates disagree about is refused, because
    which overload 5.1 binds is a question this does not answer.
    """
    positions = [
        parameters for overload in instance_overloads(owner, member)
        if len(parameters := overload.get('parameters') or ()) == len(nodes)
    ]
    if not positions:
        return None
    arguments: list[str | int] = []
    for index, argument in enumerate(nodes):
        declared = {resolve_type(parameters[index]['type']) for parameters in positions}
        value = _argument_value(read(argument), declared)
        if value is None:
            return None
        arguments.append(value)
    return arguments


def _argument_value(fact: Ps1Fact, declared: set[Ps1TypeName | None]) -> str | int | None:
    """
    What one argument contributes, given the parameter types the candidate overloads declare for its
    position.

    An `Int32` parameter takes the number the argument converts to. Anything else takes its text,
    and only from a value that already is a String or a Char: a `Char[]` parameter is satisfied by a
    String's own characters, which is what makes `'a,b;c'.Split(',;')` three parts, and by a Char,
    which makes `'abc'.Split([char]98)` two. An *integer* there is not the digits — measured,
    `'a9b'.Split(57)` splits on the character 57 is the code of — so it is refused rather than read
    as a text it never becomes.
    """
    if declared == {_INT32}:
        outcome = convert(fact, _INT32)
        return None if outcome.may_throw else integer_of(outcome.value)
    if _INT32 in declared or type_of(fact) not in (_STRING, _CHAR):
        return None
    return coerced_text(fact)


def _value_to_string(receiver: Ps1Fact, member: str, arguments: list[str | int]) -> Expression | None:
    """
    A method on a receiver that is not a String, of which exactly one is folded: `ToString()` with
    no argument, and only for a value whose text carries no culture.

    `ToString()` is *not* `[string]` in general — the method reads the current culture and the
    cast does not — so what it writes is `invariant_text` rather than `coerced_text`, which is the
    same question the separator of a collection asks and is answered once for both.
    """
    if member != 'tostring' or arguments:
        return None
    text = invariant_text(receiver)
    return None if text is None else make_string_literal(text)


def _as_text(operand: Expression | None) -> Expression | None:
    """
    An operand written as the text it contributes, or `None` where it names none or already is that
    text. `refinery.lib.scripts.canonical` is what decides *already*: a rewrite of a tree into an
    equal one is a rewrite that never converges.
    """
    if operand is None:
        return None
    text = coerced_text(read(operand))
    if text is None:
        return None
    spelled = make_string_literal(text)
    return None if canonical(spelled) == canonical(operand) else spelled


def _folded(outcome) -> Expression | None:
    """
    The expression a domain outcome folds to, or `None` where it does not fold. An outcome that may
    throw is never folded: the script's throw is part of what it does, and replacing it with the
    value the operation would have had deletes that. Everything else is left to `render`, which is
    the one place that decides whether a value has a spelling — including `$null`, which is a value
    an operation can produce and not a sign that it produced nothing.
    """
    return None if outcome.may_throw else render(outcome.value)


class Ps1ConstantFolding(Transformer):
    """
    Fold constant expressions to their values. The purity questions the fold rests on are asked
    against the run's shared `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach`, captured
    once at entry rather than re-read per fold: folding edits in post-order, so a per-fold fetch
    would rebuild the world flood on every index or member fold, of which a string-picking
    obfuscation has thousands. Holding is sound because once a fold advances the tree version the
    captured world answers `False`, so a fold it can no longer vouch for is deferred to the next
    sweep rather than mis-granted; the pipeline re-runs this pass to a fixpoint.
    """

    def __init__(self):
        super().__init__()
        self._world: Ps1WorldReach | None = None
        self._entry = False

    def visit(self, node: Node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._world = model_cache(self, node).world_reach
            return super().visit(node)
        finally:
            self._entry = False

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        if len(node.elements) == 2:
            result = substituted(node, _pipeline_output(self._try_fold_regex_pipeline(node)))
            if result is not None:
                return result
        self.generic_visit(node)
        return None

    @staticmethod
    def _fold_regex_call_result(
        invoke: Ps1InvokeMember, member_lower: str,
    ) -> Expression | None:
        if member_lower == 'matches':
            matches = _compute_regex_matches(invoke)
            if matches is not None:
                elements: list[Expression] = [make_string_literal(s) for s in matches]
                return Ps1ArrayLiteral(elements=elements)
        elif member_lower == 'match':
            result = _compute_regex_match(invoke)
            if result is not None:
                return make_string_literal(result)
        return None

    def _try_fold_regex_pipeline(self, node: Ps1Pipeline) -> Expression | None:
        first = node.elements[0].expression
        second_expr = node.elements[1].expression
        if not isinstance(first, Ps1InvokeMember) or not _is_static_regex_call(first):
            return None
        member = get_member_name(first.member)
        if member is None:
            return None
        if second_expr is None:
            return None
        shadowed = model_cache(self, node).closed_world.shadowed_names
        sb = extract_foreach_scriptblock(second_expr, shadowed)
        if sb is None or not _foreach_extracts_value(sb):
            return None
        return self._fold_regex_call_result(first, member.lower())

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        member = get_member_name(node.member)
        if member is None:
            return None
        obj = node.object
        if obj is None:
            return None
        shaped = self._fold_shape_member(node, obj, member)
        if shaped is not None:
            return shaped
        owner = type_of(read(obj))
        if owner is not None and member.lower() == 'pstypenames':
            names = type_names(owner)
            if names is not None:
                return Ps1ArrayLiteral(elements=[make_string_literal(name) for name in names])
        if owner is not None and member_record(owner, member) is MemberLookup.ABSENT:
            return Ps1Variable(name='Null')
        result = self._try_fold_regex_member_access(node, member)
        if result is not None:
            return result
        return None

    def _fold_shape_member(
        self,
        node: Ps1MemberAccess,
        obj: Expression,
        member: str,
    ) -> Expression | None:
        """
        Fold a member whose value the receiver's shape decides. The array answers go through
        `_selected` because folding one discards the elements that built it, and whether that is
        safe is the selection's question rather than this one's.

        A scalar answers 1 to both `Length` and `Count` whatever it is, which is PowerShell's object
        adapter and not the type's own surface — `System.Char` carries neither member, and
        `([char]65).Length` is 1 all the same. So the receiver is read as a *value* rather than
        matched by spelling: `$null` is not one, and its `Count` is 0.

        A collection is a scalar to neither. A spelling this cannot take apart into element nodes —
        `@()`, `@(@(1, 2))`, `@((1, 2))` — still pins how many elements it holds when every one of
        them is a literal: `read` unrolls the array operator exactly as 5.1 does and hands back the
        elements, and both `Count` and `Length` of the `Object[]` those build are that many. The
        answer goes through `_selected` for the reason the array arm does, and the elements it
        discards are the pinned literals that let `read` answer at all, so it never refuses.
        """
        name = member.lower()
        if name not in SHAPE_MEMBERS:
            return None
        array = unwrap_to_array_literal(obj)
        if array is not None:
            count = 1 if name == 'rank' else len(array.elements)
            return self._selected(node, _Selection(_integer(count), list(array.elements)))
        fact = read(obj)
        if name == 'rank':
            return None
        if fact is NULL:
            return None if self._strict_v2_may_be_in_force(node) else _integer(0)
        if not isinstance(fact, Ps1Constant):
            return None
        if isinstance(fact.payload, tuple):
            return self._selected(node, _Selection(_integer(len(fact.payload)), [obj]))
        text = text_of(fact)
        if name == 'length' and text is not None:
            return _integer(len(text))
        if self._strict_v2_may_be_in_force(node):
            return None
        return _integer(1)

    def _strict_v2_may_be_in_force(self, node: Node) -> bool:
        """
        Whether `Set-StrictMode -Version 2` may be armed at *node*, under which the `Count` and
        `Length` the object adapter fakes onto a scalar or `$null` raise rather than answer. Only
        those fakes ask this; a real member — a `String`'s `Length`, an array's `Count` — reads on
        under strict mode and is folded without it.
        """
        return model_cache(self, node).faults.strict_mode_v2_may_be_in_force()

    def _try_fold_regex_member_access(
        self, node: Ps1MemberAccess, member: str,
    ) -> Expression | None:
        chain: list[str] = [member]
        inner = node.object
        while isinstance(inner, Ps1MemberAccess):
            prop = get_member_name(inner.member)
            if prop is None:
                return None
            chain.append(prop)
            inner = inner.object
        chain.reverse()
        if not isinstance(inner, Ps1InvokeMember) or not _is_static_regex_call(inner):
            return None
        normalized = [c.lower() for c in chain]
        if normalized[-1] != 'value':
            return None
        for c in normalized[:-1]:
            if c not in ('groups', 'captures'):
                return None
        call_member = inner.member if isinstance(inner.member, str) else None
        if call_member is None:
            return None
        return self._fold_regex_call_result(inner, call_member.lower())

    @staticmethod
    def _try_join_regex_matches(operand: Expression) -> Expression | None:
        unwrapped = unwrap_parens(operand)
        if not isinstance(unwrapped, Ps1InvokeMember) or not _is_static_regex_call(unwrapped):
            return None
        member = unwrapped.member if isinstance(unwrapped.member, str) else None
        if member is None or member.lower() != 'matches':
            return None
        matches = _compute_regex_matches(unwrapped)
        if matches is None:
            return None
        return make_string_literal(''.join(matches))

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator.lower()
        if op == '-join':
            return self._handle_unary_join(node)
        if op in ('-', '-bnot'):
            return _folded(apply_unary(op, read_operand(node.operand)))
        if op in ('-not', '!'):
            truth = is_truthy(node.operand)
            if truth is not None:
                return Ps1Variable(name='False' if truth else 'True')
        return None

    def _handle_unary_join(self, node: Ps1UnaryExpression) -> Expression | None:
        operand = node.operand
        if operand is None:
            return None
        result = self._try_join_regex_matches(operand)
        if result is not None:
            return result
        parts = collect_texts(operand)
        return None if parts is None else make_string_literal(''.join(parts))

    def visit_Ps1RangeExpression(self, node: Ps1RangeExpression):
        self.generic_visit(node)
        if isinstance(node.parent, Ps1RangeExpression):
            return None
        a = integer_of(read(node.start))
        b = integer_of(read(node.end))
        if a is None or b is None:
            return None
        step = 1 if b >= a else -1
        count = abs(b - a) + 1
        if count > _MAX_RANGES_EXPAND:
            return None
        if not is_fault_free(node):
            return None
        return Ps1ArrayLiteral(elements=[
            Ps1IntegerLiteral(raw=str(v)) for v in range(a, b + step, step)])

    def _selected(self, node: Node, selection: _Selection | None) -> Expression | None:
        """
        The expression a selection out of `node` folds to, or `None` when what it leaves behind is
        work the script would no longer do; see
        `refinery.lib.scripts.ps1.analysis.effects.may_be_dropped` for what that means.

        The world is the one this pass captured at entry (see the class docstring). This pass only
        folds, so a verdict taken before its own edits is the more open, and so the more
        conservative, of the two.

        A refused selection has to release the elements it adopted: a multi-index read has already
        built the array literal that carries the result, and building it adopted elements that are
        still standing under `node`.
        """
        if selection is None:
            return None
        if not all(may_be_dropped(part, self._world) for part in selection.dropped):
            reattach(node)
            return None
        return selection.carried

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        self.generic_visit(node)
        if node.index is None or node.object is None:
            return None
        if isinstance(node.object, Ps1HashLiteral):
            return self._selected(node, _lookup_hashtable(node.object, node.index))
        indices = _resolve_index_values(node.index)
        if indices is None:
            return None
        obj_str = text_of(read(node.object))
        if obj_str is not None:
            return self._selected(node, _index_into_string(obj_str, indices))
        array = unwrap_to_array_literal(node.object)
        if array is not None:
            return self._selected(node, _index_into_array(array, indices))
        return None

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        member_name = get_member_name(node.member)
        if member_name is None:
            return None
        lower = member_name.lower()
        return (
            self._try_fold_invoke_redirect(node, lower)
            or self._try_fold_instance_method(node, lower)
            or self._try_fold_static_method(node, lower)
        ) or None

    @staticmethod
    def _try_fold_invoke_redirect(
        node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if lower == 'invoke' and isinstance(node.object, Ps1MemberAccess):
            return Ps1InvokeMember(
                offset=node.offset,
                object=node.object.object,
                member=node.object.member,
                arguments=node.arguments,
                access=node.object.access,
            )
        return None

    @staticmethod
    def _try_fold_instance_method(
        node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        """
        A method called on a constant receiver, which folds only where the receiver's type really
        carries it.

        The gate is the collected member surface and not the shape of the value: `System.Char` has a
        `ToUpper` whose every overload is static, so `([char]65).ToUpper()` reports `MethodNotFound`
        on 5.1 while `[char]::ToUpper('a')` answers.

        `ToCharArray()` is the one method not routed through `apply_string_method`: its value is a
        `Char[]`, which that kernel's `list[str]` result would spell as String elements, flipping a
        later `-is [char]`. It folds instead to the `[char[]]` cast of its receiver, the equal value
        the source could have written, so `read` reads the character array back and the `.Count` and
        `.Length` on it fold the way the same cast written by hand already does.
        """
        receiver = read(node.object)
        owner = type_of(receiver)
        if owner is None:
            return None
        if lower == 'tochararray' and not node.arguments and owner == _STRING:
            text = text_of(receiver)
            if text is not None:
                return Ps1CastExpression(type_name='char[]', operand=make_string_literal(text))
        arguments = _method_arguments(owner, lower, node.arguments)
        if arguments is None:
            return None
        text = text_of(receiver)
        if text is None:
            return _value_to_string(receiver, lower, arguments)
        try:
            result = apply_string_method(text, lower, arguments)
        except StringMethodError:
            return None
        if isinstance(result, str):
            return make_string_literal(result)
        if isinstance(result, bool):
            return Ps1Variable(name='True' if result else 'False')
        if isinstance(result, int):
            return Ps1IntegerLiteral(raw=str(result))
        if isinstance(result, list):
            elements: list[Expression] = [make_string_literal(p) for p in result]
            return Ps1ArrayLiteral(elements=elements)
        return None

    def _try_fold_static_method(
        self, node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if is_static_type_call(node, 'system.convert'):
            return self._try_fold_convert(node, lower)
        encoding_name = detect_encoding_chain(node)
        if encoding_name is not None:
            if len(node.arguments) == 1:
                int_values = collect_integers(unwrap_single_paren(node.arguments[0]))
                if int_values is not None:
                    try:
                        raw_bytes = bytearray(int_values)
                    except (ValueError, OverflowError):
                        return None
                    encoding = ENCODING_MAP.get(
                        encoding_name.lower(), encoding_name)
                    try:
                        codecs.lookup(encoding)
                    except LookupError:
                        encoding = 'utf-8'
                    try:
                        decoded_str = raw_bytes.decode(encoding)
                    except Exception:
                        return None
                    return make_string_literal(decoded_str)
        if is_static_type_call(node, 'system.string'):
            if lower == 'concat' and len(node.arguments) >= 1:
                parts: list[str] = []
                for arg in node.arguments:
                    if (sv := coerced_text(read(arg))) is None:
                        break
                    parts.append(sv)
                else:
                    return make_string_literal(''.join(parts))
            if lower == 'join' and len(node.arguments) >= 2:
                separator = coerced_text(read(node.arguments[0]))
                if separator is not None:
                    joined: list[str] = []
                    for arg in node.arguments[1:]:
                        if (sv := coerced_text(read(arg))) is None:
                            break
                        joined.append(sv)
                    else:
                        return make_string_literal(separator.join(joined))
                    if len(node.arguments) == 2:
                        args = collect_texts(node.arguments[1])
                        if args is not None:
                            return make_string_literal(separator.join(args))
        if _is_static_regex_call(node) and lower == 'replace':
            return self._handle_regex_replace(node)
        if is_static_type_call(node, 'system.bitconverter') and lower == 'tostring':
            return self._try_fold_bitconverter_tostring(node)
        if (
            is_static_type_call(node, 'system.environment')
            and lower == 'getenvironmentvariable'
            and len(na := node.arguments) == 1
            and (_en := coerced_text(read(na[0]))) is not None
            and (_ev := PS1_ENV_CONSTANTS.get(_en.lower())) is not None
        ):
            return make_string_literal(_ev)
        return None

    #: The integer type each `[Convert]::To<T>` produces, which is what the result is spelled at.
    #: Measured: `[Convert]::ToByte('FF', 16)` is a Byte and `[Convert]::ToInt64(5)` an Int64, so a
    #: fold that wrote a bare numeral for either reported an Int32 the call never produced.
    _CONVERT_INT_METHODS: dict[str, Ps1TypeName] = {
        'tobyte'  : named_type('System.Byte'),
        'toint16' : named_type('System.Int16'),
        'toint32' : named_type('System.Int32'),
        'toint64' : named_type('System.Int64'),
        'tosbyte' : named_type('System.SByte'),
        'touint16': named_type('System.UInt16'),
        'touint32': named_type('System.UInt32'),
        'touint64': named_type('System.UInt64'),
    }

    def _try_fold_convert(
        self, node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if lower == 'frombase64string' and len(node.arguments) == 1:
            b64_str = coerced_text(read(node.arguments[0]))
            if b64_str is not None:
                try:
                    decoded = base64.b64decode(b64_str)
                except Exception:
                    return None
                elements: list[Expression] = [
                    Ps1IntegerLiteral(raw=F'0x{b:02X}') for b in decoded
                ]
                array = Ps1ArrayLiteral(elements=elements)
                return Ps1ArrayExpression(
                    body=[Ps1ExpressionStatement(expression=array)])
        target = self._CONVERT_INT_METHODS.get(lower)
        if target is not None:
            return self._fold_convert_int(node, target)
        if lower == 'tochar':
            return self._fold_convert_char(node)
        return None

    @staticmethod
    def _fold_convert_char(node: Ps1InvokeMember) -> Expression | None:
        """
        `[Convert]::ToChar(n)`, which produces a Char and is *not* the cast to one: measured,
        `[Convert]::ToChar(1.5)` throws where `[char]1.5` rounds, because .NET defines no conversion
        from a Double to a Char. So only an integer is read, and only inside the range.
        """
        if len(node.arguments) != 1:
            return None
        code = integer_of(read(node.arguments[0]))
        if code is None or not 0 <= code <= 0xFFFF:
            return None
        return render(Ps1Constant(_CHAR, chr(code)))

    @staticmethod
    def _fold_convert_int(node: Ps1InvokeMember, target: Ps1TypeName) -> Expression | None:
        """
        `[Convert]::To<integer>(...)`, whose String operand is read by an oracle that is neither the
        cast's nor Python's — a third one, measured, and this is where the difference is written.

        For every source but a String the call *is* the cast, so it asks `convert`:
        `[Convert]::ToInt32(1.5)` and `(2.5)` are both 2, which is the half-to-even a cast performs,
        and a Char, a `$true` and a `$null` each convert exactly as they do under one.

        A String is stricter than the cast in the one-argument form. `[Convert]::ToInt32('0x10')`
        throws where `[int]'0x10'` is 16, and so do `'7.5'`, `'1e3'`, `'1,000'`, `'1_0'`, `'0b1010'`
        and the empty String, each of which a cast or Python's own `int` reads as a number.

        With an explicit base it is stricter still and it reads a *pattern*: `'FFFFFFFF'` at base
        sixteen is the Int32 -1 and `'80000000'` is -2147483648, where the digits read as a number
        are out of range and this refused to fold them at all.
        """
        arguments = node.arguments
        if len(arguments) == 1:
            fact = read(arguments[0])
            text = text_of(fact)
            if text is None:
                return _folded(convert(fact, target))
            digits = text.strip(_CONVERT_TRIM)
            if not _CONVERT_SIGNED.match(digits):
                return None
            return render(integer_at(target, int(digits)))
        if len(arguments) != 2:
            return None
        text = text_of(read(arguments[0]))
        base = integer_of(read(arguments[1]))
        if text is None or base is None:
            return None
        if base == 10:
            if not _CONVERT_SIGNED.match(text):
                return None
            return render(integer_at(target, int(text)))
        digits_of_base = _CONVERT_PATTERN.get(base)
        if digits_of_base is None or not digits_of_base.match(text):
            return None
        return render(pattern_at(target, int(text, base)))

    @staticmethod
    def _try_fold_bitconverter_tostring(node: Ps1InvokeMember) -> Expression | None:
        if not node.arguments:
            return None
        data = collect_byte_array(node.arguments[0])
        if data is None:
            return None
        offset = 0
        length = len(data)
        if len(node.arguments) >= 2:
            n = integer_of(read(node.arguments[1]))
            if n is None:
                return None
            offset = n
        if len(node.arguments) >= 3:
            n = integer_of(read(node.arguments[2]))
            if n is None:
                return None
            length = n
        if offset < 0 or length < 0 or offset + length > len(data):
            return None
        segment = data[offset:offset + length]
        return make_string_literal('-'.join(F'{b:02X}' for b in segment))

    def _handle_regex_replace(self, node: Ps1InvokeMember) -> Expression | None:
        if len(node.arguments) not in (3, 4):
            return None
        input_str = coerced_text(read(node.arguments[0]))
        pattern_str = coerced_text(read(node.arguments[1]))
        replacement_str = coerced_text(read(node.arguments[2]))
        if input_str is None or pattern_str is None or replacement_str is None:
            return None
        flags = 0
        if len(node.arguments) == 4:
            opts = _parse_regex_options(read(node.arguments[3]))
            if opts is None:
                return None
            flags, _ = opts
        try:
            result = dotnet_regex_replace(pattern_str, replacement_str, input_str, flags=flags)
        except re.error:
            return None
        return make_string_literal(result)

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        op = node.operator.lower()
        return self._folded_operator(node, op) or self._spelled_as_text(node, op)

    def _folded_operator(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        if op == '-f':
            return self._handle_format(node)
        if op == '+':
            return self._handle_arithmetic(node, op) or self._handle_concat(node)
        if op == '*':
            return self._handle_string_multiply(node) or self._handle_arithmetic(node, op)
        if op == '-join':
            return self._handle_binary_join(node)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._handle_binary_replace(node, op)
        if op in ('-split', '-csplit', '-isplit'):
            return self._handle_binary_split(node, op)
        if op in ('-and', '-or', '-xor'):
            return self._handle_logical(node, op)
        if op in ('-is', '-isnot'):
            return self._handle_type_test(node, op)
        return self._handle_comparison(node, op) or self._handle_arithmetic(node, op)

    def _spelled_as_text(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        """
        Every constant operand of a text-only operator, written as the text it contributes.

        This runs only where the operator itself declined to fold, which means one of its operands
        is not constant. The others still stand as whatever they were written or folded to, and for
        a Char that spelling is `[char]12499` where what the operator reads is the character — so
        `-Match [char]12499` becomes `-Match 'ビ'`, which is the same operation said in the form
        that shows what it does. See `_TEXT_OPERATORS` for which operators read an operand this way
        and what was measured to establish it.
        """
        if op not in _TEXT_OPERATORS:
            return None
        changed = False
        for field in ('left', 'right'):
            spelled = _as_text(getattr(node, field))
            if spelled is not None and substitute_field(node, field, spelled):
                changed = True
        right = node.right
        if isinstance(right, Ps1ArrayLiteral):
            elements = [_as_text(element) or element for element in right.elements]
            if any(new is not old for new, old in zip(elements, right.elements)):
                changed = substitute_list(right, 'elements', elements) or changed
        if not changed:
            return None
        self.mark_changed()
        return node

    @staticmethod
    def _handle_arithmetic(node: Ps1BinaryExpression, op: str) -> Expression | None:
        """
        Fold an arithmetic, bitwise or shift operator by asking the value domain what it produces.
        The result is spelled at the type the domain gives it, so a fold cannot quietly change one:
        `0xFFFFFFFF -bxor 0x5A` is Int32 -91 rather than the 4294967205 an operand read as an
        unsigned Python integer would give, and `2147483647 + 1` widens to a Double as a host does.
        """
        return _folded(apply(op, read_operand(node.left), read_operand(node.right)))

    @staticmethod
    def _handle_string_multiply(node: Ps1BinaryExpression) -> Expression | None:
        """
        Replication, which `*` performs when its *left* operand is a String and nothing else.

        A negative count is a throw and not an empty string. Measured: `'ab' * -1` terminates the
        script with an `ArgumentOutOfRangeException`, and so does `'ab' * 0xFFFFFFFF`, whose count
        is the Int32 -1. Folding either to `''` would turn a script that stopped into one that
        carries on, so a negative count is left unfolded.
        """
        s = text_of(read(node.left))
        count = integer_of(read(node.right))
        if s is None or count is None or count < 0:
            return None
        if len(s) * count > _MAX_STRING_EXPAND:
            return None
        return make_string_literal(s * count)

    @staticmethod
    def _bool_literal(result: bool) -> Ps1Variable:
        return Ps1Variable(name='True' if result else 'False')

    def _handle_comparison(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        """
        Fold a comparison, which the value domain answers alone: the equality of two texts, the case
        a spelling counts and what an absent operand compares as all live in
        `refinery.lib.scripts.ps1.analysis.values`, so that one reader decides what a comparison is
        and a measurement that moves it moves in one place.
        """
        return _folded(apply(op, read_operand(node.left), read_operand(node.right)))

    def _handle_type_test(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        """
        Fold `-is` and `-isnot`, whose right operand is a type rather than a value, so the value
        grid `_handle_comparison` reads does not answer them. The left operand's runtime type decides
        the test and the value domain answers it; a right operand that is not a type literal, or a
        left one whose type is not known, leaves the test standing. `-isnot` is the negation of the
        same answer.
        """
        named = node.right
        if not isinstance(named, Ps1TypeExpression):
            return None
        verdict = type_test(read_operand(node.left), named.name)
        if verdict is None:
            return None
        return self._bool_literal(verdict if op == '-is' else not verdict)

    def _handle_logical(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = is_truthy(node.left)
        right = is_truthy(node.right)
        if left is None or right is None:
            return None
        if op == '-and':
            result = left and right
        elif op == '-or':
            result = left or right
        else:
            result = left != right
        return self._bool_literal(result)

    def _handle_format(self, node: Ps1BinaryExpression) -> Expression | None:
        fmt_str = text_of(read(node.left))
        if fmt_str is None or node.right is None:
            return None
        args = collect_format_arguments(node.right)
        if args is None:
            return None
        result = apply_format_string(fmt_str, args)
        if result is None:
            return None
        return make_string_literal(result)

    def _handle_concat(self, node: Ps1BinaryExpression) -> Expression | None:
        """
        What `+` does that the value domain does not answer: appending to a literal collection, and
        rewriting a concatenation with an unknown operand into an expandable string.

        Two constants are not here at all: the domain answers them exactly, and `apply` is asked
        first.

        This does not re-associate a chain: `($x + 'a') + 'b'` is not `$x + 'ab'` wherever `$x` is
        not a String — measured, `@(1) + 'a' + 'b'` is a three-element array and `@(1) + 'ab'` a
        two-element one — so an inner-left concat is left alone.
        """
        appended = self._appended_to_array(node)
        if appended is not None:
            return appended
        is_inner_concat = (
            isinstance(node.parent, Ps1BinaryExpression)
            and node.parent.operator == '+'
            and node.parent.left is node
        )
        if is_inner_concat:
            return None
        # `'literal' + $var` is always string concatenation (the string-typed left operand governs
        # `+`), so it is safe to fold into an expandable string. `$var + 'literal'` depends on
        # $var's runtime type (array append / numeric add), so only fold it when the variable is
        # provably a string.
        left, right = node.left, node.right
        left_str = text_of(read(left))
        if isinstance(right, Ps1Variable) and left_str is not None:
            return _variable_string_to_expandable(right, left_str, var_first=False)
        right_str = text_of(read(right))
        if _is_string_typed_variable(left) and right_str is not None:
            return _variable_string_to_expandable(left, right_str, var_first=True)
        return None

    @staticmethod
    def _appended_to_array(node: Ps1BinaryExpression) -> Expression | None:
        """
        A constant appended to a literal collection, which keeps the value's own type rather than
        its text: measured, `@(1, 2) + [char]65` is a three-element array whose last element reports
        `System.Char`.
        """
        if not isinstance(node.left, Ps1ArrayLiteral) or node.right is None:
            return None
        appended = render(read(node.right))
        if appended is None:
            return None
        return Ps1ArrayLiteral(elements=[*node.left.elements, appended])

    def _handle_binary_join(self, node: Ps1BinaryExpression) -> Expression | None:
        separator = coerced_text(read(node.right))
        if separator is None:
            return None
        parts = collect_texts(node.left)
        return None if parts is None else make_string_literal(separator.join(parts))

    def _handle_binary_replace(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        haystack = coerced_text(read(node.left))
        if haystack is None or node.right is None:
            return None
        if not isinstance(node.right, Ps1ArrayLiteral) or len(node.right.elements) != 2:
            return None
        needle_str = coerced_text(read(node.right.elements[0]))
        insert_str = coerced_text(read(node.right.elements[1]))
        if needle_str is None or insert_str is None:
            return None
        flags = re.IGNORECASE if op != '-creplace' else 0
        try:
            result = dotnet_regex_replace(needle_str, insert_str, haystack, flags=flags)
        except re.error:
            return None
        return make_string_literal(result)

    def _handle_binary_split(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        pattern_str = coerced_text(read(node.right))
        if pattern_str is None:
            return None
        inputs = collect_texts(node.left)
        if inputs is None:
            return None
        flags = re.IGNORECASE if op != '-csplit' else 0
        try:
            parts: list[str] = []
            for s in inputs:
                parts.extend(re.split(pattern_str, s, flags=flags))
        except re.error:
            return None
        elements: list[Expression] = [make_string_literal(p) for p in parts]
        return Ps1ArrayLiteral(elements=elements)
