"""
Evaluate user-defined PowerShell functions called with constant arguments.
"""
from __future__ import annotations

import base64
import re

from collections import ChainMap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Mapping, TypeAlias

    _Value: TypeAlias = 'str | int | float | bool | list | None | _MatchTable'

from refinery.lib.scripts import Block, Node, Statement, Transformer
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.commands import CommandKind, Ps1CommandModel
from refinery.lib.scripts.ps1.analysis.effects import (
    MATCH_OPERATORS,
    opens_a_redirection_target,
    takes_output_away,
)
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.model import (
    Ps1SemanticModel,
    occurrence_role,
)
from refinery.lib.scripts.ps1.analysis.separator import OFS_FALLBACK, OFS_NAME
from refinery.lib.scripts.ps1.analysis.world import runs_code_supplied_as_data
from refinery.lib.scripts.ps1.analysis.values import (
    UNKNOWN,
    Ps1Constant,
    Ps1Fact,
    char_fact,
    collection_fact,
    coerced_text,
    collect_facts,
    fact_of,
    integer_at,
    integer_of,
    make_string_literal,
    null_expression,
    read,
    render,
)
from refinery.lib.scripts.ps1.ast import (
    get_body,
    get_command_name,
    get_member_name,
    normalize_command_name,
    normalize_dotnet_type_name,
    standalone_command_statement,
)
from refinery.lib.scripts.ps1.data import (
    COMPARISON_OPS,
    ENCODING_MAP,
    PS1_KNOWN_VARIABLES,
    is_type,
    named_type,
    resolve_type,
)
from refinery.lib.scripts.ps1.deobfuscation.constants import (
    PS1_AUTOMATIC_VARIABLES,
    PS1_ENGINE_VARIABLES,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    StringMethodError,
    apply_format_string,
    apply_string_method,
    detect_encoding_chain,
    dotnet_regex_replace,
    extract_foreach_scriptblock,
    ps_divide,
    ps_modulo,
    ps_shift_left,
    ps_shift_right,
    stands_where_only_a_command_may,
    switch_matches,
)
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan
from refinery.lib.scripts.ps1.deobfuscation.substitution import (
    carried_redirections,
    substitute_list,
    substitute_statement,
    substituted,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CastExpression,
    Ps1ClassDefinition,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1EnumDefinition,
    Ps1ErrorNode,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ReturnStatement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_MAX_INTERPRETER_ITERATIONS = 100_000
_MAX_INTERPRETER_STRING_LEN = 1_000_000
_MAX_INTERPRETER_DEPTH = 64

#: The operators whose *left* operand a `Boolean` may not be. 5.1 dispatches an operator to a method
#: on the left operand's type and `Boolean` carries none of these three, so `$true * 2` is
#: `The operation '[System.Boolean] * [System.Int32]' is not defined` — where the interpreter would
#: answer a number, because Python's `bool` is an `int` and nothing here carries the .NET type that
#: tells the two apart. What is left out is left out on the same measurement: `$true + 1`,
#: `$true / 2` and `$true -bxor 1` are values on 5.1, and a `Boolean` on the *right* is a value for
#: every one of the ten. The measured grid is not the oracle for this list — it answers a cell and
#: not an operand, so its throw over `/` and `%` is the divisor `$false`, which `ps_divide` and
#: `ps_modulo` already refuse where it stands.
_NO_OPERATOR_METHOD_ON_BOOLEAN = frozenset({'*', '-shl', '-shr'})

#: The operators whose *left* operand a `Char` may not be, the same three the grid's `System.Char`
#: row marks as always throwing. 5.1 dispatches to a method on the left type and a `Char` carries
#: none of these, so `[char]65 -shl 2` is `The operation '[System.Char] -shl [System.Int32]' is not
#: defined` — where the interpreter, carrying the Char as the one-character string it spells, would
#: shift its code point. A Char on the *right* is a value for every one: it is the count a shift
#: reads and the number `-band`, `-bor` and `-bxor` fold against.
_NO_OPERATOR_METHOD_ON_CHAR = frozenset({'*', '-shl', '-shr'})

#: The one element type `Ps1ForEachPipeline._get_constant_array` may drop off an array cast that the
#: script's own spelling does not already name: a `Char` is measured against `UInt16` because a code
#: point is what it holds, and the domain's integer widths carry no cell for `Char` itself.
_CHAR_WIDTH = named_type('System.UInt16')

_BYTE_WIDTH = named_type('System.Byte')


def _width_of(spelling: str) -> Ps1TypeName | None:
    """
    The type an element of an array cast to *spelling* is measured against, or `None` for a spelling
    that names no type at all.

    Which spellings name a type is `refinery.lib.scripts.ps1.data.resolve_type` and not a table of
    its own, because a table would have to restate the accelerators 5.1 has and a name it invented
    is the one mistake that costs a fold its soundness: `[ushort]` does not resolve on 5.1, so a
    script written with it stops there, and a table that carried it would drop the cast and fold on
    past the error. Whether the type it names is a width the item survives is `integer_at`'s
    question, asked in `_fills_the_width`, so this refuses nothing that resolves.
    """
    return _CHAR_WIDTH if spelling == 'char' else resolve_type(spelling)


def _value_of(fact: Ps1Fact) -> tuple[bool, _Value]:
    """
    The interpreter's own currency for a value the domain names, or `(False, None)` where its
    currency cannot hold that value.

    The test is a **round trip** rather than a list of types this happens to know: a `_Value`
    carries a magnitude and a Python kind and no .NET type at all, so it may stand for a fact only
    where `refinery.lib.scripts.ps1.analysis.values.fact_of` gives that same fact back. What that
    refuses is exactly what carrying the value here would lose — a Char, whose payload is a
    String's; a Decimal; and every integer written at a width its own magnitude does not take, so
    `[byte] 5` is declined rather than folded back out as the Int32 `5`. It is one rule, so the
    types the interpreter grows into cannot come apart from the types it may accept.

    **`$null` is refused although it round-trips**, because the round trip is about the value and
    this is about the currency: `None` is what the interpreter also uses for a statement that
    emitted nothing, and `_Ps1Interpreter._append` drops it on that reading. A `$null` handed in as
    an item comes back out of the stream as an item that is not there, so `1, $null, 2 | %{ $_ }`
    would fold to a collection of two. Until the interpreter has a mark for *no output*, an
    emitted `$null` is a value it cannot carry.
    """
    carried = _carried(fact)
    if carried is None:
        return False, None
    return (True, carried) if fact_of(carried) == fact else (False, None)


def _fills_the_width(fact: Ps1Fact, width: str) -> bool:
    """
    Whether an element of an array cast to *width* is a number that width holds, which is what
    `Ps1ForEachPipeline._get_constant_array` needs before it may drop the cast and hand the element
    on as the number written inside it.

    Two ways to fail and they fail alike here. An element that is not a number at all is converted
    by the cast rather than merely renamed — `[int[]]('1', '2')` hands out Int32s where the text
    would concatenate. And a number the width does not hold is not converted at all: 5.1 throws on
    `[byte[]](300, 1)`, so a fold that answered `300, 1` would put a value where the script has an
    error.
    """
    named = _width_of(width)
    found = integer_of(fact)
    if named is None or found is None:
        return False
    return integer_at(named, found) is not UNKNOWN


def _carried(fact: Ps1Fact) -> _Value:
    """
    The Python object under a fact, read with no regard for whether it stands for the value —
    which is `_value_of`'s question and is asked of the answer rather than of the parts.

    `None` is this function's refusal and never a value it carries, which is what lets an element
    refuse the collection around it: a `$null` item reads as `None` here and the interpreter's
    stream deletes a `None`, so a collection holding one would come back a member short. That is
    the same refusal `_value_of` states for a `$null` handed over on its own, and stating it here
    is what makes it reach an element — a list is not `None`, so the caller's test never sees the
    item that could not be carried.
    """
    if isinstance(fact, Ps1Constant):
        payload = fact.payload
        if isinstance(payload, tuple):
            items = [_carried(one) for one in payload]
            return None if any(one is None for one in items) else items
        if isinstance(payload, (str, bool, int, float)):
            return payload
    return None


class _Char(str):
    """
    A `System.Char` the interpreter carries as the one-character string it spells, kept apart
    from an ordinary String so that an operation a String has and a Char does not is refused rather
    than run. 5.1 repeats a String on the left of `*` and throws for a Char there, so `[char]65 * 2`
    stops the fold where `'A' * 2` folds to `AA`. Being a `str` subclass, a Char reads as its text
    everywhere a String would — it concatenates, coerces and indexes the same — and only the places
    that must tell the two apart look for this type.
    """


class _Byte(int):
    """
    A `System.Byte` the interpreter carries as the integer it names, kept apart from an ordinary
    number so that a fold spelling the value back out writes the width the body produced rather
    than the Int32 its magnitude is. Everything a Byte does with another number promotes —
    measured, `[byte]200 + [byte]200` is the Int32 `400` — and being an `int` subclass this does
    exactly that for free: every operation the interpreter runs over it returns a plain number.
    """


class _CharArray(list):
    """
    A `System.Char[]` the interpreter carries as the list of characters it holds, kept apart from
    an ordinary collection because the two spell differently: an `Object[]` of Chars is written as
    the elements and a `Char[]` has no spelling at all (`render` spells none), so a value this
    wide refuses a fold. Being a `list` subclass it reads as its elements everywhere a collection
    would — it joins, indexes and counts the same — and only the places that must tell the two
    apart look for this type.
    """


class _MatchTable:
    """
    The `$Matches` automatic variable, the `System.Hashtable` a successful `-match` leaves behind.
    It holds the whole match under the Int32 key `0` and each group that took part under its own
    number, every value a String. It answers a subscript and nothing else: a script reads its
    captures as `$Matches[<n>]`, so an index into it is honoured, and every other use — coercing it
    to text, adding to it, spelling it back as a value — is left to fall through to the
    interpreter's refusal, which stops a fold at the first step that would need a hashtable this
    does not model rather than inventing one.
    """
    __slots__ = ('entries',)

    def __init__(self, entries: dict[int, str]):
        self.entries = entries


#: The lowercased name of the `$Matches` automatic variable in the interpreter's scope.
_MATCHES_NAME = 'matches'

#: Every name the engine supplies a value for that an isolated body does not carry: the automatic
#: variables and the known session and preference variables, `$FormatEnumerationLimit` and the
#: `$Maximum*Count` scalars among them. A read of one before the emulated body writes it is refused
#: rather than answered `$null`, since `$null` is not what the host holds — measured, 5.1 reads
#: `$FormatEnumerationLimit` as `4`, so `$FormatEnumerationLimit + 1` is `5` and not `1`.
_ENGINE_SUPPLIED_VARIABLES = PS1_AUTOMATIC_VARIABLES | frozenset(PS1_KNOWN_VARIABLES)


def _matches_table(match: re.Match) -> _MatchTable:
    """
    The `$Matches` table a successful match leaves: the whole match under the Int32 key `0` and each
    group that took part under its own number. A group an optional quantifier skipped is absent from
    the table rather than empty, which is how 5.1 fills it — `'ac' -match '(a)(b)?(c)'` leaves keys
    `0`, `1` and `3` and reads `$Matches[2]` as `$null`.
    """
    entries: dict[int, str] = {0: match.group(0)}
    for index in range(1, match.re.groups + 1):
        captured = match.group(index)
        if captured is not None:
            entries[index] = captured
    return _MatchTable(entries)


def _fact_of_value(value: _Value) -> Ps1Fact:
    """
    The fact a computed value denotes, keeping the kinds the interpreter's currency carries: a
    `_Char` builds the Char fact and a `_Byte` the Byte fact, both rather than the wider value the
    payload alone names; a `_CharArray` names nothing, because a `Char[]` has no spelling; and a
    plain collection is built elementwise under the same rule, since every producer of one other
    than the `char[]` cast — a pipeline, an array literal, an `@()` — builds an `Object[]` on the
    host, whose elements a cast of a numeral spells exactly. Everything else is `fact_of`'s to
    answer.
    """
    if isinstance(value, _Char):
        return char_fact(str(value))
    if isinstance(value, _Byte):
        return integer_at(_BYTE_WIDTH, int(value))
    if isinstance(value, _CharArray):
        return UNKNOWN
    if isinstance(value, list):
        return collection_fact(_fact_of_value(one) for one in value)
    return fact_of(value)


def _rendered_value(value: _Value) -> Expression | None:
    """
    The expression that spells a computed value, or `None` where nothing does.

    This is the output half of the rule `_value_of` holds at the input: a value leaves the
    interpreter only where the fact it denotes reads back from the spelling `render` writes, so a
    spelling that would fold out as a different value refuses rather than installs. `None` is
    refused here although `render` spells it, for the reason `_value_to_node` states.
    """
    if value is None:
        return None
    fact = _fact_of_value(value)
    expression = render(fact)
    if expression is None:
        return None
    return expression if read(expression) == fact else None


class _Ps1InterpreterError(Exception):
    pass


class _ReturnSignal(Exception):
    """
    A `return` unwinding to the block it leaves, carrying the success **stream** written up to that
    point rather than the value it collapses to.

    The stream is what it has to be, for the reason `_Ps1Interpreter.emit` states: collapsing here
    and letting the catcher re-assemble runs one object through the same lossy step twice, and
    `return ,($x, $y)` then hands out the two values where the bare expression hands out the one
    array. A `return` writes to the stream exactly as the expression alone does, so it must reach
    its catcher in the same shape.
    """
    def __init__(self, stream: list[_Value]):
        self.stream = stream


class InvokeExpression(Exception):
    """
    Raised when the interpreter encounters `Invoke-Expression` with a string argument. Instead of
    attempting to execute the string (which may contain constructs the interpreter cannot handle),
    the string is propagated upward so the function evaluator can emit it as a literal replacement.
    """
    def __init__(self, code: str):
        self.code = code


class _BreakSignal(Exception):
    pass


class _ContinueSignal(Exception):
    pass


_WILDCARD_METACHARACTERS = frozenset('()[.?*{}^$+|\\')


def _append_wildcard_literal(regex: list[str], char: str) -> None:
    if char in _WILDCARD_METACHARACTERS:
        regex.append('\\')
    regex.append(char)


def _append_wildcard_set_member(regex: list[str], char: str) -> None:
    if char == '[':
        regex.append('[')
    elif char == ']':
        regex.append('\\]')
    elif char == '-':
        regex.append('\\x2d')
    else:
        _append_wildcard_literal(regex, char)


def _append_wildcard_set(regex: list[str], members: list[str], ranges: list[bool]) -> None:
    regex.append('[')
    index = 0
    count = len(members)
    while index < count:
        if index + 2 < count and ranges[index + 1]:
            lower, upper = members[index], members[index + 2]
            index += 3
            if lower > upper:
                raise _Ps1InterpreterError
            _append_wildcard_set_member(regex, lower)
            regex.append('-')
            _append_wildcard_set_member(regex, upper)
        else:
            _append_wildcard_set_member(regex, members[index])
            index += 1
    regex.append(']')


def _wildcard_to_regex(pattern: str) -> str:
    """
    Translate a PowerShell wildcard pattern into the regular expression 5.1 compiles it to, so that
    `-like` reads a pattern the way the host does rather than the way `fnmatch` does. A backtick
    escapes the character behind it; `*` is any run and `?` is one character; a `[...]` set holds
    literal characters and `a-z` ranges, and inside it `^`, `[` and `!` are literal, so `[!a]` is
    the two-character set `!a` and not a negated class. An unterminated set or a reversed range is
    a pattern 5.1 rejects, so the fold is refused rather than guessed.
    """
    regex: list[str] = ['^']
    escaped = False
    opened_set = False
    inside_set = False
    members: list[str] = []
    ranges: list[bool] = []
    for char in pattern:
        if inside_set:
            if char == ']' and not opened_set and not escaped:
                inside_set = False
                _append_wildcard_set(regex, members, ranges)
                members, ranges = [], []
            elif char != '`' or escaped:
                members.append(char)
                ranges.append(char == '-' and not escaped)
            opened_set = False
        elif char == '*' and not escaped:
            regex.append('.*')
        elif char == '?' and not escaped:
            regex.append('.')
        elif char == '[' and not escaped:
            inside_set = True
            opened_set = True
            members, ranges = [], []
        elif char != '`' or escaped:
            _append_wildcard_literal(regex, char)
        escaped = char == '`' and not escaped
    if inside_set:
        raise _Ps1InterpreterError
    if escaped and pattern != '`':
        _append_wildcard_literal(regex, pattern[-1])
    regex.append('$')
    return ''.join(regex)


def _strict_mode_flags(cache) -> tuple[bool, bool]:
    """
    The two strict-mode questions every driver that emulates a body asks of the fault reach: whether
    `Set-StrictMode -Version 2` may be in force, under which the object adapter's faked `Count` on
    `$null` raises, and whether any `Set-StrictMode` may be, under which a read of a never-assigned
    name is a statement-terminating error. One place reads them, so a driver that emulates a body
    cannot leave one of the two out.
    """
    return (
        cache.faults.strict_mode_v2_may_be_in_force(),
        cache.faults.strict_mode_may_be_in_force(),
    )


class _Ps1Interpreter:

    def __init__(
        self,
        max_iterations: int = _MAX_INTERPRETER_ITERATIONS,
        max_string_len: int = _MAX_INTERPRETER_STRING_LEN,
        functions: Mapping[str, Ps1FunctionDefinition] | None = None,
        parent_env: Mapping[str, _Value] | None = None,
        depth: int = 0,
        caller_scope_names: frozenset[str] = frozenset(),
        strict_v2_may_be_in_force: bool = True,
        strict_may_be_in_force: bool = False,
    ):
        self.max_iterations = max_iterations
        self.max_string_len = max_string_len
        self._functions: Mapping[str, Ps1FunctionDefinition] = functions or {}
        self._parent_env: Mapping[str, _Value] | None = parent_env
        self._env: dict[str, _Value] = {}
        self._iterations = 0
        self._depth = depth
        #: Whether the script may arm `Set-StrictMode -Version 2`, under which the `Count` and
        #: `Length` the object adapter fakes onto `$null` raise rather than answer. The default is
        #: the safe one: a body evaluated without a script to scan for the arming withholds those
        #: fakes. Only the driver that has scanned the whole script lowers it. See
        #: `_resolve_property`.
        self._strict_v2 = strict_v2_may_be_in_force
        #: Whether the script may arm `Set-StrictMode` at any version, under which a read of a
        #: never-assigned name is a statement-terminating error rather than the `$null` a default
        #: read answers. This gates an *existing* fold, so the default is the current behaviour —
        #: a body evaluated without a script to scan reads an unset name as `$null` — and only the
        #: driver that measured the arming raises it. See `_eval_variable`.
        self._strict = strict_may_be_in_force
        #: The names an enclosing scope this fold was entered without may bind — the script-scope
        #: writes the driver gives it. A read of one before this body writes it is refused, not
        #: read as `$null`; see `_eval_variable`.
        self._caller_scope_names = caller_scope_names
        #: Whether a statement has handed `$null` to the success stream, which `_append` drops —
        #: the registered mid-stream defect, held as a fact a driver with the choice may refuse
        #: the fold over rather than install a stream shorter than the one 5.1 assembles.
        self._dropped_null = False

    def _lookup(self, key: str) -> _Value:
        """
        Read a variable through the scope chain: the local scope first, then enclosing scopes.
        """
        if key in self._env:
            return self._env[key]
        if self._parent_env is not None:
            return self._parent_env.get(key)
        return None

    def _written(self, key: str) -> bool:
        """
        Whether the emulated code has written this name anywhere in the scope chain it holds.

        `_lookup` answers `$null` both for a name written `$null` and for one no emulated scope has
        touched, which is the right answer for a *read* — the caller scope this interpreter is
        entered without is a hole it has always had — and the wrong one wherever the two differ.
        `$OFS` is where they differ, so that is what asks this.
        """
        if key in self._env:
            return True
        return self._parent_env is not None and key in self._parent_env

    def emit(
        self,
        script_block: Ps1ScriptBlock,
        bindings: dict[str, _Value],
    ) -> list[_Value]:
        """
        The success stream a script block writes: one entry per object it hands out.

        `execute` is this collapsed, and the two are separate entries because **the collapse is
        lossy in exactly the way a pipeline needs**. A block emitting one two-element array and a
        block emitting two values collapse to the same Python list, and nothing downstream can
        tell them apart afterwards — measured, they are different pipelines: `@(1, 2) | %{ ,($_,
        $_) }` has `.Count` 2 with an `Object[]` at each position, where `%{ $_, $_ }` has
        `.Count` 4. A caller assembling a pipeline's own stream out of per-item results therefore
        asks this, and one that wants the value a call produced asks `execute`.
        """
        if script_block.begin_block or script_block.process_block:
            raise _Ps1InterpreterError
        if script_block.end_block or script_block.dynamicparam_block:
            raise _Ps1InterpreterError
        self._env = dict(bindings)
        self._iterations = 0
        stream: list[_Value] = []
        try:
            for statement in script_block.body:
                self._emit_stmt(statement, stream)
        except _ReturnSignal as signal:
            return signal.stream
        except (_BreakSignal, _ContinueSignal):
            # A loop exit that reached this boundary left every loop the emulation ran: 5.1 sends
            # it on to a loop *outside* the emulated body, which is a program state this holds no
            # value for. The loops inside the body catch these signals before they get here.
            raise _Ps1InterpreterError
        return stream

    def execute(
        self,
        script_block: Ps1ScriptBlock,
        bindings: dict[str, _Value],
    ) -> _Value:
        return self._collapse(self.emit(script_block, bindings))

    def _exec_statements(self, stmts: list) -> _Value:
        """
        Execute a statement list and return the collapsed success-stream value, mirroring how
        PowerShell assembles a function/scriptblock result: assignments and redirected pipelines
        emit nothing, every other statement contributes its value, and the accumulated output
        collapses to `$null` (none), a scalar (one), or a list (many).
        """
        stream: list = []
        for stmt in stmts:
            self._emit_stmt(stmt, stream)
        return self._collapse(stream)

    def _append(self, stream: list, value: _Value):
        if value is None:
            self._dropped_null = True
            return
        if isinstance(value, list):
            stream.extend(value)
        else:
            stream.append(value)

    @staticmethod
    def _collapse(stream: list) -> _Value:
        if not stream:
            return None
        if len(stream) == 1:
            return stream[0]
        return list(stream)

    def _emit_stmt(self, stmt, stream: list):
        if isinstance(stmt, Ps1ExpressionStatement):
            if isinstance(stmt.expression, Ps1AssignmentExpression):
                self._eval(stmt.expression)
            else:
                self._append(stream, self._eval(stmt.expression))
            return
        if isinstance(stmt, Ps1Pipeline):
            self._append(stream, self._exec_pipeline(stmt))
            return
        if isinstance(stmt, Ps1ForLoop):
            self._exec_for(stmt, stream)
            return
        if isinstance(stmt, Ps1ForEachLoop):
            self._exec_foreach(stmt, stream)
            return
        if isinstance(stmt, Ps1WhileLoop):
            self._exec_while(stmt, stream)
            return
        if isinstance(stmt, Ps1DoLoop):
            self._exec_do_loop(stmt, stream)
            return
        if isinstance(stmt, Ps1IfStatement):
            self._exec_if(stmt, stream)
            return
        if isinstance(stmt, Ps1SwitchStatement):
            self._exec_switch(stmt, stream)
            return
        if isinstance(stmt, Ps1ReturnStatement):
            if stmt.pipeline:
                self._append(stream, self._eval(stmt.pipeline))
            raise _ReturnSignal(list(stream))
        if isinstance(stmt, Ps1BreakStatement):
            raise _BreakSignal
        if isinstance(stmt, Ps1ContinueStatement):
            raise _ContinueSignal
        raise _Ps1InterpreterError

    def _exec_pipeline(self, node: Ps1Pipeline) -> _Value:
        """
        The value a one-stage pipeline hands the body around it. An element is where the parser
        writes a redirection that follows an expression — a command keeps its own — so the two
        questions `_eval_command` asks a redirected command are asked of the element here, with
        the answers it gives there: a redirection that opens a file ends the emulation rather
        than answer for a file the source writes, and a discard takes the value away where a
        merge leaves it standing.
        """
        if len(node.elements) != 1:
            raise _Ps1InterpreterError
        elem = node.elements[0]
        if not isinstance(elem, Ps1PipelineElement):
            raise _Ps1InterpreterError
        if opens_a_redirection_target(elem):
            raise _Ps1InterpreterError
        result = self._eval(elem.expression)
        return None if takes_output_away(elem) else result

    def _exec_for(self, node: Ps1ForLoop, stream: list):
        if node.initializer:
            self._eval(node.initializer)
        while True:
            self._tick()
            if node.condition:
                if not self._truthy(self._eval(node.condition)):
                    break
            try:
                self._exec_block(node.body, stream)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
            if node.iterator:
                self._eval(node.iterator)

    def _exec_foreach(self, node: Ps1ForEachLoop, stream: list):
        if not isinstance(node.variable, Ps1Variable):
            raise _Ps1InterpreterError
        key = node.variable.name.lower()
        iterable = self._eval(node.iterable)
        if isinstance(iterable, list):
            items: list = iterable
        else:
            items = [iterable]
        for item in items:
            self._tick()
            self._env[key] = item
            try:
                self._exec_block(node.body, stream)
            except _BreakSignal:
                break
            except _ContinueSignal:
                continue

    def _exec_while(self, node: Ps1WhileLoop, stream: list):
        while True:
            self._tick()
            if not self._truthy(self._eval(node.condition)):
                break
            try:
                self._exec_block(node.body, stream)
            except _BreakSignal:
                break
            except _ContinueSignal:
                continue

    def _exec_do_loop(self, node: Ps1DoLoop, stream: list):
        while True:
            self._tick()
            try:
                self._exec_block(node.body, stream)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
            truth = self._truthy(self._eval(node.condition))
            if node.is_until == truth:
                break

    def _exec_if(self, node: Ps1IfStatement, stream: list):
        for condition, body in node.clauses:
            if self._truthy(self._eval(condition)):
                self._exec_block(body, stream)
                return
        if node.else_block:
            self._exec_block(node.else_block, stream)

    def _exec_switch(self, node: Ps1SwitchStatement, stream: list):
        if node.regex or node.wildcard or node.file:
            raise _Ps1InterpreterError
        value = self._eval(node.value)
        default_block = None
        matched = False
        for condition, block in node.clauses:
            if condition is None:
                default_block = block
                continue
            cond_val = self._eval(condition)
            if switch_matches(value, cond_val, case_sensitive=node.case_sensitive):
                matched = True
                try:
                    self._exec_block(block, stream)
                except _BreakSignal:
                    return
        if not matched and default_block is not None:
            try:
                self._exec_block(default_block, stream)
            except _BreakSignal:
                return

    def _exec_block(self, block, stream: list):
        if block is None:
            return
        if isinstance(block, Block):
            for stmt in block.body:
                self._emit_stmt(stmt, stream)
            return
        raise _Ps1InterpreterError

    def _tick(self):
        self._iterations += 1
        if self._iterations > self.max_iterations:
            raise _Ps1InterpreterError

    @staticmethod
    def _numeral(literal: Ps1IntegerLiteral) -> int:
        """
        The number an integer literal spells, asked of the value domain rather than of the node's
        derived `value`: a hexadecimal numeral names the pattern its digits fill and not the
        magnitude they read as, so `0xFFFFFFFF` is -1 and `0xFFFFFFFFL` is 4294967295. The bound
        argument of a call is read the same way — see
        `Ps1FunctionEvaluator._extract_constant_value` — and a body that answered differently from
        its own call site would be two readers of one spelling.
        """
        found = integer_of(read(literal))
        if found is None:
            raise _Ps1InterpreterError
        return found

    @staticmethod
    def _real(literal: Ps1RealLiteral) -> _Value:
        """
        The number a real literal spells, asked of the value domain for the reason `_numeral` gives
        and refused where this currency cannot hold it.

        A multiplier suffix does not make a numeral a fraction: measured, `1kb` is the Int32 1024
        where the node's derived `value` is the float 1024.0, and since `_value_to_node` spells a
        float as a `Double` the derived reading wrote a type the script never had. A `Decimal` — the
        `d` suffix — has no place in this currency at all and is declined rather than flattened onto
        a `Double`, which is the same rule `_value_of` states for a bound argument.
        """
        ok, value = _value_of(read(literal))
        if not ok:
            raise _Ps1InterpreterError
        return value

    def _eval(self, expr) -> _Value:
        if expr is None:
            return None
        if isinstance(expr, Ps1StringLiteral):
            return expr.value
        if isinstance(expr, Ps1ExpandableString):
            return self._eval_string_parts(expr.parts)
        if isinstance(expr, Ps1ExpandableHereString):
            return self._eval_string_parts(expr.parts)
        if isinstance(expr, Ps1HereString):
            return expr.value
        if isinstance(expr, Ps1IntegerLiteral):
            return self._numeral(expr)
        if isinstance(expr, Ps1RealLiteral):
            return self._real(expr)
        if isinstance(expr, Ps1Variable):
            return self._eval_variable(expr)
        if isinstance(expr, Ps1AssignmentExpression):
            return self._eval_assignment(expr)
        if isinstance(expr, Ps1BinaryExpression):
            return self._eval_binary(expr)
        if isinstance(expr, Ps1UnaryExpression):
            return self._eval_unary(expr)
        if isinstance(expr, Ps1ParenExpression):
            return self._eval(expr.expression)
        if isinstance(expr, Ps1MemberAccess):
            return self._eval_member_access(expr)
        if isinstance(expr, Ps1InvokeMember):
            return self._eval_invoke_member(expr)
        if isinstance(expr, Ps1IndexExpression):
            return self._eval_index(expr)
        if isinstance(expr, Ps1ArrayLiteral):
            return [self._eval(e) for e in expr.elements]
        if isinstance(expr, Ps1ArrayExpression):
            return self._eval_array_expression(expr)
        if isinstance(expr, Ps1CastExpression):
            return self._eval_cast(expr)
        if isinstance(expr, Ps1SubExpression):
            return self._exec_statements(expr.body)
        if isinstance(expr, Ps1Pipeline):
            return self._exec_pipeline(expr)
        if isinstance(expr, Ps1PipelineElement):
            if expr.redirections:
                raise _Ps1InterpreterError
            return self._eval(expr.expression)
        if isinstance(expr, Ps1CommandInvocation):
            return self._eval_command(expr)
        raise _Ps1InterpreterError

    def _eval_command(self, node: Ps1CommandInvocation) -> _Value:
        """
        The value a command in the emulated body produces, or `_Ps1InterpreterError` when this
        cannot say.

        A redirection is two questions and both have to be asked, because neither implies the other
        and they have different answers. Opening a file is work this cannot do: PowerShell creates
        or truncates the target as it sets the redirection up whatever the command then writes, so
        folding the enclosing call into the result would delete a file the script produced, and the
        only honest answer is that this cannot say. Taking the output away is not a reason to stop —
        the command still runs, and `Invoke-Expression $code > $Null` still hands its code out — it
        only means the value never reaches the caller: `$a = j > $Null` binds `$a` to `$null`. So it
        is asked *after* the command has been evaluated and discards what came back. Asking it
        before would refuse a body this can fold; not asking it at all answers `4` for
        `$a = New-Object byte[] 4 > $Null; $a.Length`. A merge that neither opens nor takes —
        `j 2>&1` — leaves both alone.

        The call site asks its own, blunter question through
        `refinery.lib.scripts.ps1.deobfuscation.substitution.may_substitute`, because there the
        replacement stands where the redirection was written and changes what it evaluates to.
        """
        if opens_a_redirection_target(node):
            raise _Ps1InterpreterError
        value = self._eval_command_value(node)
        return None if takes_output_away(node) else value

    def _eval_command_value(self, node: Ps1CommandInvocation) -> _Value:
        if not isinstance(node.name, Ps1StringLiteral):
            raise _Ps1InterpreterError
        name = node.name.value.lower()
        builtin = name.replace('-', '')
        if builtin in ('iex', 'invokeexpression'):
            return self._eval_iex(node)
        if builtin == 'newobject':
            return self._eval_new_object(node)
        return self._eval_user_function_call(node, name)

    def _eval_iex(self, node: Ps1CommandInvocation) -> _Value:
        positional = self._collect_positional_args(node)
        if len(positional) != 1:
            raise _Ps1InterpreterError
        code_str = positional[0]
        if not isinstance(code_str, str):
            raise _Ps1InterpreterError
        raise InvokeExpression(code_str)

    def _eval_user_function_call(
        self, node: Ps1CommandInvocation, cmd: str,
    ) -> _Value:
        funcdef = self._functions.get(cmd)
        if funcdef is None:
            raise _Ps1InterpreterError
        if self._depth >= _MAX_INTERPRETER_DEPTH:
            raise _Ps1InterpreterError
        body = funcdef.body
        if body is None:
            raise _Ps1InterpreterError
        if body.begin_block or body.process_block:
            raise _Ps1InterpreterError
        if body.end_block or body.dynamicparam_block:
            raise _Ps1InterpreterError
        positional = self._collect_positional_args(node)
        bindings = Ps1FunctionEvaluator._bind_parameters(funcdef, positional)
        if bindings is None:
            raise _Ps1InterpreterError
        if self._parent_env is None:
            parent_env: Mapping[str, _Value] = self._env
        else:
            parent_env = ChainMap(self._env, self._parent_env)
        child = _Ps1Interpreter(
            max_iterations=self.max_iterations - self._iterations,
            max_string_len=self.max_string_len,
            functions=self._functions,
            parent_env=parent_env,
            depth=self._depth + 1,
            caller_scope_names=self._caller_scope_names,
            strict_v2_may_be_in_force=self._strict_v2,
            strict_may_be_in_force=self._strict,
        )
        try:
            result = child.execute(body, bindings)
        except InvokeExpression as iex:
            return self._resolve_iex_code(iex.code)
        finally:
            self._iterations += child._iterations
        return result

    def _resolve_iex_code(self, code: str) -> _Value:
        """
        When a called function raises `InvokeExpression`, the code string may be a simple variable
        reference like `$varName`. Resolve it in the current scope before propagating the signal.
        """
        from refinery.lib.scripts.ps1.parser import Ps1Parser
        try:
            parsed = Ps1Parser(code).parse()
        except Exception:
            raise InvokeExpression(code)
        if (
            len(parsed.body) == 1
            and isinstance(parsed.body[0], Ps1ExpressionStatement)
        ):
            expr = parsed.body[0].expression
            if isinstance(expr, Ps1Variable):
                resolved = self._eval_variable(expr)
                if isinstance(resolved, str):
                    raise InvokeExpression(resolved)
                raise _Ps1InterpreterError
        raise InvokeExpression(code)

    def _collect_positional_args(self, node: Ps1CommandInvocation) -> list[_Value]:
        positional: list[_Value] = []
        for arg in node.arguments:
            if isinstance(arg, Ps1CommandArgument):
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    continue
                expr = arg.value
            elif isinstance(arg, Expression):
                expr = arg
            else:
                continue
            positional.append(self._eval(expr) if expr is not None else None)
        return positional

    def _eval_new_object(self, node: Ps1CommandInvocation) -> _Value:
        positional = self._collect_positional_args(node)
        if len(positional) != 2:
            raise _Ps1InterpreterError
        type_name = positional[0]
        if not isinstance(type_name, str) or not type_name.lower().endswith('[]'):
            raise _Ps1InterpreterError
        size_arg = positional[1]
        try:
            size = self._to_int(size_arg)
        except _Ps1InterpreterError:
            # A size that 5.1's `[int]` converter refuses is a non-terminating error, so the cmdlet
            # writes `$null` and the body runs on rather than throwing. Only a String reaches that
            # converter; a value this cannot read at all leaves the fold refused. A Char never
            # refuses — it reads as its code point in the branch above — so it is not seen here.
            if isinstance(size_arg, str):
                return None
            raise
        if size < 0 or size > self.max_string_len:
            raise _Ps1InterpreterError
        return [0] * size

    def _eval_string_parts(self, parts: list) -> str:
        out: list[str] = []
        for part in parts:
            if isinstance(part, Ps1StringLiteral):
                out.append(part.value)
            elif isinstance(part, Ps1SubExpression):
                val = self._exec_statements(part.body)
                out.append(self._to_str(val))
            else:
                out.append(self._to_str(self._eval(part)))
        result = ''.join(out)
        if len(result) > self.max_string_len:
            raise _Ps1InterpreterError
        return result

    def _eval_array_expression(self, expr: Ps1ArrayExpression) -> list:
        results: list[_Value] = []
        for stmt in expr.body:
            self._emit_stmt(stmt, results)
        return results

    def _eval_variable(self, node: Ps1Variable) -> _Value:
        if node.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        name = node.name.lower()
        if name == 'true':
            return True
        if name == 'false':
            return False
        if name == 'null':
            return None
        if name == 'psitem':
            name = '_'
        if name in _ENGINE_SUPPLIED_VARIABLES and not self._written(name):
            # An engine-supplied variable holds state this body does not carry: the pipeline item
            # of the caller, `$args` of a call that supplied none, the `$Matches` an earlier match
            # left, and the session scalars such as `$FormatEnumerationLimit` the host seeds with a
            # value no isolated body knows. Reading one as `$null` because no scope here wrote it is
            # a wrong answer every caller of the interpreter shares, so the refusal lives here and
            # not in one driver. A write the emulated code itself performed — the `matches` a
            # `-match` inside the body refills, the `_` a driver seeds — is what `_written` clears
            # it on.
            raise _Ps1InterpreterError
        if name in self._caller_scope_names and not self._written(name):
            # A name an enclosing scope binds, read before this body writes it, is refused rather
            # than read as `$null`: the caller scope this fold is entered without may hold the value
            # (see `Ps1SemanticModel.script_scope_write_names`). `$q = $env:Temp; function f { $q + 1
            # }` is `$env:Temp + 1` on the host, not `1`. A name no enclosing scope writes is
            # genuinely unset, so an accumulator `$r = $r + …` still reads its first `$r` as `$null`
            # and folds.
            raise _Ps1InterpreterError
        if self._strict and not self._written(name):
            # Under `Set-StrictMode` a read of a never-assigned name is a statement-terminating
            # error, not the `$null` an isolated body reads it as, so the fold is withheld rather
            # than answered with a value 5.1 throws on — including the accumulator's first `$r`,
            # which is exactly such a read.
            raise _Ps1InterpreterError
        return self._lookup(name)

    def _eval_assignment(self, node: Ps1AssignmentExpression) -> _Value:
        if isinstance(node.target, Ps1IndexExpression):
            return self._eval_index_assignment(node)
        if not isinstance(node.target, Ps1Variable):
            raise _Ps1InterpreterError
        if node.target.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        key = node.target.name.lower()
        value = self._eval(node.value)
        op = node.operator
        if op == '=':
            self._env[key] = value
        elif op == '+=':
            # PowerShell compound assignment reads only the local scope (verified): a `$x += v`
            # against a variable that exists only in an enclosing scope starts from $null, unlike a
            # plain read of `$x`. Do NOT look through the scope chain here.
            current = self._env.get(key)
            self._env[key] = self._add(current, value)
        elif op == '-=':
            current = self._env.get(key)
            self._env[key] = self._numeric_op(current, value, int.__sub__, float.__sub__)
        elif op == '*=':
            current = self._env.get(key)
            if isinstance(current, bool):
                raise _Ps1InterpreterError
            self._env[key] = self._numeric_op(current, value, int.__mul__, float.__mul__)
        else:
            raise _Ps1InterpreterError
        return self._env[key]

    def _eval_index_assignment(self, node: Ps1AssignmentExpression) -> _Value:
        target = node.target
        if not isinstance(target, Ps1IndexExpression):
            raise _Ps1InterpreterError
        if not isinstance(target.object, Ps1Variable):
            raise _Ps1InterpreterError
        if target.object.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        if node.operator != '=':
            raise _Ps1InterpreterError
        key = target.object.name.lower()
        lst = self._lookup(key)
        if not isinstance(lst, list):
            raise _Ps1InterpreterError
        idx = self._to_index(self._eval(target.index))
        value = self._eval(node.value)
        try:
            lst[idx] = value
        except IndexError:
            raise _Ps1InterpreterError
        return value

    def _eval_binary(self, node: Ps1BinaryExpression) -> _Value:
        op = node.operator.lower()
        if op == '-as':
            if not isinstance(node.right, Ps1TypeExpression):
                raise _Ps1InterpreterError
            left = self._eval(node.left)
            return self._apply_type_cast(node.right.name, left)
        left = self._eval(node.left)
        if op == '-and':
            return self._truthy(left) and self._truthy(self._eval(node.right))
        if op == '-or':
            return self._truthy(left) or self._truthy(self._eval(node.right))
        right = self._eval(node.right)
        if isinstance(left, bool) and op in _NO_OPERATOR_METHOD_ON_BOOLEAN:
            raise _Ps1InterpreterError
        if isinstance(left, _Char) and op in _NO_OPERATOR_METHOD_ON_CHAR:
            raise _Ps1InterpreterError
        if op == '+':
            return self._add(left, right)
        if op == '-':
            return self._numeric_op(left, right, int.__sub__, float.__sub__)
        if op == '*':
            return self._multiply(left, right)
        if op == '/':
            return self._numeric_op(left, right, ps_divide, ps_divide)
        if op == '%':
            return self._numeric_op(left, right, ps_modulo, ps_modulo)
        if op == '-band':
            return self._int_op(left, right, int.__and__)
        if op == '-bor':
            return self._int_op(left, right, int.__or__)
        if op == '-bxor':
            return self._int_op(left, right, int.__xor__)
        if op == '-shl':
            return self._shifted(left, right, ps_shift_left)
        if op == '-shr':
            return self._shifted(left, right, ps_shift_right)
        if op == '-xor':
            return self._truthy(left) != self._truthy(right)
        cmp_fn = COMPARISON_OPS.get(op)
        if cmp_fn is not None:
            return self._compare(left, right, cmp_fn)
        if op in ('-split', '-csplit', '-isplit'):
            return self._eval_split(left, right, op)
        if op == '-join':
            return self._eval_join(left, right)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._eval_replace(left, right, op)
        if op in ('-match', '-cmatch', '-imatch'):
            return self._eval_match(left, right, op)
        if op in ('-notmatch', '-cnotmatch', '-inotmatch'):
            return not self._eval_match(left, right, op)
        if op == '-contains':
            return self._eval_contains(left, right)
        if op == '-notcontains':
            return not self._eval_contains(left, right)
        if op == '-in':
            return self._eval_contains(right, left)
        if op == '-notin':
            return not self._eval_contains(right, left)
        if op in ('-like', '-clike', '-ilike'):
            return self._eval_like(left, right, op)
        if op in ('-notlike', '-cnotlike', '-inotlike'):
            return not self._eval_like(left, right, op)
        raise _Ps1InterpreterError

    def _eval_unary(self, node: Ps1UnaryExpression) -> _Value:
        op = node.operator
        if op in ('++', '--'):
            if not isinstance(node.operand, Ps1Variable):
                raise _Ps1InterpreterError
            key = node.operand.name.lower()
            current = self._lookup(key)
            if not isinstance(current, (int, float)):
                current = 0
            delta = 1 if op == '++' else -1
            new_val = current + delta
            self._env[key] = new_val
            return current if not node.prefix else new_val
        if op.lower() == '-not' or op == '!':
            return not self._truthy(self._eval(node.operand))
        if op.lower() == '-bnot':
            val = self._eval(node.operand)
            if not isinstance(val, int):
                raise _Ps1InterpreterError
            return ~int(val)
        if op == '-':
            val = self._eval(node.operand)
            if isinstance(val, int):
                return -val
            if isinstance(val, float):
                return -val
            raise _Ps1InterpreterError
        if op.lower() == '-split':
            val = self._eval(node.operand)
            parts = re.split(r'\s+', self._coerce_str(val))
            return [p for p in parts if p]
        if op.lower() == '-join':
            val = self._eval(node.operand)
            if isinstance(val, list):
                return ''.join(self._coerce_str(item) for item in val)
            return self._coerce_str(val)
        raise _Ps1InterpreterError

    _MEMBER_ARITHMETIC = re.compile(r'^(\w+)([+\-])(\d+)$')

    def _eval_member_access(self, node: Ps1MemberAccess) -> _Value:
        obj = self._eval(node.object)
        member = get_member_name(node.member)
        if member is None:
            raise _Ps1InterpreterError
        name = member.lower()
        result = self._resolve_property(obj, name)
        if result is not None:
            return result
        # Handle parser quirk: $obj.Length-1 is parsed as member 'Length-1'
        m = self._MEMBER_ARITHMETIC.match(name)
        if m:
            prop = m.group(1)
            op = m.group(2)
            offset = int(m.group(3))
            base = self._resolve_property(obj, prop)
            if isinstance(base, (int, float)):
                if op == '-':
                    return base - offset
                return base + offset
        raise _Ps1InterpreterError

    def _resolve_property(self, obj: _Value, name: str) -> _Value:
        if obj is None:
            # The object adapter fakes a `Count` of 0 onto `$null`, which reads on wherever
            # `Set-StrictMode -Version 2` is not armed and raises where it is; a real `Length` it
            # does not fake, so that stays refused.
            if name == 'count' and not self._strict_v2:
                return 0
            return None
        if isinstance(obj, str):
            if name == 'length':
                return len(obj)
            return None
        if isinstance(obj, list):
            if name in ('length', 'count'):
                return len(obj)
            return None
        return None

    def _eval_invoke_member(self, node: Ps1InvokeMember) -> _Value:
        if node.access == Ps1AccessKind.STATIC:
            return self._eval_static_invoke(node)
        enc = self._try_encoding_chain(node)
        if enc is not None:
            return enc
        obj = self._eval(node.object)
        member = get_member_name(node.member)
        if member is None:
            raise _Ps1InterpreterError
        name = member.lower()
        args = [self._eval(a) for a in node.arguments]
        if isinstance(obj, _Char):
            return self._invoke_char_method(str(obj), name, args)
        if isinstance(obj, str):
            return self._invoke_string_method(obj, name, args)
        if isinstance(obj, list):
            return self._invoke_list_method(obj, name, args)
        raise _Ps1InterpreterError

    def _eval_static_invoke(self, node: Ps1InvokeMember) -> _Value:
        if not isinstance(node.object, Ps1TypeExpression):
            raise _Ps1InterpreterError
        type_name = node.object.name
        member = get_member_name(node.member)
        if member is None:
            raise _Ps1InterpreterError
        name = member.lower()
        args = [self._eval(a) for a in node.arguments]
        if is_type(type_name, 'System.Convert'):
            return self._invoke_convert(name, args)
        if is_type(type_name, 'System.Text.Encoding'):
            return self._invoke_encoding(name, args)
        if is_type(type_name, 'System.String'):
            return self._invoke_string_static(name, args)
        if is_type(type_name, 'System.Math'):
            return self._invoke_math_static(name, args)
        raise _Ps1InterpreterError

    def _invoke_convert(self, method: str, args: list[_Value]) -> _Value:
        try:
            if method == 'tobyte' and len(args) == 2:
                return _Byte(int(self._to_str(args[0]), self._to_int(args[1])) & 0xFF)
            if method == 'toint16' and len(args) == 2:
                v = int(self._to_str(args[0]), self._to_int(args[1]))
                if v >= 0x8000:
                    v -= 0x10000
                return v
            if method == 'toint32' and len(args) == 2:
                v = int(self._to_str(args[0]), self._to_int(args[1]))
                if v >= 0x80000000:
                    v -= 0x100000000
                return v
            if method == 'toint64' and len(args) == 2:
                return int(self._to_str(args[0]), self._to_int(args[1]))
            if method == 'tochar' and len(args) == 1:
                return _Char(chr(self._to_int(args[0])))
            if method == 'tostring' and len(args) == 1:
                return self._to_str(args[0])
            if method == 'frombase64string' and len(args) == 1:
                return list(base64.b64decode(self._to_str(args[0])))
            if method == 'tobase64string' and len(args) == 1:
                value = args[0]
                if not isinstance(value, list):
                    raise _Ps1InterpreterError
                return base64.b64encode(bytearray(int(b) for b in value)).decode('ascii')
        except (ValueError, OverflowError, TypeError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_encoding(self, method: str, args: list[_Value]) -> _Value:
        encoding = ENCODING_MAP.get(method)
        if encoding is None or len(args) != 1:
            raise _Ps1InterpreterError
        return self._decode_byte_list(args[0], encoding)

    def _try_encoding_chain(self, node: Ps1InvokeMember) -> _Value | None:
        enc_name = detect_encoding_chain(node)
        if enc_name is None:
            return None
        encoding = ENCODING_MAP.get(enc_name.lower(), enc_name.lower())
        if len(node.arguments) != 1:
            raise _Ps1InterpreterError
        arg = self._eval(node.arguments[0])
        return self._decode_byte_list(arg, encoding)

    def _decode_byte_list(self, value: _Value, encoding: str) -> str:
        if not isinstance(value, list):
            raise _Ps1InterpreterError
        try:
            raw = bytearray(int(b) for b in value)
            return raw.decode(encoding)
        except (ValueError, OverflowError, TypeError, UnicodeDecodeError, LookupError):
            raise _Ps1InterpreterError

    def _invoke_string_static(self, method: str, args: list[_Value]) -> _Value:
        if method == 'join' and len(args) >= 2:
            separator = self._to_str(args[0])
            if len(args) > 2 or not isinstance(args[1], list):
                return separator.join(self._to_str(a) for a in args[1:])
            return separator.join(self._to_str(item) for item in args[1])
        if method == 'format' and len(args) >= 1:
            fmt = self._to_str(args[0])
            str_args = [self._to_str(a) for a in args[1:]]
            result = apply_format_string(fmt, str_args)
            if result is None:
                raise _Ps1InterpreterError
            return result
        if method == 'isnullorempty' and len(args) == 1:
            v = args[0]
            return v is None or (isinstance(v, str) and len(v) == 0)
        if method == 'concat' and len(args) >= 1:
            return ''.join(self._to_str(a) for a in args)
        raise _Ps1InterpreterError

    def _invoke_math_static(self, method: str, args: list[_Value]) -> _Value:
        import math
        try:
            if method == 'abs' and len(args) == 1:
                v = args[0]
                if isinstance(v, int):
                    return abs(v)
                if isinstance(v, float):
                    return abs(v)
            if method == 'floor' and len(args) == 1:
                val = self._to_float(args[0])
                return int(math.floor(val))
            if method == 'ceiling' and len(args) == 1:
                val = self._to_float(args[0])
                return int(math.ceil(val))
            if method == 'round' and len(args) in (1, 2):
                val = self._to_float(args[0])
                digits = self._to_int(args[1]) if len(args) == 2 else 0
                result = round(val, digits)
                return int(result) if digits == 0 else result
            if method == 'pow' and len(args) == 2:
                base = self._to_float(args[0])
                exp = self._to_float(args[1])
                result = math.pow(base, exp)
                return int(result) if result == int(result) else result
            if method == 'sqrt' and len(args) == 1:
                val = self._to_float(args[0])
                return math.sqrt(val)
            if method == 'min' and len(args) == 2:
                a = args[0] if isinstance(args[0], (int, float)) else self._to_int(args[0])
                b = args[1] if isinstance(args[1], (int, float)) else self._to_int(args[1])
                return min(a, b)
            if method == 'max' and len(args) == 2:
                a = args[0] if isinstance(args[0], (int, float)) else self._to_int(args[0])
                b = args[1] if isinstance(args[1], (int, float)) else self._to_int(args[1])
                return max(a, b)
        except (ValueError, OverflowError, TypeError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_char_method(
        self, s: str, method: str, args: list[_Value],
    ) -> _Value:
        """
        A `System.Char` carries none of a String's text methods, so 5.1 throws for
        `([char]65).ToUpper()`, `.Substring(0)`, `.Trim()` and their like where it would fold the
        same call on a String. Only `ToString`, which every value answers, folds here, and it
        yields the one-character String the Char spells; everything else refuses so the fold stops
        where the script would.
        """
        if method == 'tostring' and not args:
            return s
        raise _Ps1InterpreterError

    def _invoke_string_method(
        self, s: str, method: str, args: list[_Value],
    ) -> _Value:
        try:
            coerced = [self._to_int(a) if isinstance(a, (int, float, bool)) else self._to_str(a) for a in args]
            return apply_string_method(s, method, coerced)
        except StringMethodError:
            pass
        except (IndexError, ValueError, TypeError, OverflowError):
            raise _Ps1InterpreterError
        try:
            if method == 'tochararray' and not args:
                return _CharArray(_Char(c) for c in s)
            if method == 'padleft' and len(args) >= 1:
                width = self._to_int(args[0])
                ch = self._to_str(args[1]) if len(args) > 1 else ' '
                return s.rjust(width, ch)
            if method == 'padright' and len(args) >= 1:
                width = self._to_int(args[0])
                ch = self._to_str(args[1]) if len(args) > 1 else ' '
                return s.ljust(width, ch)
        except (IndexError, ValueError, TypeError, OverflowError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_list_method(
        self, lst: list, method: str, args: list[_Value],
    ) -> _Value:
        if method == 'contains' and len(args) == 1:
            return args[0] in lst
        raise _Ps1InterpreterError

    def _eval_index(self, node: Ps1IndexExpression) -> _Value:
        obj = self._eval(node.object)
        if isinstance(obj, _MatchTable):
            return self._match_group(obj, self._eval(node.index))
        idx = self._to_index(self._eval(node.index))
        try:
            if isinstance(obj, str):
                return _Char(obj[idx])
            if isinstance(obj, list):
                return obj[idx]
        except IndexError:
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    @staticmethod
    def _match_group(table: _MatchTable, index: _Value) -> _Value:
        """
        A subscript into `$Matches`. 5.1 keys the table by Int32 group number and reads a key it
        does not hold as `$null` — `$Matches['1']` is empty where `$Matches[1]` is the first group,
        and a group an optional quantifier skipped is no key at all — so a String or an out-of-range
        number answers absent rather than a wrong group. An index that is neither a number nor text
        is refused, so the fold stops rather than guessing which group a value names.
        """
        if isinstance(index, bool):
            raise _Ps1InterpreterError
        if isinstance(index, int):
            return table.entries.get(index)
        if isinstance(index, str):
            return None
        raise _Ps1InterpreterError

    def _eval_cast(self, node: Ps1CastExpression) -> _Value:
        val = self._eval(node.operand)
        return self._apply_type_cast(node.type_name, val)

    def _apply_type_cast(self, type_name: str, val: _Value) -> _Value:
        tn = normalize_dotnet_type_name(type_name)
        if tn == 'string':
            return self._coerce_str(val)
        if tn in ('int', 'int32', 'int64'):
            return self._to_int(val)
        if tn == 'char':
            if isinstance(val, int):
                try:
                    return _Char(chr(val))
                except (ValueError, OverflowError):
                    raise _Ps1InterpreterError
            raise _Ps1InterpreterError
        if tn == 'char[]':
            if isinstance(val, str):
                return _CharArray(_Char(c) for c in val)
            raise _Ps1InterpreterError
        if tn == 'byte':
            result = self._to_int(val)
            if not 0 <= result <= 0xFF:
                raise _Ps1InterpreterError
            return _Byte(result)
        raise _Ps1InterpreterError

    def _add(self, left: _Value, right: _Value) -> _Value:
        if left is None and isinstance(right, str):
            return right
        if isinstance(left, str) and right is None:
            return left
        if isinstance(left, str) or isinstance(right, str):
            result = self._coerce_str(left) + self._coerce_str(right)
            if len(result) > self.max_string_len:
                raise _Ps1InterpreterError
            return result
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            return self._numeric_op(left, right, int.__add__, float.__add__)
        if isinstance(left, list):
            if isinstance(right, list):
                return left + right
            return left + [right]
        raise _Ps1InterpreterError

    def _multiply(self, left: _Value, right: _Value) -> _Value:
        if isinstance(left, str) and isinstance(right, int):
            result = left * right
            if len(result) > self.max_string_len:
                raise _Ps1InterpreterError
            return result
        return self._numeric_op(left, right, int.__mul__, float.__mul__)

    @staticmethod
    def _numeric_op(left: _Value, right: _Value, int_op, float_op) -> int | float:
        if left is None:
            left = 0
        if right is None:
            right = 0
        try:
            if isinstance(left, float) or isinstance(right, float):
                return float_op(float(left), float(right))  # type: ignore
            if isinstance(left, int) and isinstance(right, int):
                return int_op(left, right)
        except (ZeroDivisionError, ValueError, OverflowError, ArithmeticError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    @staticmethod
    def _shifted(left: _Value, right: _Value, op) -> _Value:
        """
        A shift, answered at the width the left operand carries: 5.1 converts a Byte to `Int32` to
        compute the shift and back to a Byte to answer it, wrapping through the conversion —
        measured, `[byte]1 -shl 4` is the Byte `16` and `[byte]1 -shl -1` is the Byte `0`. Every
        other left operand answers the plain number it always did.
        """
        result = _Ps1Interpreter._int_op(left, right, op)
        return _Byte(result & 0xFF) if isinstance(left, _Byte) else result

    @staticmethod
    def _int_op(left: _Value, right: _Value, op) -> int:
        if left is None:
            left = 0
        if right is None:
            right = 0
        if isinstance(left, str):
            left = _Ps1Interpreter._to_int(left)
        if isinstance(right, str):
            right = _Ps1Interpreter._to_int(right)
        if isinstance(left, int) and isinstance(right, int):
            return op(left, right)
        raise _Ps1InterpreterError

    @staticmethod
    def _compare(left: _Value, right: _Value, op) -> bool:
        if isinstance(left, str) and isinstance(right, str):
            return op(left.lower(), right.lower())
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return op(left, right)
        if left is None:
            left = 0
        if right is None:
            right = 0
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return op(left, right)
        raise _Ps1InterpreterError

    def _eval_split(self, left: _Value, right: _Value, op: str) -> list:
        s = self._coerce_str(left)
        delimiter, maxsplit = self._split_delimiter_and_maxsplit(right)
        pattern = self._coerce_str(delimiter)
        flags = re.IGNORECASE if op != '-csplit' else 0
        try:
            return re.split(pattern, s, maxsplit=maxsplit, flags=flags)
        except re.error:
            raise _Ps1InterpreterError

    def _split_delimiter_and_maxsplit(self, right: _Value) -> tuple[_Value, int]:
        """
        The delimiter and the Python `maxsplit` a `-split` right operand names.

        5.1 reads a right operand that is a collection as `<delimiter>, <max-substrings>, <options>`
        in that order (`parserutils.SplitOperatorImpl`). A max-substrings of `n` caps the result at
        `n` elements, which .NET's `Regex.Split(input, n)` reaches with `n - 1` splits; a zero caps
        nothing and is the unlimited default the bare operator also passes. Python's `maxsplit` is
        `n - 1` for `n` at least two, and its zero is that same unlimited, so both map across.

        Three cases are refused rather than answered with a value 5.1 does not produce: a
        max-substrings of one, which caps at a single unsplit element that `maxsplit` cannot express
        because its zero already means unlimited; a negative one, which splits a right-to-left regex
        Python's `re` has no equivalent for; and any explicit split option.
        """
        if not isinstance(right, list):
            return right, 0
        if len(right) == 1:
            return right[0], 0
        if len(right) != 2:
            raise _Ps1InterpreterError
        limit = self._to_int(right[1])
        if limit == 0:
            return right[0], 0
        if limit < 2:
            raise _Ps1InterpreterError
        return right[0], limit - 1

    def _eval_join(self, left: _Value, right: _Value) -> str:
        separator = self._coerce_str(right)
        if isinstance(left, list):
            return separator.join(self._coerce_str(item) for item in left)
        return self._coerce_str(left)

    def _eval_replace(self, left: _Value, right: _Value, op: str) -> str:
        s = self._coerce_str(left)
        if isinstance(right, list) and len(right) == 2:
            pattern = self._coerce_str(right[0])
            replacement = self._coerce_str(right[1])
        else:
            raise _Ps1InterpreterError
        flags = re.IGNORECASE if op != '-creplace' else 0
        try:
            return dotnet_regex_replace(pattern, replacement, s, flags=flags)
        except re.error:
            raise _Ps1InterpreterError

    def _eval_match(self, left: _Value, right: _Value, op: str) -> bool:
        """
        The `-match` family, which answers whether the pattern is found and, on a find, refills the
        `$Matches` table with the whole match and every group that took part. 5.1 leaves `$Matches`
        untouched where the pattern is not found — a failed `-match` and a `-notmatch` whose pattern
        misses both read the table an earlier match left — so it is rewritten only where the search
        returns a match, and the value returned stays the bare found/not-found the operator negates.
        """
        if not isinstance(left, str) or not isinstance(right, str):
            raise _Ps1InterpreterError
        flags = re.IGNORECASE if op[1] != 'c' else 0
        try:
            found = re.search(right, left, flags=flags)
        except re.error:
            raise _Ps1InterpreterError
        if found is not None:
            self._env[_MATCHES_NAME] = _matches_table(found)
        return found is not None

    def _eval_contains(self, collection: _Value, item: _Value) -> bool:
        """
        The `-contains`/`-in` membership test: an element matches when 5.1's `LanguagePrimitives.
        Equals` holds between it and the item, which is the same equality `-eq` runs. A single
        element that matches answers `$True`; an item this cannot decide against some element leaves
        the whole test refused rather than answered `$False`, since a later element it could not
        read might have been the one that matched.
        """
        if not isinstance(collection, list):
            raise _Ps1InterpreterError
        undecided = False
        for elem in collection:
            try:
                if self._ps_equals(elem, item):
                    return True
            except _Ps1InterpreterError:
                undecided = True
        if undecided:
            raise _Ps1InterpreterError
        return False

    def _ps_equals(self, first: _Value, second: _Value, ignore_case: bool = True) -> bool:
        """
        Whether 5.1's `LanguagePrimitives.Equals(first, second, ignoreCase, InvariantCulture)`
        holds. The second operand is converted to the first's type and the two are compared, so
        `'1' -eq 1` joins on the text `'1'` and `1 -eq '1'` on the number `1`.

        The distinction this owes a wrong answer is between a conversion 5.1 *rejects* and one this
        interpreter cannot *reproduce*. A rejection — `1 -eq 'abc'`, whose right operand is no Int32 —
        is caught by 5.1 as an `InvalidCastException` and answered `$False`, so it is answered here
        the same way. A conversion whose result is the host culture's to write — a `Double` rendered
        as text, a `String` read as a `Double` — is refused with `_Ps1InterpreterError` rather than
        answered with a value 5.1 may not share.
        """
        if first is None or second is None:
            return first is None and second is None
        if isinstance(first, list) or isinstance(second, list):
            if first is second:
                return True
            raise _Ps1InterpreterError
        if isinstance(first, str):
            if isinstance(second, float):
                raise _Ps1InterpreterError
            second_string = self._to_str(second)
            if ignore_case:
                return first.lower() == second_string.lower()
            return first == second_string
        if type(first) is type(second):
            return first == second
        if self._is_number(first) and self._is_number(second):
            return first == second
        return self._equals_after_cast(first, second)

    def _equals_after_cast(self, first: _Value, second: _Value) -> bool:
        """
        `first.Equals(secondConverted)` for the scalars 5.1 reaches by converting the second operand
        to the type of the first. A `String` the target type rejects is not equal rather than a
        throw; a `String` read as a `Double` is refused, since its parse is the host culture's.
        """
        if isinstance(first, bool):
            if isinstance(second, str):
                return first == (len(second) > 0)
            return first == bool(second)
        if isinstance(first, int):
            if isinstance(second, bool):
                return first == int(second)
            if isinstance(second, str):
                try:
                    return first == self._string_to_int(second)
                except _Ps1InterpreterError:
                    return False
            raise _Ps1InterpreterError
        if isinstance(first, float):
            if isinstance(second, bool):
                return first == float(second)
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    @staticmethod
    def _is_number(value: _Value) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def _eval_like(left: _Value, right: _Value, op: str) -> bool:
        if not isinstance(left, str) or not isinstance(right, str):
            raise _Ps1InterpreterError
        flags = re.DOTALL | (re.IGNORECASE if op[1] != 'c' else 0)
        pattern = _wildcard_to_regex(right)
        try:
            return re.match(pattern, left, flags=flags) is not None
        except re.error:
            raise _Ps1InterpreterError

    @staticmethod
    def _truthy(value: _Value) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, float):
            return value != 0.0
        if isinstance(value, str):
            return len(value) > 0
        if isinstance(value, list):
            if len(value) != 1:
                return len(value) > 0
            element = value[0]
            if isinstance(element, list):
                return len(element) > 0
            return _Ps1Interpreter._truthy(element)
        return True

    def _to_str(self, value: _Value) -> str:
        if isinstance(value, str):
            return value
        if value is None:
            return ''
        if isinstance(value, bool):
            return 'True' if value else 'False'
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            # A `Double`'s text is the current culture's to write everywhere `_to_str` is reached —
            # string interpolation, a `.ToString()` call, the `$OFS` separator a collection is
            # joined with — so it is refused rather than written as a value 5.1's session may not
            # share. A string *operator* coerces it culture-invariantly instead; that is `_coerce_str`.
            raise _Ps1InterpreterError
        if isinstance(value, list):
            return self._separator().join(self._to_str(item) for item in value)
        raise _Ps1InterpreterError

    def _coerce_str(self, value: _Value) -> str:
        """
        The text a value contributes where a string *operator* coerces it — the `[string]` cast,
        `+`, `-join`, `-split` and `-replace`. That coercion is culture-invariant, so it is a text
        this unit can write for every value, including the one whose Python `str` disagrees with
        5.1's: a `Double`, written here by the value domain's measured `[string]` text. Every other
        value carries no culture in its text and is deferred to `_to_str` unchanged.
        """
        if isinstance(value, float):
            text = coerced_text(fact_of(value))
            if text is None:
                raise _Ps1InterpreterError
            return text
        return self._to_str(value)

    def _separator(self) -> str:
        """
        What a collection coerced to a String is written with between its elements: `$OFS`, read
        out of the scope chain the way the engine reads it at the point the coercion happens.

        **A name the emulated code has not itself written is refused, not defaulted.** An
        interpreter is entered at a call site whose caller scope it does not hold — the outermost
        `_parent_env` is `None`, which is *unknown beyond here* and not *empty* — and the caller is
        entitled to have written `$OFS`. Writing the fallback space there would be a value 5.1 does
        not produce, and an explicit refusal is what this unit owes a wrong answer.
        `refinery.lib.scripts.ps1.analysis.separator` asks the same question statically, at a point
        where the enclosing scope is in view, and it is what folds the collections this declines.

        A write of `$null` is the fallback and a write of `''` is not — see that module for the
        measurement. A `Double` separator is refused because its text is the one thing here the
        host's culture writes, and a collection separator because reading it asks this again.
        """
        if not self._written(OFS_NAME):
            raise _Ps1InterpreterError
        written = self._lookup(OFS_NAME)
        if written is None:
            return OFS_FALLBACK
        if isinstance(written, (str, bool, int)):
            return self._to_str(written)
        raise _Ps1InterpreterError

    @staticmethod
    def _to_int(value: _Value) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return round(value)
        if isinstance(value, _Char):
            return ord(value)
        if isinstance(value, str):
            return _Ps1Interpreter._string_to_int(value)
        if value is None:
            return 0
        raise _Ps1InterpreterError

    @staticmethod
    def _string_to_int(text: str) -> int:
        """
        Read a String as Int32 the way 5.1's converter does, which is its own numeral grammar and
        not Python's. A `0x` prefix names hexadecimal, a leading zero is just a decimal digit, and
        neither a `0b`/`0o` prefix nor a `_` separator names anything, so `'0b10'`, `'0o10'` and
        `'1_0'` throw where Python's own `int` would read them as two, eight and ten.
        """
        body = text.strip()
        sign = -1 if body[:1] == '-' else 1
        if body[:1] in ('+', '-'):
            body = body[1:]
        if not body or '_' in body:
            raise _Ps1InterpreterError
        try:
            if body[:2].lower() == '0x':
                return sign * int(body[2:], 16)
            return sign * int(body, 10)
        except ValueError:
            raise _Ps1InterpreterError

    def _to_index(self, value: _Value) -> int:
        """
        A subscript is converted to Int32 the way any value is, except that `$null` is no index:
        5.1 raises NullArrayIndex where a plain Int32 conversion of `$null` would answer zero.
        """
        if value is None:
            raise _Ps1InterpreterError
        return self._to_int(value)

    def _to_float(self, value: _Value) -> float:
        if isinstance(value, _Char):
            return float(ord(value))
        if isinstance(value, (int, float)):
            return float(value)
        return float(self._to_str(value))


class Ps1FunctionEvaluator(Transformer):
    """
    Evaluate calls to user-defined functions when all arguments are constants.
    Replaces the call expression with the computed string or integer literal.
    Removes function definitions once all their calls have been resolved.
    """

    def __init__(
        self,
        max_iterations: int = _MAX_INTERPRETER_ITERATIONS,
        max_string_len: int = _MAX_INTERPRETER_STRING_LEN,
    ):
        super().__init__()
        self.max_iterations = max_iterations
        self.max_string_len = max_string_len
        self._functions: dict[str, Ps1FunctionDefinition] = {}
        self._call_counts: dict[str, int] = {}
        self._replaced_counts: dict[str, int] = {}
        self._failed_counts: dict[str, int] = {}
        self._callers: dict[str, set[str]] = {}
        self._ambiguous: set[str] = set()
        self._unreached: frozenset[str] = frozenset()
        self._commands: Ps1CommandModel | None = None
        self._caller_scope_names: frozenset[str] = frozenset()
        self._strict_v2 = True
        self._strict = False
        self._entry = False

    def visit(self, node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._functions.clear()
            self._call_counts.clear()
            self._replaced_counts.clear()
            self._failed_counts.clear()
            self._callers.clear()
            self._ambiguous.clear()
            self._collect_functions(node)
            if not self._functions:
                return None
            # Read before the fold rather than after it: folding a call into its value can neither
            # create nor destroy an `Export-ModuleMember` invocation, and asking afterwards drops
            # the whole shared model on the mutation counter to rebuild it for one boolean.
            cache = model_cache(self, node)
            exports = cache.call_graph.exports_a_name
            self._commands = cache.commands
            self._caller_scope_names = cache.model.script_scope_write_names()
            self._strict_v2, self._strict = _strict_mode_flags(cache)
            self._unreached = cache.used_before_defined
            super().visit(node)
            # Folding a call into its value preserves meaning whoever else can reach the name, so
            # the substitution above is unconditional. Deleting the *definition* is a name-keyed
            # removal, and an exported name has a caller this walk never read: the definition is a
            # reachable entry point and folding its one internal call proves nothing about it.
            #
            # `exports_a_name` and not `is_readable`, deliberately: the other four unknowns
            # `is_readable` carries are risks this pass accepts to resolve the `iex` trampolines
            # obfuscators are built out of, but an export is a reachable call site this walk never
            # scans and is worth nothing to accept.
            if not exports:
                self._remove_resolved_definitions(node)
            return None
        finally:
            self._entry = False

    def _collect_functions(self, root):
        for node in root.walk():
            if isinstance(node, Ps1FunctionDefinition):
                if node.is_filter:
                    continue
                if not node.name:
                    continue
                if node.body is None:
                    continue
                key = normalize_command_name(node.name)
                # A name with more than one definition is not foldable: which body a call reaches
                # depends on the order and scope in which the definitions run, which this pass does
                # not model.
                if key in self._functions:
                    self._ambiguous.add(key)
                self._functions[key] = node
        func_names = set(self._functions)
        for caller_key, funcdef in self._functions.items():
            for node in funcdef.walk():
                if isinstance(node, Ps1CommandInvocation):
                    name = get_command_name(node)
                    if name is not None:
                        callee = normalize_command_name(name)
                        if callee in func_names and callee != caller_key:
                            self._callers.setdefault(callee, set()).add(caller_key)

    def visit_Ps1FunctionDefinition(self, node: Ps1FunctionDefinition):
        return None

    def visit_Ps1ClassDefinition(self, node: Ps1ClassDefinition):
        return None

    def visit_Ps1EnumDefinition(self, node: Ps1EnumDefinition):
        return None

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        if stands_where_only_a_command_may(node):
            return None
        name_str = get_command_name(node)
        if name_str is None:
            return None
        key = normalize_command_name(name_str)
        funcdef = self._functions.get(key)
        if funcdef is None or key in self._ambiguous or key in self._unreached:
            return None
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        if carried_redirections(node):
            # Counted first and refused after. What this pass installs is an expression and an
            # expression carries no redirections, so the answer is the same for every call and every
            # spelling — but a call the counter never heard of is one `_remove_resolved_definitions`
            # reads as absent, and it then deletes the definition this call still names.
            return None
        if self._commands is not None and (
            self._commands.denotation(node).kind is not CommandKind.FUNCTION
        ):
            # Folding a call into its function body is a claim that the name denotes that function.
            # An alias of the same name beats it, so `Set-Alias echo X; function echo { }; echo`
            # runs the alias, not the body — folding it would substitute a value 5.1 never produces.
            # Counted before the refusal for the reason the redirection guard states.
            return None
        args = self._extract_constant_args(node)
        if args is None:
            return None
        bindings = self._bind_parameters(funcdef, args)
        if bindings is None:
            return None
        interpreter = _Ps1Interpreter(
            max_iterations=self.max_iterations,
            max_string_len=self.max_string_len,
            functions=self._functions,
            caller_scope_names=self._caller_scope_names,
            strict_v2_may_be_in_force=self._strict_v2,
            strict_may_be_in_force=self._strict,
        )
        if funcdef.body is None:
            return None
        try:
            result = interpreter.execute(funcdef.body, bindings)
        except InvokeExpression as iex:
            replacement = self._make_iex_node(iex.code)
            if replacement is None:
                self._failed_counts[key] = self._failed_counts.get(key, 0) + 1
                return None
            self._replaced_counts[key] = self._replaced_counts.get(key, 0) + 1
            return replacement
        except _Ps1InterpreterError:
            return None
        replacement = self._value_to_node(result)
        if replacement is None:
            return None
        self._replaced_counts[key] = self._replaced_counts.get(key, 0) + 1
        return replacement

    @staticmethod
    def _extract_constant_value(val: Expression | None) -> tuple[bool, _Value]:
        """
        The value an argument expression pins, as the interpreter's own currency, or `(False, None)`
        where it pins none this can hold.

        The value comes through `read`, not from an integer literal's derived `value`: `0xFFFFFFFF`
        binds to a parameter as -1, where its derived value is four billion. `_value_of` then
        refuses the values this interpreter cannot carry.
        """
        return _value_of(read(val))

    @staticmethod
    def _extract_constant_args(
        node: Ps1CommandInvocation,
    ) -> list[_Value] | dict[str, _Value] | None:
        arguments = node.arguments
        has_switch = any(
            isinstance(a, Ps1CommandArgument)
            and a.kind == Ps1CommandArgumentKind.SWITCH
            for a in arguments
        )
        if has_switch:
            named: dict[str, _Value] = {}
            i = 0
            while i < len(arguments):
                arg = arguments[i]
                if isinstance(arg, Ps1CommandArgument):
                    if arg.kind == Ps1CommandArgumentKind.SWITCH:
                        param_name = arg.name.lstrip('-').lower()
                        i += 1
                        if i >= len(arguments):
                            return None
                        val_arg = arguments[i]
                        if isinstance(val_arg, Ps1CommandArgument):
                            if val_arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                                return None
                            val_expr = val_arg.value
                        elif isinstance(val_arg, Expression):
                            val_expr = val_arg
                        else:
                            return None
                        ok, val = Ps1FunctionEvaluator._extract_constant_value(val_expr)
                        if not ok:
                            return None
                        named[param_name] = val
                        i += 1
                        continue
                    if arg.kind == Ps1CommandArgumentKind.NAMED:
                        ok, val = Ps1FunctionEvaluator._extract_constant_value(arg.value)
                        if not ok:
                            return None
                        named[arg.name.lstrip('-').lower()] = val
                        i += 1
                        continue
                    return None
                else:
                    return None
            return named
        args: list[_Value] = []
        for arg in arguments:
            if isinstance(arg, Ps1CommandArgument):
                if arg.kind == Ps1CommandArgumentKind.NAMED:
                    ok, val = Ps1FunctionEvaluator._extract_constant_value(arg.value)
                    if not ok:
                        return None
                    args.append(val)
                    continue
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    return None
                val_expr = arg.value
            elif isinstance(arg, Expression):
                val_expr = arg
            else:
                return None
            ok, extracted = Ps1FunctionEvaluator._extract_constant_value(val_expr)
            if not ok:
                return None
            args.append(extracted)
        return args

    @staticmethod
    def _bind_parameters(
        funcdef: Ps1FunctionDefinition,
        args: list[_Value] | dict[str, _Value],
    ) -> dict[str, _Value] | None:
        body = funcdef.body
        if body is None:
            return None
        param_block = body.param_block

        def _default(param: Ps1ParameterDeclaration) -> tuple[bool, _Value]:
            if param.default_value is not None:
                return Ps1FunctionEvaluator._extract_constant_value(param.default_value)
            return True, None

        if isinstance(args, dict):
            if param_block is None:
                return {} if not args else None
            bindings: dict[str, _Value] = {}
            for param in param_block.parameters:
                if not isinstance(param.variable, Ps1Variable):
                    return None
                key = param.variable.name.lower()
                if key in args:
                    bindings[key] = args[key]
                else:
                    ok, val = _default(param)
                    if not ok:
                        return None
                    bindings[key] = val
            return bindings

        if param_block is None:
            if args:
                return {'args': args}
            return {}
        params = param_block.parameters
        bindings = {}
        for i, param in enumerate(params):
            if not isinstance(param.variable, Ps1Variable):
                return None
            key = param.variable.name.lower()
            if i < len(args):
                bindings[key] = args[i]
            else:
                ok, val = _default(param)
                if not ok:
                    return None
                bindings[key] = val
        return bindings

    @staticmethod
    def _value_to_node(value: _Value) -> Expression | None:
        """
        The expression that spells a computed value, or `None` where nothing does.

        Both halves are the domain's: `_fact_of_value` says which PowerShell value a Python object
        denotes, keeping the kinds the interpreter's currency carries, and `render` says how that
        value is written — with the round trip `_rendered_value` enforces between them.

        **Producing nothing is not producing `$null`**, and that is why `None` is refused here
        although `render` spells it. A variable bound to either reads the same, which is what makes
        the two look interchangeable, but the stream does not: measured, `@(g).Count` is 0 for a
        body that emits nothing and 1 for `@($null)`, and `g | %{ }` runs the block no times where
        `$null | %{ }` runs it once. An emission that did not happen has no expression to stand in
        its place.
        """
        return _rendered_value(value)

    @staticmethod
    def _make_iex_node(code: str) -> Ps1CommandInvocation | None:
        """
        Build an `Invoke-Expression 'code'` command node so that the existing IEX-inlining pass
        can pick it up in a later round. Returns `None` when the code string is empty or does not
        parse into a valid PowerShell AST (i.e. contains error nodes).
        """
        if not code or not code.strip():
            return None
        from refinery.lib.scripts.ps1.parser import Ps1Parser
        try:
            parsed = Ps1Parser(code).parse()
        except Exception:
            return None
        for node in parsed.walk():
            if isinstance(node, Ps1ErrorNode):
                return None
        return Ps1CommandInvocation(
            name=Ps1StringLiteral(value='Invoke-Expression', raw='Invoke-Expression'),
            arguments=[Ps1CommandArgument(
                kind=Ps1CommandArgumentKind.POSITIONAL,
                name='',
                value=make_string_literal(code),
            )],
        )

    def _remove_resolved_definitions(self, root):
        # Read once for the whole sweep and not per definition. Each removal that lands advances the
        # tree version, so a per-definition read rebuilds every control-flow graph in the script
        # once per function deleted — measured at 2.9x on two hundred of them, which is the shape an
        # obfuscator that emits one function per operation produces. Reusing it is sound because
        # what it is asked is where an error raised *inside the next definition* would go, and
        # deleting a definition changes no routing but its own: a body's graph is built from that
        # body alone. Where the deleted definition held the only acting handler the reused model
        # keeps refusing, which is the conservative direction.
        cache = model_cache(self, root)
        faults = cache.faults
        error_state = cache.error_state
        removed: set[str] = set()
        dead_functions: set[str] = set()
        for key, funcdef in self._functions.items():
            call_count = self._call_counts.get(key, 0)
            if call_count == 0:
                continue
            replaced = self._replaced_counts.get(key, 0)
            failed = self._failed_counts.get(key, 0)
            if (replaced + failed) < call_count:
                continue
            if self._remove_funcdef(funcdef, faults, error_state):
                removed.add(key)
            if failed > 0:
                dead_functions.add(key)
        for key, funcdef in self._functions.items():
            if key in removed:
                continue
            callers = self._callers.get(key)
            if callers is None or not callers:
                continue
            if not callers.issubset(removed):
                continue
            # A removal can be declined — a definition holding a payload is kept whatever the call
            # graph says — and recording it as removed anyway would let the closure delete what it
            # still calls, manufacturing a call to a function that is no longer defined.
            if self._remove_funcdef(funcdef, faults, error_state):
                removed.add(key)
        if dead_functions:
            self._remove_dead_calls(root, dead_functions, faults, error_state)

    def _remove_funcdef(
        self,
        funcdef: Ps1FunctionDefinition,
        faults: Ps1FaultReach,
        error_state: Ps1ErrorStateReach,
    ) -> bool:
        parent = funcdef.parent
        if not isinstance(parent, (Ps1Script, Block)):
            return False
        plan = Ps1RemovalPlan(parent, faults=faults, error_state=error_state)
        plan.propose(funcdef)
        if not plan.commit():
            return False
        self.mark_changed()
        return True

    def _remove_dead_calls(
        self,
        root,
        dead_functions: set[str],
        faults: Ps1FaultReach,
        error_state: Ps1ErrorStateReach,
    ):
        """
        Delete the calls to functions this pass has just deleted, from `root`'s own body.

        Which statement a call *is* comes from
        `refinery.lib.scripts.ps1.ast.standalone_command_statement`, shared so this pass and the
        alias-definition remover recognize a standalone command the same way.

        The redirection refusal is a backstop and is measured to be one: a redirecting call is
        already refused at the visit, which leaves the definition's replaced and failed counts short
        of its call count, so the function is never proved inert and its name never reaches here.
        It is kept because what makes it unreachable is an invariant of a different method, and what
        it prevents if that invariant ever moves is a file: PowerShell opens the redirection target
        as it sets the redirection up, so `deadfunc > C:\\log` creates the file although the body
        writes nothing.
        """
        if not isinstance(root, (Ps1Script, Block)):
            return
        held = {id(statement) for statement in root.body}
        plan = Ps1RemovalPlan(root, faults=faults, error_state=error_state)
        for cmd in root.walk():
            if not isinstance(cmd, Ps1CommandInvocation):
                continue
            name = get_command_name(cmd)
            if name is None or name.lower() not in dead_functions:
                continue
            statement = standalone_command_statement(cmd)
            if statement is None or id(statement) not in held:
                continue
            if carried_redirections(statement):
                continue
            plan.propose(statement)
        if plan.commit():
            self.mark_changed()


class Ps1SubExpressionEvaluator(Transformer):
    """
    Evaluate a `$(...)` whose body the interpreter can run, replacing the body with one statement
    that spells the value it produced.

    The value domain folds only the bodies it can pin as literal structure; every other body — a
    statement, an operator, an unbound name — is `UNKNOWN` to it and is exactly what this pass may
    fold instead. No fold the domain performs is revisited: a body it pinned reads as a fact and
    this pass declines it.

    A sub-expression runs in the scope it is written in, so a fold is a claim about everything
    around it, and each part of that claim is a refusal here rather than a guess: the names the body
    reads were written nowhere it can see, and its state does not carry between evaluations of the
    one site. The names it writes are the one claim answered differently — a name a reader could
    observe is retained, with one store per name holding the final value the emulator computed,
    hoisted before the statement the sub-expression is written in. The value is the stream the body
    emits, collapsed the way a function result collapses.
    """

    def __init__(
        self,
        max_iterations: int = _MAX_INTERPRETER_ITERATIONS,
        max_string_len: int = _MAX_INTERPRETER_STRING_LEN,
    ):
        super().__init__()
        self.max_iterations = max_iterations
        self.max_string_len = max_string_len
        self._entry = False
        self._model: Ps1SemanticModel | None = None
        self._write_sites: dict[str, list[Node]] = {}
        self._doubts_names = False
        self._runs_data_code = False
        self._strict_v2 = True
        self._strict = False

    def visit(self, node: Node):
        if self._entry or not isinstance(node, Ps1Script):
            return super().visit(node)
        self._entry = True
        try:
            cache = model_cache(self, node)
            self._model = cache.model
            self._write_sites = cache.model.write_sites()
            self._doubts_names = cache.model.writes_unreadable_names
            self._runs_data_code = runs_code_supplied_as_data(cache.world_measurement)
            self._strict_v2, self._strict = _strict_mode_flags(cache)
            return super().visit(node)
        finally:
            self._entry = False
            self._model = None
            self._write_sites = {}
            self._doubts_names = False
            self._runs_data_code = False
            self._strict_v2 = True
            self._strict = False

    def visit_Ps1SubExpression(self, node: Ps1SubExpression):
        self.generic_visit(node)
        model = self._model
        if model is None or read(node) is not UNKNOWN:
            return None
        reads, written = self._body_names(node)
        if not self._may_evaluate(node, reads, written):
            return None
        retained = self._names_a_reader_may_observe(node, written)
        if retained is None:
            return None
        hoist = None
        if retained:
            hoist = self._hoist_position(node)
            if hoist is None:
                return None
        result = self._evaluate(node, reads)
        if result is None:
            return None
        value, env = result
        literal = Ps1FunctionEvaluator._value_to_node(value)
        if literal is None:
            return None
        stores = self._retained_stores(retained, env)
        if stores is None:
            return None
        if stores:
            if hoist is None:
                return None
            container, statement = hoist
            if not substitute_statement(container, statement, [*stores, statement]):
                return None
        if not substitute_list(node, 'body', [Ps1ExpressionStatement(expression=literal)]):
            return None
        self.mark_changed()
        return None

    def _body_names(self, node: Ps1SubExpression) -> tuple[set[str], set[str]]:
        """
        The names the body reads and the names it writes. A read is every occurrence that observes
        a value — a plain read as much as the target of a `+=`, the operand of a `++` or the
        container a store reaches through — and a write is every occurrence that changes what a
        read observes, `matches` included whenever the body holds a `-match` operator that refills
        it. A name a `foreach` header binds is a write and not a read: the header supplies it
        before the body runs.
        """
        reads: set[str] = set()
        written: set[str] = set()
        for descendant in node.walk():
            if isinstance(descendant, Ps1Variable):
                if descendant.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
                    continue
                role = occurrence_role(descendant)
                name = descendant.name.lower()
                if name == 'psitem':
                    name = '_'
                if role.observes:
                    reads.add(name)
                if role.stores:
                    written.add(name)
            elif (
                isinstance(descendant, Ps1BinaryExpression)
                and descendant.operator.lower() in MATCH_OPERATORS
            ):
                written.add(_MATCHES_NAME)
        return reads, written

    def _may_evaluate(self, node: Ps1SubExpression, reads: set[str], written: set[str]) -> bool:
        for descendant in node.walk():
            if isinstance(
                descendant,
                (Ps1ReturnStatement, Ps1BreakStatement, Ps1ContinueStatement),
            ):
                # These act on the scope the sub-expression is written in — a `return` exits the
                # enclosing function, a `break` the enclosing loop — so the value this would
                # install is not the value the script produces.
                return False
            if getattr(descendant, 'redirections', None):
                # 5.1 keeps what a redirected stage writes out of the stream this folds, and the
                # interpreter refuses the spelling already; this is the one scan that keeps the
                # driver sound should a parser change ever open a path the interpreter does not.
                return False
        if not self._reads_follow_certain_writes(node, written):
            return False
        if self._doubts_names or self._runs_data_code:
            if reads - written - self._write_sites.keys() - PS1_AUTOMATIC_VARIABLES:
                # A name no write anywhere in the script claims reads as `$null` only where
                # nothing outside the syntax can have written it: a write aimed at a name nobody
                # can read, or code a site runs out of data this tree does not contain.
                return False
        return True

    def _reads_follow_certain_writes(
        self, node: Ps1SubExpression, written: set[str],
    ) -> bool:
        """
        Whether every read of a name the body writes follows a write of it that certainly ran.
        A read that can execute with the name unset answers `$null` on a fresh evaluation and the
        value the previous evaluation left on the host, and a sub-expression inside a loop is
        evaluated more than once. Textual order alone does not certify: a write nested in a branch
        that does not run leaves the read seeing the store the last evaluation made.
        """
        certain: set[str] = set()
        for statement in node.body:
            store = _plain_statement_store_target(statement)
            if store is not None:
                name, value = store
                if not self._reads_certified(value, written, certain):
                    return False
                certain.add(name)
                continue
            if isinstance(statement, Ps1ForLoop):
                if not self._for_reads_follow(statement, written, certain):
                    return False
                continue
            if not self._reads_certified(statement, written, certain):
                return False
        return True

    def _for_reads_follow(
        self, loop: Ps1ForLoop, written: set[str], certain: set[str],
    ) -> bool:
        """
        A top-level `for` initializer runs exactly once, before the condition, the iterator and the
        body, so a plain store it carries certifies every read after it — its own right side
        excepted, which a store does not reach across: `for($c = $c + 'x'; …)` reads the value the
        previous evaluation left.
        """
        parts: list[Node] = []
        initializer = loop.initializer
        if initializer is not None:
            store = _plain_store_target(initializer)
            if store is not None:
                name, value = store
                if not self._reads_certified(value, written, certain):
                    return False
                certain.add(name)
            else:
                parts.append(initializer)
        parts.extend(
            part for part in (loop.condition, loop.iterator, loop.body) if part is not None
        )
        return all(self._reads_certified(part, written, certain) for part in parts)

    def _reads_certified(self, root: Node | None, written: set[str], certain: set[str]) -> bool:
        """
        Whether every observing read under *root* of a name written somewhere in the body is
        covered by *certain* — the names a store that certainly ran has bound — or by the
        header of a `foreach` the read sits inside, a body running only after its binding.
        """
        if root is None:
            return True
        for descendant in root.walk():
            if not isinstance(descendant, Ps1Variable):
                continue
            if descendant.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
                continue
            if not occurrence_role(descendant).observes:
                continue
            name = descendant.name.lower()
            if name == 'psitem':
                name = '_'
            if name not in written or name in certain:
                continue
            if self._bound_by_a_foreach_body(descendant, name):
                continue
            return False
        return True

    def _bound_by_a_foreach_body(self, var: Ps1Variable, name: str) -> bool:
        """
        Whether *var* sits inside the body of a `foreach` whose header binds *name*.
        """
        cursor: Node = var
        inside_a_body = False
        while (parent := cursor.parent) is not None:
            if isinstance(parent, Ps1ForEachLoop):
                if inside_a_body:
                    bound = parent.variable
                    if isinstance(bound, Ps1Variable) and bound.name.lower() == name:
                        return True
                inside_a_body = False
            elif (
                isinstance(parent, Block)
                and isinstance(parent.parent, Ps1ForEachLoop)
                and parent.parent.body is parent
            ):
                inside_a_body = True
            cursor = parent
        return False

    def _names_a_reader_may_observe(self, node: Ps1SubExpression, written: set[str]) -> set[str] | None:
        """
        The body-written names a reader could observe, or `None` where the fold must refuse
        outright.

        An engine variable is the outright refusal, because the engine reads it between statements —
        `$OFS` at the next collection coercion, `$ErrorActionPreference` at the next failing cmdlet —
        so a reader of one observes the body's write wherever this pass could put a store. Every
        other written name is one a reader could observe for either of two reasons, and either one
        is answered by retention rather than refusal: the script spells a reader outside the body,
        which `_occurs_outside` answers through the semantic model — in both models, since a spelled
        reader is not what the trusting model's contract excuses — or the run takes code from data,
        which reads the scope with no occurrence in the tree at all. A name with neither reader is
        one no fold needs to answer for and is dropped, as before.
        """
        if not written:
            return set()
        if written & PS1_ENGINE_VARIABLES:
            return None
        if self._runs_data_code:
            return set(written)
        return {name for name in written if self._occurs_outside(node, name)}

    def _occurs_outside(self, node: Ps1SubExpression, name: str) -> bool:
        """
        Whether *name* is referenced anywhere outside *node*'s subtree. The name is asked through the
        semantic model: a same-named local of another scope is not a reader of this write, while a
        reader inside a nested function or a captured scriptblock is, and a binding a qualifier or a
        dynamic reach can arrive at counts.

        Every name this is asked reaches it with a binding, because the caller filters out the engine
        variables first and `_body_names` writes only two kinds of name — a variable-spelled store,
        which the model binds, and `matches`, which is an engine variable — so the only binding-less
        write never arrives here. A name with no binding is nonetheless treated as read outside, the
        direction that refuses a fold rather than dropping a store some reader observes.
        """
        model = self._model
        if model is None:
            return True
        bindings = set()
        for descendant in node.walk():
            if (
                isinstance(descendant, Ps1Variable)
                and descendant.name.lower() == name
                and (binding := model.binding_of(descendant)) is not None
            ):
                bindings.add(binding)
        if not bindings:
            return True
        for binding in bindings:
            if binding.dynamic_or_qualified:
                return True
            for occurrence in (*binding.reads, *binding.writes):
                if not self._inside(occurrence.node, node):
                    return True
        return False

    @staticmethod
    def _inside(inner: Node, outer: Node) -> bool:
        cursor: Node | None = inner
        while cursor is not None:
            if cursor is outer:
                return True
            cursor = cursor.parent
        return False

    def _hoist_position(self, node: Ps1SubExpression) -> tuple[Node, Statement] | None:
        """
        The statement the retained stores go before and the body that holds it, or `None` for a
        position whose window is not empty.

        A retained store runs earlier than the body's own store did — before the statement the
        sub-expression is written in rather than inside it — so the statement between the two must
        read nothing the store writes before it reaches the sub-expression. That holds exactly where
        the sub-expression is the first thing its statement evaluates: the entire right-hand side
        of a plain `$name = ...` assignment, or a bare expression statement. A compound assignment
        reads its target first and an index assignment its container, so both keep the refusal; so
        does every position deeper inside a statement, which reads what stands before the
        sub-expression to build the expression around it.
        """
        parent = node.parent
        if isinstance(parent, Ps1ExpressionStatement) and parent.expression is node:
            statement = parent
        else:
            if not (
                isinstance(parent, Ps1AssignmentExpression)
                and parent.value is node
                and parent.operator == '='
                and isinstance(parent.target, Ps1Variable)
                and parent.target.scope in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL)
                and isinstance(parent.parent, Ps1ExpressionStatement)
                and parent.parent.expression is parent
            ):
                return None
            statement = parent.parent
        container = statement.parent
        if container is None:
            return None
        body = get_body(container)
        if body is None or not any(one is statement for one in body):
            return None
        return container, statement

    def _retained_stores(
        self, retained: set[str], env: Mapping[str, _Value],
    ) -> list[Ps1ExpressionStatement] | None:
        """
        One store per retained name the body wrote on the taken path, holding the final value the
        emulator computed, or `None` where a value has no spelling.

        Single-threaded execution means nothing observes the body's intermediate stores, so the
        value each written name holds after the body is the interpreter's final one; a store that
        rewrites it where the fold can spell it is exact. The names are visited in their own order,
        so the fold is deterministic over a set. A name the body wrote `$null` is stored as `$Null` —
        it was set on 5.1, and `Set-StrictMode` tells a set-to-`$null` name from an unset one —
        where `render`'s refusal of `None` is about the stream, in which an emitted `$null` and an
        emission that did not happen differ. A name the body never wrote on the taken path is not
        stored at all: it is unset on both sides of the fold.
        """
        stores: list[Ps1ExpressionStatement] = []
        for name in sorted(retained):
            if name not in env:
                continue
            value = env[name]
            spelled = null_expression() if value is None else _rendered_value(value)
            if spelled is None:
                return None
            stores.append(Ps1ExpressionStatement(
                expression=Ps1AssignmentExpression(
                    target=Ps1Variable(name=name),
                    operator='=',
                    value=spelled,
                ),
            ))
        return stores

    def _evaluate(
        self, node: Ps1SubExpression, reads: set[str],
    ) -> tuple[_Value, Mapping[str, _Value]] | None:
        """
        The value the body's success stream collapses to and the environment the body left, or
        `None` where this will not answer. The interpreter is refused every name an enclosing scope
        may hold and given no functions: a user-function call inside a `$(...)` declines, because
        the call-site bookkeeping that licenses folding a call is the function evaluator's and does
        not transfer to a value position. An `Invoke-Expression` the body raises refuses the fold
        rather than installing the command the function evaluator substitutes, which would drop the
        rest of the stream.
        """
        interpreter = _Ps1Interpreter(
            max_iterations=self.max_iterations,
            max_string_len=self.max_string_len,
            caller_scope_names=frozenset(
                name for name in reads if self._written_outside(node, name)
            ),
            strict_v2_may_be_in_force=self._strict_v2,
            strict_may_be_in_force=self._strict,
        )
        try:
            value = interpreter._exec_statements(node.body)
        except (InvokeExpression, _Ps1InterpreterError):
            return None
        if interpreter._dropped_null:
            # 5.1 keeps a `$null` a statement hands the stream while the interpreter drops it, so
            # a fold would install a shorter stream than the one the host assembles.
            return None
        return value, interpreter._env

    def _written_outside(self, node: Ps1SubExpression, name: str) -> bool:
        return any(
            not self._inside(site, node) for site in self._write_sites.get(name, ())
        )


def _plain_store_target(expression: Node | None) -> tuple[str, Node | None] | None:
    """
    The name a plain `=` onto an unqualified variable stores and the value it stores, or `None` for
    any other expression shape. The value is handed back rather than re-read off the expression so a
    caller certifies the store without reaching through a node the type checker only knows as a
    `Statement`.
    """
    if not isinstance(expression, Ps1AssignmentExpression) or expression.operator != '=':
        return None
    target = expression.target
    if not isinstance(target, Ps1Variable):
        return None
    if target.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
        return None
    return target.name.lower(), expression.value


def _plain_statement_store_target(statement: Node) -> tuple[str, Node | None] | None:
    """
    The name and value a top-level statement of a statement list stores with a plain `=` onto an
    unqualified variable. Such a statement runs exactly once per evaluation of the list, before every
    later statement, which is what makes it the one certain write.
    """
    if not isinstance(statement, Ps1ExpressionStatement):
        return None
    return _plain_store_target(statement.expression)


class Ps1ForEachPipeline(Transformer):
    """
    Evaluate pipelines of the form `<array> | %{ <scriptblock> }` by executing the scriptblock
    for each element and replacing the pipeline with the computed result.
    """

    _BUILTIN_VARS = frozenset({'_', 'psitem', 'true', 'false', 'null'})

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        if len(node.elements) != 2:
            return None
        src_elem = node.elements[0]
        cmd_elem = node.elements[1]
        if not isinstance(src_elem, Ps1PipelineElement):
            return None
        if not isinstance(cmd_elem, Ps1PipelineElement):
            return None
        items = self._get_constant_array(src_elem.expression)
        if items is None:
            return None
        if cmd_elem.expression is None:
            return None
        shadowed = model_cache(self, node).closed_world.shadowed_names
        script_block = extract_foreach_scriptblock(cmd_elem.expression, shadowed)
        if script_block is None:
            return None
        if self._has_free_variables(script_block):
            return None
        results: list[_Value] = []
        interpreter = _Ps1Interpreter()
        for item in items:
            try:
                results.extend(interpreter.emit(script_block, {'_': item}))
            except (_Ps1InterpreterError, InvokeExpression):
                return None
        return substituted(node, self._results_to_node(results))

    @staticmethod
    def _has_free_variables(script_block: Ps1ScriptBlock) -> bool:
        for node in script_block.walk():
            if isinstance(node, Ps1Variable):
                if node.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
                    return True
                if node.name.lower() not in Ps1ForEachPipeline._BUILTIN_VARS:
                    return True
        return False

    @staticmethod
    def _get_constant_array(expr: Expression | None) -> list[_Value] | None:
        """
        The items a pipeline source hands one at a time, or `None` where this cannot say what they
        are. A scalar source is one item, which is what a pipeline does with one.

        **The element type of an array cast is dropped, and that is the residual this stands on.**
        `[Char[]](72, 73)` is read as the numbers written inside it, so a block reading `$_` is
        emulated over an Int32 where 5.1 hands it a Char. The two agree wherever the block converts
        the item back — `[Char]($_ -bxor $k)`, which is the shape loaders write — and come apart
        wherever it does not. What ends it is not a wider reader here but the interpreter carrying
        a Char at all: until its values have types, an element of a `Char[]` has nowhere to land,
        and refusing the cast outright would drop the folds that shape depends on. A cast to a
        *scalar* is not dropped, because `[string](1, 2)` is one item and not two.

        **What may be dropped is exactly a width over numbers, and nothing else.** The residual is
        that the block sees a number where 5.1 shows it a narrower one; a cast this cannot read
        that way changes what the block is handed, not merely what it is called. `[Char[]]'ab'`
        hands out two Chars where the operand alone is one String, so dropping it changes the
        *count*; `[int[]]('1', '2')` hands out numbers where the elements alone are text, so
        `$_ + 1` becomes concatenation. Both are refused here, and so is `[byte[]](300, 1)`, where
        the cast is not merely narrower than the number but does not hold it: 5.1 throws there and
        the pipeline never runs at all.
        """
        widths: list[str] = []
        while isinstance(expr, Ps1CastExpression):
            target = normalize_dotnet_type_name(expr.type_name)
            if not target.endswith('[]'):
                break
            widths.append(target[:-2])
            expr = expr.operand
        facts = collect_facts(expr)
        if facts is None:
            return None
        if any(not _fills_the_width(fact, width) for width in widths for fact in facts):
            return None
        values: list[_Value] = []
        for fact in facts:
            ok, value = _value_of(fact)
            if not ok:
                return None
            values.append(value)
        return values

    @staticmethod
    def _results_to_node(results: list[_Value]) -> Expression | None:
        """
        Turn the success stream of `<array> | %{ ... }` into a node.

        **A pipeline builds a collection whatever its items are**, so what stands here is the
        stream and nothing narrower — joining a run of one-character strings into one String would
        be wrong: `@('a', 'b') | %{ $_ }` is an `Object[]` of two, so `.Count` is 2, `-join '-'`
        writes the separator, and `foreach` runs twice. Joining is `$OFS`'s job, which
        `refinery.lib.scripts.ps1.analysis.separator` answers: the collection this writes reaches
        the enclosing coercion as a collection, and the fold that follows the emulation is where it
        becomes a String with the separator the script wrote.

        The stream arrives already assembled (see `emit`). Concatenating what a block *returned*
        would flatten a block that hands out one array into the objects inside it: measured,
        `@(1, 2) | %{ $_, $_ }` is four Int32s where `%{ ,($_, $_) }` is two pairs, and a collapsed
        result spells both the same way. A stream
        that ends up empty is refused rather than spelled `$null`, because a pipeline that produced
        no value is not an expression this can put in its place.
        """
        if not results:
            return None
        return Ps1FunctionEvaluator._value_to_node(_Ps1Interpreter._collapse(results))


def evaluate_truthy(
    condition: Expression,
    bindings: Mapping[str, int | float | str | bool | None],
) -> bool | None:
    """
    Evaluate a PS1 condition with the given variable bindings and return its truthiness. Returns
    `None` if the expression cannot be evaluated.
    """
    try:
        interp = _Ps1Interpreter(max_iterations=100)
        interp._env = dict(bindings)
        value = interp._eval(condition)
        return _Ps1Interpreter._truthy(value)
    except (_Ps1InterpreterError, InvokeExpression, _BreakSignal, _ContinueSignal):
        return None
