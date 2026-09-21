"""
Shared utilities for JavaScript deobfuscation transforms, and the runtime value domain they and the
interpreter agree on: what a JavaScript value is (`Value`, `JS_NULL`, `JsBuffer`), the ECMA-262
conversions between values (`to_number`, `to_string`, `to_boolean`, `js_typeof`), the operator tables
over them (`UNARY_OPS`, `BINARY_OPS`), the own-property read on them (`read_data_property`), and the
two bridges to the syntax tree (`extract_literal_value`, `value_to_node`).

That domain lives below the interpreter rather than inside it, because a static fold and an emulated
execution must answer an operator the same way — if `~NaN` were implemented once for each, only one of
the two would be wrong at a time and nothing would say which. The interpreter is a consumer here like
any transform is.
"""
from __future__ import annotations

import math
import operator
import re

from collections import Counter
from enum import Enum, auto
from typing import TYPE_CHECKING, Callable, Collection, Iterator, NamedTuple, Sequence

if TYPE_CHECKING:
    from typing import TypeAlias

    from refinery.lib.scripts.js.analysis.effects import EffectModel
    from refinery.lib.scripts.js.model import JsArrowFunctionExpression as _Arrow
    from refinery.lib.scripts.js.model import JsFunctionDeclaration as _FuncDecl
    from refinery.lib.scripts.js.model import JsFunctionExpression as _FuncExpr

    LiteralValue: TypeAlias = str | int | float | bool | list | dict | None
    Value: TypeAlias = str | float | bool | list | dict | _FuncDecl | _FuncExpr | _Arrow | None

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    Transformer,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
    set_body,
    set_child,
    set_value,
    tree_root,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.effects import side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    SAME_REALM_GLOBAL_OBJECT_ALIASES,
    Binding,
    Role,
    Scope,
    SemanticModel,
    build_semantic_model,
    is_invocation_target,
    is_use_position,
    reference_role,
    tolerates_unresolvable,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsExportSpecifier,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsLogicalExpression,
    JsLabeledStatement,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsThisExpression,
    JsThrowStatement,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
    callee_form_sensitive,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.numbers import (
    canonical_array_index,
    is_negative_zero,
    js_number_to_string,
    js_string_to_number,
    to_js_number,
)
from refinery.lib.scripts.js.options import (
    is_host_entrypoint,
    runs_as_module,
)
from refinery.lib.scripts.js.strict import (
    directive_prologue,
    is_prologue_host,
    keeping_directives,
    statement_list,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS
from refinery.lib.scripts.js.utf16 import SURROGATE_PAIR, code_units, from_code_units

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

VOID_LITERAL_OPERANDS = (JsNumericLiteral, JsStringLiteral, JsBooleanLiteral, JsNullLiteral)

OBJECT_PROTOTYPE_MEMBERS = frozenset({
    '__defineGetter__',
    '__defineSetter__',
    '__lookupGetter__',
    '__lookupSetter__',
    '__proto__',
    'constructor',
    'hasOwnProperty',
    'isPrototypeOf',
    'propertyIsEnumerable',
    'toLocaleString',
    'toString',
    'valueOf',
})
"""
The members every plain object inherits from `Object.prototype`. An access of one of these names on
an object that does not own it resolves through the prototype rather than to `undefined`, so a fold
that treats an absent own-property as `undefined` must leave these intact.
"""

STRING_PROTOTYPE_METHODS = frozenset({
    'anchor', 'at', 'big', 'blink', 'bold', 'charAt', 'charCodeAt', 'codePointAt', 'concat',
    'endsWith', 'fixed', 'fontcolor', 'fontsize', 'includes', 'indexOf', 'isWellFormed', 'italics',
    'lastIndexOf', 'link', 'localeCompare', 'match', 'matchAll', 'normalize', 'padEnd', 'padStart',
    'repeat', 'replace', 'replaceAll', 'search', 'slice', 'small', 'split', 'startsWith', 'strike',
    'sub', 'substr', 'substring', 'sup', 'toLocaleLowerCase', 'toLocaleUpperCase', 'toLowerCase',
    'toString', 'toUpperCase', 'toWellFormed', 'trim', 'trimEnd', 'trimLeft', 'trimRight',
    'trimStart', 'valueOf',
})

ARRAY_PROTOTYPE_METHODS = frozenset({
    'at', 'concat', 'copyWithin', 'entries', 'every', 'fill', 'filter', 'find', 'findIndex',
    'findLast', 'findLastIndex', 'flat', 'flatMap', 'forEach', 'includes', 'indexOf', 'join',
    'keys', 'lastIndexOf', 'map', 'pop', 'push', 'reduce', 'reduceRight', 'reverse', 'shift',
    'slice', 'some', 'sort', 'splice', 'toLocaleString', 'toReversed', 'toSorted', 'toSpliced',
    'toString', 'unshift', 'values', 'with',
})
"""
The callable members of `String.prototype` and `Array.prototype`, enumerated from a real engine
rather than from the subset this package implements. Reading one of these names yields the method
itself, so a reader that answers `undefined` for the ones we cannot evaluate would contradict
`typeof`; membership and evaluability are separate questions.
"""

SEQUENCE_DATA_PROPERTIES = frozenset({'length'})
"""
The non-callable inherited properties of a string or array. `length` is the only one, which is why
it must never be reached through a method registry: `'abc'.length` is the number `3` and
`'abc'.length()` is a `TypeError`, whereas a registry entry would answer `3` to both.
"""

PROTOTYPE_CHAIN_PROPERTIES = frozenset({'__proto__', 'constructor'})
"""
The two properties that expose the prototype chain itself. Both exist on every value, so answering
`undefined` for them is wrong, but modelling them would hand out the `Function` constructor that
`[].constructor.constructor('...')()` reflection depends on. They are therefore left unevaluated.
"""


class _JsNull:
    """
    Singleton sentinel for the JavaScript `null` value. The interpreter uses Python `None` for
    `undefined` (the value of missing/absent things), so a distinct object is required to keep `null`
    and `undefined` apart where JavaScript treats them differently: `Number(null)` is `0` but
    `Number(undefined)` is `NaN`, `typeof null` is `'object'`, `null === undefined` is `false`, and
    `String(null)` is `'null'`.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return 'JS_NULL'


JS_NULL = _JsNull()


class _JsHole:
    """
    Singleton sentinel for an array hole: a position an array holds no element at, which is not
    an element holding `undefined`. A program cannot produce one as a value — reading a hole
    yields `undefined` (`read_data_property` answers `ABSENT` for the slot) — so the sentinel
    never reaches a folded result. It exists so that a store growing an array past its end can
    grow the array in place, where a copy could not: `var v = u; u[87] = 5` leaves `v.length`
    at 88, so the positions the store skipped over have to live in the one array both names
    hold, as slots no read treats as elements.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return 'JS_HOLE'


JS_HOLE = _JsHole()


def _holes_present(values: list) -> bool:
    """
    Whether *values* holds at least one hole. The arms of the value domain that visit a list's
    elements decide per method whether a hole is skipped (`forEach`, `filter`), read as
    `undefined` (`find`, for-of, `includes`), or preserved in a result (`map`); this is the one
    test they would otherwise each spell out for itself.
    """
    return any(value is JS_HOLE for value in values)


GLOBAL_VALUE_NAMES: dict[str, Value] = {
    'undefined': None,
    'NaN': float('nan'),
    'Infinity': float('inf'),
}
"""
The three global names that carry a value no literal spells, so that an operand written with one of
them holds a value `extract_literal_value` cannot report and a caller that wants it looks here.

What makes reading them safe is *not* the specification. ES5 made them non-writable and
non-configurable, but ES3 did not — its own Annex E lists the change as an intentional
incompatibility — and ES3 is what Windows Script Host runs, which is the dialect of the `.js`, `.wsf`
and `.hta` droppers this tool exists for. Measured under `cscript`, JScript 11.0: `undefined =
'CLOBBERED'` sticks, and `typeof undefined` becomes `'string'` afterwards. Clobbering `undefined` is
a live obfuscation technique precisely because it breaks a naive `=== undefined` check.

What makes reading them safe is the binding analysis. A program that assigns one of these names at
top level creates an `IMPLICIT_GLOBAL` binding the model records, and `denoted_value` — the only
reader that may consult this table — refuses any name the model resolves. All three are also
ordinary identifiers as far as scoping goes: a parameter, a `let` or a `var` of the same name shadows
them, and that is the same refusal. Reading the table without asking the model is a bug.
"""

PROTO_KEY = '__proto__'
"""
The one property key whose plain spelling in an object literal does not denote an own property.
`{__proto__: v}` and `{'__proto__': v}` install `v` as the prototype and leave the object with no own
property at all, whereas `{['__proto__']: v}` — and `JSON.parse` — create an ordinary own property of
that name. A runtime object modelled as a Python dict holds only own data properties, so a
`__proto__` entry in such a dict can only have come from one of the latter two, and may only be
rendered back as the computed form.
"""


class JsBuffer(list):
    """
    Thin wrapper around `list` to distinguish a Node.js Buffer (byte array) from a plain JS Array in
    the interpreter's type-based method dispatch. It lives beside `JS_NULL` because both are members
    of the interpreter's value domain that a plain Python type cannot express, and every consumer of
    that domain — most importantly `value_to_node`, which must not render a Buffer as an array
    literal — has to be able to tell them apart.
    """
    pass


def converts_uninterceptably(value: Value) -> bool:
    """
    Whether converting *value* to a string — or to the key of a property access, which converts it
    the same way — is an internal operation no program can replace. Every primitive is: `String(1)`
    and `o[1]` answer what the specification says whatever the file did to the prototypes. A hole
    is too: it renders as the empty string, and whether an array's chain supplies an element at the
    position the hole stands at is a question about the array, which the caller holding the array
    asks of it. An array and an object are not, because their conversion runs `Array.prototype.join`
    and `Object.prototype.toString`, so a file that replaces either decides what `o[[1]]` reads.
    This is the rule `concat_string` states for the operand of a `+`, asked of a value rather than
    a node, and a fold that converts a value without asking it computes a key the engine never
    would.
    """
    return (
        value is None or value is JS_NULL or value is JS_HOLE
        or isinstance(value, (str, int, float, bool))
    )


_TO_PRIMITIVE_METHODS = frozenset({'valueOf', 'toString', 'Symbol.toPrimitive'})


def coerces_uninterceptably(effects: EffectModel | None, value: Value) -> bool:
    """
    Whether converting *value* to a primitive — the string a `+`, a template hole, a `String()`
    call, or a computed property key needs, or the number an arithmetic operator asks for — is an
    operation no program can replace. This is `converts_uninterceptably` widened by what an
    effect model can vouch for, which is the two halves of an object's conversion: it owns none of
    `valueOf`, `toString` or `Symbol.toPrimitive` — this domain's objects are plain data
    dictionaries, so a program can have written one only as an own property — and the prototype
    chain that would supply them is still the one the language describes, which
    `EffectModel.read_chain_intact` answers. An array converts element-wise, so each element has
    to answer this question too.

    A caller with no effect model gets `False` for every object: the interpreter used on one
    expression in isolation cannot see the file the expression came from, and whether anything
    replaced a conversion is a question about that file.
    """
    if converts_uninterceptably(value):
        return True
    if isinstance(value, dict):
        if any(name in value for name in _TO_PRIMITIVE_METHODS):
            return False
    elif not isinstance(value, (list, JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return False
    if effects is None or not effects.read_chain_intact(type(value)):
        return False
    if isinstance(value, list) and not all(coerces_uninterceptably(effects, item) for item in value):
        return False
    return True


def coerces_uninterceptably_from_written_chain(effects: EffectModel | None, value: Value) -> bool:
    """
    `coerces_uninterceptably` for a caller the tampering oracle has cleared at an anchor: the
    chain is asked `EffectModel.chain_roots_unwritten` — the same half
    `property_absent_from_written_chain` takes — so an anchored execution converts a value where
    the reflection term is what the oracle's clearance replaced. A caller that has not asked the
    oracle takes `coerces_uninterceptably` itself.
    """
    if converts_uninterceptably(value):
        return True
    if isinstance(value, dict):
        if any(name in value for name in _TO_PRIMITIVE_METHODS):
            return False
    elif not isinstance(value, (list, JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return False
    if effects is None or not effects.chain_roots_unwritten(type(value)):
        return False
    if isinstance(value, list) and not all(
        coerces_uninterceptably_from_written_chain(effects, item) for item in value
    ):
        return False
    return True


class MemberRead(Enum):
    """
    What reading a key off a value found. `FOUND` carries the value the read answers with. `ABSENT`
    is an index past the end of a string or array: the value holds no such slot, so the read is
    `undefined` unless the prototype chain supplies one. `NOT_DATA` is every other key, which is a
    name the chain has to be consulted about before anything can be said.

    The two ways of not finding a value are kept apart because the callers part company on them. An
    emulated execution answers `undefined` for an index past the end, having no reason to doubt the
    chain of a value it is holding; a fold has to leave that read standing, because the file it is
    rewriting may install an index on `String.prototype` before it runs. Reporting both as one
    outcome would force the caller that cares to ask `canonical_array_index` a second time, which is
    the duplication this function exists to remove.
    """
    FOUND = auto()
    ABSENT = auto()
    NOT_DATA = auto()


def own_property_keys(obj: dict) -> list[str]:
    """
    The own keys of *obj* in the order JavaScript enumerates them: the array indices first, ascending
    by value, then every remaining key in the order it was created.

    A `dict` already preserves creation order, which is the whole of the second half of the rule and
    the reason enumeration reads as insertion order for as long as no index is present. An index is
    what breaks it, and the break is not a detail of ordering: a lookup table written with numeric
    keys comes back in an order the source does not show, so a program that walks one and a fold that
    walks the same one must agree about which key is first.

    Which keys are indices is the distinction `refinery.lib.scripts.js.numbers.canonical_array_index`
    draws, so a key an array could not have used as an index — `'01'`, `'-1'`, `'4294967295'` — sorts
    with the names and not with the numbers.

    This is the own half of enumeration, like `read_data_property` is the own half of a read: it
    answers about the keys *obj* holds and nothing about the ones a prototype would contribute.
    """
    indices: list[tuple[int, str]] = []
    names: list[str] = []
    for key in obj:
        index = canonical_array_index(key)
        if index is None:
            names.append(key)
        else:
            indices.append((index, key))
    indices.sort()
    return [key for _, key in indices] + names


def read_data_property(obj: Value, key: str) -> tuple[MemberRead, Value]:
    """
    Read *key* off *obj* as far as the value itself decides it: the own data properties of a string,
    an array, and a plain object, which are `length`, a canonical index, and a present key. Every
    other key is `NOT_DATA` — a method name, an inherited name, a missing key of an object, or any
    key at all of a value with no own slots to read, such as a number.

    The read is the *own* half of a property access and answers nothing about the prototype chain,
    which is where the outcome is decided for a `NOT_DATA` key and is why this takes no model. What
    it does answer, it answers alone: `length` and an index within range are own properties of a
    string or array, so no prototype can be consulted for them and none can shadow them.

    A list holds a value at every index it has or a hole there, which is what makes the second of
    those answerable without a model either way: a hole is an index the array's length reaches and
    no element was ever stored at, so the read is `ABSENT` for exactly the reason an index past the
    end is, and the prototype answers for it as it does for that. A literal's elision is the same
    slot spelled by the source, which is why the producer of a literal still refuses to build one
    rather than this reporting on a list only a store grew.

    *obj* must hold a string the way JavaScript does, as UTF-16 code units — the form the lexer gives
    a literal and the builtin registry gives a produced string. A string of code points read here
    counts an astral character once where JavaScript counts it twice, and answers `length` and every
    index after it one too low.
    """
    if isinstance(obj, (str, list)):
        if key in SEQUENCE_DATA_PROPERTIES:
            return MemberRead.FOUND, len(obj)
        index = canonical_array_index(key)
        if index is not None:
            if 0 <= index < len(obj):
                if obj[index] is JS_HOLE:
                    return MemberRead.ABSENT, None
                return MemberRead.FOUND, obj[index]
            return MemberRead.ABSENT, None
    elif isinstance(obj, dict) and key in obj:
        return MemberRead.FOUND, obj[key]
    return MemberRead.NOT_DATA, None


def property_absent_from_written_chain(
    effects: EffectModel | None,
    value_type: type,
    key: str,
) -> bool:
    """
    `property_provably_absent` for a caller whose cost of refusing is a whole pass rather than one
    fold. The chain is asked `EffectModel.chain_roots_unwritten` instead of
    `EffectModel.read_chain_intact`, so a file carrying a reflective surface is not treated as one
    that wrote a prototype. See the note on `chain_roots_unwritten` for what that trade is; the
    short of it is that such a surface is what the real obfuscated files carry, and clearing it is
    what the gated pass would have done.

    It is a separate function rather than a parameter because the choice is the caller's to justify
    and has to be readable where it is made. The callers entitled to it are the two whose refusal
    costs the pipeline a pass rather than an expression — namespace flattening and the dispatcher
    unwrapper — and the interpreter's anchored arm, whose justification is the tampering oracle
    having answered the reflection term at the anchor. Every caller that folds one expression takes
    `property_provably_absent`, which keeps both arms and gains nothing by the weaker question.
    """
    if key in OBJECT_PROTOTYPE_MEMBERS or key in PROTOTYPE_CHAIN_PROPERTIES:
        return False
    if issubclass(value_type, JsBuffer):
        return False
    if effects is not None and not effects.chain_roots_unwritten(value_type):
        return False
    if issubclass(value_type, str):
        return key not in STRING_PROTOTYPE_METHODS and key not in SEQUENCE_DATA_PROPERTIES
    if issubclass(value_type, list):
        return key not in ARRAY_PROTOTYPE_METHODS and key not in SEQUENCE_DATA_PROPERTIES
    return issubclass(value_type, dict)


def property_is_inherited_from_an_intact_chain(
    effects: EffectModel | None,
    value_type: type,
    key: str,
) -> bool:
    """
    Whether *key* names a member the prototype chain of *value_type* supplies **and** that chain is
    still the one the language describes, so a value of that type has the member whether or not it
    owns one.

    This is `property_is_inherited` with the question that one cannot answer added to it. The tables
    say what the language installs; only the model can say whether the file took it away, and
    `delete Object.prototype.toString` removes a name every one of those tables lists. A caller with
    no effect model gets the tables alone and owns that assumption itself.

    It asks `EffectModel.read_chain_intact` and not the write arm, so that it refuses wherever
    `property_provably_absent` refuses. The two are the halves of one read, and a half that answers
    under a reflective surface the other half declines under is a read decided by which half
    happened to be asked: an unresolvable `eval` that deleted `toString` would leave
    `'toString' in o` folding to `true` while `'zz' in o` refused.
    """
    if not property_is_inherited(value_type, key):
        return False
    return effects is None or effects.read_chain_intact(value_type)


def property_is_inherited_from_an_unwritten_chain(
    effects: EffectModel | None,
    value_type: type,
    key: str,
) -> bool:
    """
    `property_is_inherited_from_an_intact_chain` for a caller the tampering oracle has cleared at
    an anchor: the chain is asked `EffectModel.chain_roots_unwritten` — the same half
    `property_absent_from_written_chain` takes — so an anchored execution answers the two halves of
    one read under one chain question. A caller that has not asked the oracle takes the intact-chain
    question, whose reflection term is what the oracle's clearance replaces.
    """
    if not property_is_inherited(value_type, key):
        return False
    return effects is None or effects.chain_roots_unwritten(value_type)


def property_is_inherited(value_type: type, key: str) -> bool:
    """
    Whether *key* names a member the prototype chain of *value_type* supplies, so a value of that
    type has one whether or not it owns one. This is the yes-side of the question
    `property_provably_absent` answers the no-side of, and the two are not each other's negation:
    between them lies every name the tables do not list, which a value has only if the file put it
    there.

    The asymmetry was once the point: writing a prototype adds a name to a chain, so a name the
    language already puts there was taken to be still there afterwards, while a name it does not put
    there is one only the file can account for. That reasoning is true of a write and **false of a
    `delete`** — `delete Object.prototype.toString` removes a name every table here lists — so this
    side needs the model as much as the other one does, and a caller must pair it with
    `EffectModel.read_chain_intact` or `EffectModel.chain_roots_unwritten` exactly as
    `property_provably_absent` does. A caller that does not is answering `true` for a name the
    program removed.
    """
    if key in OBJECT_PROTOTYPE_MEMBERS or key in PROTOTYPE_CHAIN_PROPERTIES:
        return True
    if issubclass(value_type, JsBuffer):
        return False
    if issubclass(value_type, str):
        return key in STRING_PROTOTYPE_METHODS
    if issubclass(value_type, list):
        return key in ARRAY_PROTOTYPE_METHODS
    return False


def property_provably_absent(effects: EffectModel | None, value_type: type, key: str) -> bool:
    """
    Whether reading *key* off a value of *value_type* that does not own *key* provably yields
    `undefined`, so a caller may answer that in place of the read. This is the inherited half of a
    property access where `read_data_property` is the own half, and it is one function because every
    caller is deciding the same thing — what the prototype chain says about a key the value itself
    does not answer for — and each of them was deciding it alone with a different clause missing.

    Two questions have to answer together. The name must be one no prototype in the chain holds,
    which is what the tables above enumerate from a real engine rather than from the subset this
    package can evaluate: `normalize` is a function whether or not we can run it, and answering
    `undefined` for it would contradict `typeof`. And the chain has to still be the one the language
    describes, which only *effects* can say — `Object.prototype.z = 9` puts a name there that no
    table here lists, so deciding from the tables alone answers `undefined` where the program
    answers `9`.

    A caller with no effect model has nothing to consult and owns that assumption itself, the same
    way `EffectModel.trusted_intrinsic` leaves it with one. A `JsBuffer` is refused outright: its
    surface is over a hundred methods that vary between Node versions, so nothing is provably absent
    on one. So is every receiver this file enumerates no surface for — a function, a number — since
    the arms below name the three that have one and nothing else falls through them.
    """
    if key in OBJECT_PROTOTYPE_MEMBERS or key in PROTOTYPE_CHAIN_PROPERTIES:
        return False
    if issubclass(value_type, JsBuffer):
        return False
    if effects is not None and not effects.read_chain_intact(value_type):
        return False
    if issubclass(value_type, str):
        return key not in STRING_PROTOTYPE_METHODS and key not in SEQUENCE_DATA_PROPERTIES
    if issubclass(value_type, list):
        return key not in ARRAY_PROTOTYPE_METHODS and key not in SEQUENCE_DATA_PROPERTIES
    return issubclass(value_type, dict)


def utf16_code_units(text: str) -> list[str]:
    """
    Split *text* into its UTF-16 code units, which is what JavaScript indexing and `split('')` operate
    on. Python strings are sequences of code points, so a character outside the BMP is one Python
    character but two JavaScript ones: `'\U0001F600'.split('')` has length 2 in JS, and each half is a
    lone surrogate. Iterating the Python string directly would under-count it.
    """
    units: list[str] = []
    for char in text:
        units.extend(code_units(ord(char)))
    return units


def _to_int32(v: int | float) -> int:
    """
    Replicate the ECMA-262 ToInt32 abstract operation: `NaN`, `+Infinity`, and `-Infinity` all
    coerce to `0`, finite floats truncate towards zero, the result is taken mod 2^32 and
    sign-extended to the int32 range.
    """
    if isinstance(v, float):
        if v != v or v == float('inf') or v == float('-inf'):
            return 0
        v = int(v) if v >= 0 else -int(-v)
    v = v & 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def _to_uint32(v: int | float) -> int:
    """
    Replicate the ECMA-262 ToUint32 abstract operation.
    """
    if isinstance(v, float):
        if v != v or v == float('inf') or v == float('-inf'):
            return 0
        v = int(v) if v >= 0 else -int(-v)
    return v & 0xFFFFFFFF


def to_boolean(value: Value) -> bool:
    """
    Apply the ECMA-262 ToBoolean abstract operation. This is the value-domain counterpart of the
    AST-node `is_truthy`; the two must agree on which values are falsy (`undefined`, `null`, `0`,
    `NaN`, `''`) so that interpreted and statically-folded conditionals stay consistent.
    """
    if value is None or value is JS_NULL:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0 and value == value
    if isinstance(value, str):
        return len(value) > 0
    if isinstance(value, list):
        return True
    if isinstance(value, dict):
        return True
    if isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return True
    return False


def to_number(value: Value) -> float:
    """
    Apply the ECMA-262 ToNumber abstract operation, which is a dispatch on the type of a value. The
    string case is the only one with a grammar behind it, and that grammar is `js_string_to_number`
    in the Number domain, where the reading of a Number belongs; asking Python's `float` here
    instead would answer a different question, its own grammar being wider than the language's in
    several places at once.
    """
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return to_js_number(value)
    if isinstance(value, str):
        return js_string_to_number(value)
    if value is JS_NULL:
        return 0.0
    if isinstance(value, list):
        return to_number(to_string(value))
    return float('nan')


def function_source(func: _FuncDecl | _FuncExpr | _Arrow) -> str:
    """
    The text `Function.prototype.toString` answers for *func*. A function the parser read carries
    the source it was written with; one a transform built carries none, and is written back the way
    the synthesizer would write it, which is what running that program would then read for it.
    """
    if func.source_text is not None:
        return func.source_text
    from refinery.lib.scripts.js.synth import JsSynthesizer
    return JsSynthesizer().convert(func)


def to_string(value: Value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return 'undefined'
    if value is JS_NULL:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return js_number_to_string(value)
    if isinstance(value, list):
        return ','.join(_array_element_string(v) for v in value)
    if isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return function_source(value)
    return '[object Object]'


def _array_element_string(value: Value) -> str:
    """
    Stringify an array element for `Array.prototype.toString` / `join` / the string coercion of
    the whole array. JavaScript renders `null`, `undefined` and hole elements as the empty string
    (e.g. `[1, null, 2].toString()` is `'1,,2'`), unlike a top-level `String(null)` which is
    `'null'`.
    """
    if value is None or value is JS_NULL or value is JS_HOLE:
        return ''
    return to_string(value)


def _to_int(value: Value) -> int:
    n = to_number(value)
    if n != n or math.isinf(n):
        return 0
    return int(n)


def js_typeof(value: Value) -> str:
    """
    Apply the `typeof` operator to a value. Total over the domain, and the reason `typeof null` is
    `'object'` falls out of the ordering rather than being stated: `JS_NULL` is not any of the
    primitive types tested for, so it reaches the same answer every object does.
    """
    if value is None:
        return 'undefined'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return 'function'
    return 'object'


def _js_div(a: int | float, b: int | float) -> int | float:
    if b == 0:
        if a == 0 or a != a:
            return float('nan')
        negative = (a < 0) != (math.copysign(1.0, b) < 0)
        return float('-inf') if negative else float('inf')
    return a / b


def _js_mul(a: int | float, b: int | float) -> int | float:
    """
    Multiply two JavaScript numbers, preserving the IEEE-754 sign of a zero product: a product of
    magnitude zero is negative zero exactly when the operands have opposite signs. Python integer
    multiplication cannot represent `-0`, so `0 * -5` would otherwise silently lose the sign.
    """
    result = a * b
    if result == 0 and (math.copysign(1.0, a) < 0) != (math.copysign(1.0, b) < 0):
        return -0.0
    return result


def _js_mod(a: int | float, b: int | float) -> int | float:
    if b == 0 or a != a or b != b:
        return float('nan')
    if a == float('inf') or a == float('-inf'):
        return float('nan')
    if b == float('inf') or b == float('-inf'):
        return a
    return math.fmod(a, b)


def _js_pow(base: int | float, exp: int | float) -> float:
    """
    Replicate JavaScript exponentiation (`**` / `Math.pow`). JavaScript numbers are IEEE-754 doubles,
    so this diverges from Python in cases that matter: `anything ** 0` is `1` (even `NaN ** 0`); a base
    of `1` or `-1` with an infinite exponent is `NaN` (Python: `1.0`); a negative base with a
    non-integer exponent is a complex number in Python (JS: `NaN`); a zero base with a negative
    exponent is `Infinity` (with the sign rule for `-0`); and a magnitude beyond the double range is
    `Infinity`, whereas Python's arbitrary-precision `int ** int` returns an exact bignum.

    An infinite exponent is decided from the base's *magnitude* alone and never from its sign, which
    is why it is answered before the negative-base rule rather than folded into it. Raising `-2` to
    `Infinity` is `Infinity` and raising `-0.5` to it is `0`, where reading an infinite exponent as
    a non-integer one would call both `NaN`.

    Both operands are coerced here and not only at `eval_binary_op`, because this is the one
    operator that answers an unbounded amount of work when handed Python integers, and it is
    reachable through `BINARY_OPS` without passing that function.
    """
    base = to_js_number(base)
    exp = to_js_number(exp)
    inf = float('inf')
    if exp == 0:
        return 1.0
    if base != base or exp != exp:
        return float('nan')
    if exp in (inf, -inf):
        magnitude = abs(base)
        if magnitude == 1:
            return float('nan')
        return inf if (magnitude > 1) == (exp == inf) else 0.0
    is_int_exp = exp == int(exp)
    if base == 0 and exp < 0:
        if is_int_exp and int(exp) % 2 != 0 and math.copysign(1.0, base) < 0:
            return -inf
        return inf
    if base < 0 and base != -inf and not is_int_exp:
        return float('nan')
    try:
        result = base ** exp
    except OverflowError:
        return -inf if (base < 0 and is_int_exp and int(exp) % 2 != 0) else inf
    except (ValueError, ZeroDivisionError):
        return float('nan')
    return result


BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : _js_mul,
    '/'  : _js_div,
    '%'  : _js_mod,
    '**' : _js_pow,
    '|'  : lambda a, b: float(_to_int32(a) | _to_int32(b)),
    '&'  : lambda a, b: float(_to_int32(a) & _to_int32(b)),
    '^'  : lambda a, b: float(_to_int32(a) ^ _to_int32(b)),
    '<<' : lambda a, b: float(_to_int32(_to_int32(a) << (_to_int32(b) & 0x1F))),
    '>>' : lambda a, b: float(_to_int32(a) >> (_to_int32(b) & 0x1F)),
}
"""
JavaScript's binary operators over two *numbers*. Every entry assumes both operands have already been coerced,
which is why `+` is `operator.add` here: on numbers that is what `+` means, but on a value that may be a string
or an object `+` is a different operator entirely — it applies ToPrimitive to both sides and concatenates when
either is a string. A caller holding uncoerced values must not reach this table for `+`; the interpreter routes
every operator through `JsInterpreter._apply_binary`, which resolves the string cases before delegating here.
"""

UNARY_OPS: dict[str, Callable[[Value], Value]] = {
    '-'     : lambda v: -to_number(v),
    '+'     : to_number,
    '~'     : lambda v: float(_to_int32(~_to_int(v))),
    '!'     : lambda v: not to_boolean(v),
    'void'  : lambda v: None,
    'typeof': js_typeof,
}
"""
JavaScript's unary operators that are functions of their operand's *value* alone. Each is total over
the value domain — the coercions answer for every value rather than refusing any — so a caller holding
a value needs no per-operator guard, and a caller holding a syntax tree needs only to obtain the value.

`delete` is absent because it is not one of these: its result depends on the operand's *reference*
rather than its value, and evaluating it changes the object it names. A pass that wants to fold a
`delete` has to reason about that object, which is a question about the program and not about a value,
so the absence is what keeps this table from being asked it.

`void` is a member despite discarding its operand, because discarding a value is still a function of
it. The caller remains responsible for evaluating the operand: `void f()` is `undefined` and calls `f`,
and this table only supplies the first half.
"""

RELATIONAL_OPS: dict[str, Callable] = {
    '<' : operator.lt,
    '>' : operator.gt,
    '<=': operator.le,
    '>=': operator.ge,
}

LOGICAL_ASSIGNMENT_OPS = frozenset({'&&=', '||=', '??='})
"""
The assignment operators that short-circuit. Unlike every other compound assignment, these evaluate their
right operand only when the target's existing value does not already decide the result, and perform no store
when it does — a distinction JavaScript makes observable through a setter or a frozen object. They therefore
have no entry in `BINARY_OPS`, whose members are total functions of both operands.
"""


def eval_binary_op(op: str, left: float, right: float) -> float | bool | None:
    """
    Evaluate a JavaScript binary operator on two numeric operands. Returns the result value, or
    `None` when the operator is unknown or the computation overflows/divides by zero. Handles
    arithmetic, bitwise, relational, equality, and the unsigned right shift `>>>`.

    Both operands are coerced here so that every operator below sees the Number the caller meant and
    not whichever Python type happened to carry it. That is a normalization and not the bound on the
    work: `refinery.lib.scripts.js.deobfuscation.stringarray` reaches `BINARY_OPS` without passing
    through this function, so the operator that can be asked for unbounded work — `**`, where Python
    integers build a number of half a billion digits for what a double answers in one operation —
    coerces for itself as well.
    """
    left = to_js_number(left)
    right = to_js_number(right)
    if op in ('===', '=='):
        return left == right
    if op in ('!==', '!='):
        return left != right
    rel = RELATIONAL_OPS.get(op)
    if rel is not None:
        return rel(left, right)
    if op == '>>>':
        a = _to_uint32(left)
        b = _to_uint32(right) & 0x1F
        return float((a >> b) & 0xFFFFFFFF)
    fn = BINARY_OPS.get(op)
    if fn is None:
        return None
    try:
        return fn(left, right)
    except (ZeroDivisionError, OverflowError, ValueError):
        return None


def _escape_residue(m: re.Match[str]):
    cp = ord(m.group())
    if cp > 0xFF:
        return F'\\u{cp:04X}'
    return F'\\x{cp:02x}'


def spell_astral_characters(value: str) -> str:
    """
    Write the pairs of code units that name a character above the basic plane as that character. A
    value is held as the code units a JavaScript string is made of, which is what a program asking
    about its length or its halves has to be answered from; but a file is written in characters, so
    printing the units back would spell an emoji as two escapes nobody wrote.

    A surrogate standing alone is left alone. It names no character, so there is nothing to write it
    as, and an escape is the only spelling a file has for it.
    """
    return from_code_units(value)


def code_points(value: str) -> list[str]:
    """
    The code points of a string, each kept as the code units that spell it. A JavaScript string is
    indexed by code unit but iterated by code point — a `for ... of`, a spread, `Array.from` — so a
    well-formed surrogate pair is one element here, and every other code unit is its own. A lone
    surrogate stands as a code point of its own, because a string may hold one and the split may not
    invent the partner it lacks.
    """
    points: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        step = 2 if SURROGATE_PAIR.match(value, index) else 1
        points.append(value[index:index + step])
        index += step
    return points


def escape_js_string(value: str, quote: str = "'") -> str:
    """
    Escape a string for use in a JavaScript string literal. Returns the escaped body without
    surrounding quotes. Backslash is escaped first to avoid double-escaping. Control characters
    not covered by named escapes are emitted as `\\xHH`; a surrogate that names no character on its
    own as `\\uXXXX`, and a pair of them as the character they name.

    A NUL is `\\0`, except where a digit stands behind it: `\\0` followed by `0` through `7` is one
    legacy octal escape and would swallow the digit into a different character, and followed by `8`
    or `9` it is an escape strict code refuses. A NUL a digit follows is spelled `\\x00` instead, so
    the character behind it stays the character the value held.
    """
    value = spell_astral_characters(value)
    value = value.replace('\\', r'\\')
    value = value.replace('\n', r'\n')
    value = value.replace('\r', r'\r')
    value = value.replace('\t', r'\t')
    value = re.sub(r'\x00(?=[0-9])', r'\\x00', value)
    value = value.replace('\0', r'\0')
    value = value.replace(quote, F'\\{quote}')
    return re.sub(r'[\x01-\x1f\ud800-\udfff]', _escape_residue, value)


def escape_js_template_text(value: str) -> str:
    """
    Escape a string so that it spells itself inside a template literal. Three characters end a run
    of template text rather than standing in it — the backtick that closes the literal, the `${`
    that opens a hole, and the backslash that would eat what follows it.

    A line feed stands as itself, because a template is the one literal that may span lines. A
    carriage return does not: every line terminator sequence a template is written with denotes a
    line feed, so a return written into the text would come back as one and the string would not
    be the string. A lone surrogate has to be spelled too, for the same reason a string spells one
    — there is no encoding of the file that carries it.
    """
    value = spell_astral_characters(value)
    value = value.replace('\\', r'\\')
    value = value.replace('\r', r'\r')
    value = value.replace('`', r'\`')
    value = value.replace('${', r'\${')
    return re.sub(r'[\x00-\x08\x0b-\x1f\ud800-\udfff]', _escape_residue, value)


def string_value(node: Expression | None) -> str | None:
    """
    The text a literal denotes, where it is a literal that denotes one. A literal the source never
    closed is not, and answering with the text it would have denoted is how a fold repairs it: the
    text goes into a fresh literal that carries the closing quote nobody wrote, and a file that no
    engine reads comes back as a program that runs.
    """
    if isinstance(node, JsStringLiteral) and node.terminated:
        return node.value
    return None


def property_key(prop: JsProperty) -> str | None:
    """
    Extract the string key from a property node. Handles both string-literal keys and plain
    identifier keys. Returns `None` for computed keys.
    """
    if prop.computed:
        return None
    if isinstance(prop.key, JsStringLiteral):
        return prop.key.value
    if isinstance(prop.key, JsIdentifier):
        return prop.key.name
    return None


def access_key(node: JsMemberExpression) -> str | None:
    """
    Extract the string key from a member-access expression. Handles both computed (`obj['key']`)
    and dot (`obj.key`) accesses.
    """
    if node.computed:
        return string_value(node.property)
    if isinstance(node.property, JsIdentifier):
        return node.property.name
    return None


def names_this_realms_global_object(model: SemanticModel, node: Node | None) -> bool:
    """
    Whether *node* denotes this realm's global object: it is spelled with one of
    `SAME_REALM_GLOBAL_OBJECT_ALIASES` and nothing binds that name where it stands. Both halves are
    needed by every pass that acts on a property written through such a spelling, because a
    declaration of the name binds it and the access then reads an ordinary object the program may
    read back through any second name for it.

    The two questions are one predicate because a pass asking only the first is the shape of a
    defect rather than of a policy: `refinery.lib.scripts.js.deobfuscation.unused` deleted a write
    on the object a `var self = {}` held, and
    `refinery.lib.scripts.js.deobfuscation.scramble.JsScrambleStringDecoder` deleted the
    installation of a decoder a later call still reached through the same object.

    A pass that needs the name the access designates asks
    `refinery.lib.scripts.js.analysis.model.SemanticModel.global_alias_member_name` instead, which
    answers both questions at once for a statically spelled key. This one is for a caller that reads
    its key some other way.
    """
    base = strip_parens(node)
    if not isinstance(base, JsIdentifier) or base.name not in SAME_REALM_GLOBAL_OBJECT_ALIASES:
        return False
    return model.lookup(base.name, model.scope_of(base)) is None


def make_string_literal(value: str) -> JsStringLiteral:
    escaped = escape_js_string(value)
    raw = F"'{escaped}'"
    return JsStringLiteral(value=value, raw=raw)


def numeric_value(node: Expression) -> float | None:
    if isinstance(node, JsNumericLiteral):
        return node.value
    return None


def make_numeric_literal(value: int | float) -> JsNumericLiteral | None:
    """
    Spell a Number as a literal, or refuse with `None` when it has none. `NaN` is the only Number
    without one, and a caller that can produce it must spell it through `value_to_node`.

    The infinities do have one. ECMA-262 defines the mathematical value of a decimal literal and then
    rounds it to the nearest Number, and a value too large to round to a finite one rounds to the
    infinity — so `1e999` is a numeric literal denoting `+Infinity` exactly as `1` is one denoting
    one. That matters because the alternative spelling, the identifier `Infinity`, is an ordinary
    global binding that the program being deobfuscated may have rebound, whereas a literal denotes
    its value in every scope.

    The spelling is otherwise `Number.prototype.toString`, with one deliberate deviation: that
    algorithm reads the mathematical value, so it prints negative zero as `0`, but a literal `0`
    denotes *positive* zero and the two are distinguishable — `1 / -0` is `-Infinity`. Negative zero
    is therefore spelled `-0`. That spelling, like `-1e999` and the one every other negative value
    gets, is a negation applied to a literal rather than a literal, so the node binds like the unary
    operator it starts with. That is a fact about the spelling, which
    `refinery.lib.scripts.js.precedence` therefore reads from the `raw` rather than from the class.
    """
    value = to_js_number(value)
    if value != value:
        return None
    if value == float('inf'):
        return JsNumericLiteral(value=value, raw='1e999')
    if value == float('-inf'):
        return JsNumericLiteral(value=value, raw='-1e999')
    if is_negative_zero(value):
        return JsNumericLiteral(value=value, raw='-0')
    return JsNumericLiteral(value=value, raw=js_number_to_string(value))


def make_undefined_expression() -> JsUnaryExpression:
    """
    The expression that spells `undefined`. That value has no literal, and the global name that
    denotes it is an ordinary binding which any scope may rebind, so it is written as an operator
    applied to a literal instead: `void 0` denotes it wherever it stands.
    """
    return JsUnaryExpression(operator='void', operand=JsNumericLiteral(value=0, raw='0'))


def make_nan_expression() -> JsBinaryExpression:
    """
    The expression that spells `NaN`, which has no literal either, for the same reason and by the
    same means: `0 / 0`.
    """
    return JsBinaryExpression(
        operator='/',
        left=JsNumericLiteral(value=0, raw='0'),
        right=JsNumericLiteral(value=0, raw='0'),
    )


def denotes_nan(node: Node) -> bool:
    """
    Whether *node* is the expression `make_nan_expression` builds. A zero literal divided by a zero
    literal is `NaN` however either zero happens to be written, so the test reads the two values
    rather than the text.
    """
    return (
        isinstance(node, JsBinaryExpression)
        and node.operator == '/'
        and isinstance(node.left, JsNumericLiteral)
        and isinstance(node.right, JsNumericLiteral)
        and node.left.value == 0
        and node.right.value == 0
    )


def extract_literal_value(node: Node) -> tuple[bool, LiteralValue]:
    """
    Extract a Python value from a literal AST node. Returns `(True, value)` on success or
    `(False, None)` when the node is not a recognized literal form. Handles string, numeric,
    boolean, null literals, `void expr`, negative numerics, `!0`/`!1`, `0 / 0`, and array
    expressions where all elements are themselves literals.

    A string literal that denotes nothing — one written with a `\\x` or `\\u` escape naming no
    character, whose `value` is `None` — is not a recognized literal form: reporting `(True, None)`
    for it would hand the caller the value `undefined`, folding a run the file could never have
    carried into a value it never named.

    The two forms that are operator expressions rather than literals, `void 0` and `0 / 0`, are here
    because they are what `undefined` and `NaN` have instead of a literal: an expression built from
    an operator, which no scope can rebind, rather than from one of the global names, which any
    scope can. Recognizing them is what lets those two values survive a round trip through the tree,
    and this must stay paired with `value_to_node`, its declared inverse.
    """
    if isinstance(node, JsStringLiteral):
        if not node.terminated or node.value is None:
            return False, None
        return True, node.value
    if isinstance(node, JsNumericLiteral):
        return True, node.value
    if isinstance(node, JsBooleanLiteral):
        return True, node.value
    if isinstance(node, JsNullLiteral):
        return True, JS_NULL
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'void' and isinstance(node.operand, VOID_LITERAL_OPERANDS):
            return True, None
        if node.operator == '-' and isinstance(node.operand, JsNumericLiteral):
            return True, -node.operand.value
        if node.operator == '+' and isinstance(node.operand, JsNumericLiteral):
            return True, node.operand.value
        if node.operator == '!' and isinstance(node.operand, JsNumericLiteral):
            return True, not bool(node.operand.value)
    if denotes_nan(node):
        return True, float('nan')
    if isinstance(node, JsArrayExpression):
        items: list[LiteralValue] = []
        for el in node.elements:
            if el is None:
                return False, None
            ok, val = extract_literal_value(el)
            if not ok:
                return False, None
            items.append(val)
        return True, items
    return False, None


#: The largest list a fold may splice in place of the expression that computed it, so one decoded
#: string array replaces its decoder while a fold computed over a whole file's worth of data
#: cannot rebuild the file as a literal.
MAX_RESULT_ARRAY_LEN = 260


def replace_with_value(node: Node, result: object) -> bool:
    """
    Replace *node* with a literal denoting *result*, refusing when no such literal exists or when
    the literal would be larger than the expression it replaces. Every path that folds a call to a
    value shares this, so the result guards cannot be present at one and missing at another.
    Announcing the change is the caller's — it owns `mark_changed`.
    """
    if isinstance(result, list) and len(result) > MAX_RESULT_ARRAY_LEN:
        return False
    replacement = value_to_node(result)
    if replacement is None:
        return False
    _replace_in_parent(node, replacement)
    return True


def value_to_node(value: object) -> Expression | None:
    """
    Convert a Python value to the corresponding AST literal node, or `None` when the value has no
    literal form that denotes it faithfully. Refusing is always sound — the caller leaves the original
    expression in place — whereas rendering an approximation silently changes what the program means,
    so every case here either round-trips exactly or returns `None`.

    A number is spelled by `make_numeric_literal` whatever its sign, so that a negative one is a single
    literal carrying its sign in the `raw` and not a negation applied to its magnitude. Those two nodes
    synthesize to the same text, which is what let the second spelling go unnoticed, but only the first
    is a `JsNumericLiteral`: the fold that reads an operand with `numeric_value` sees a number in one
    and nothing in the other.

    `NaN` and `undefined` are the only values this returns a compound node for, because they are the
    only ones no literal denotes. Neither is spelled with the global name that names it. Those names
    are ordinary bindings, and this function does not know the scope it is writing into: a fold that
    happens under `function (NaN) { … }` would otherwise emit text meaning the parameter.

    A list holding a hole has no faithful literal: a hole is spelled by an elision, which a
    synthesized array literal writes as no element at all, so a hole at any depth — including
    one inside a nested list, where the residual would flip an `in` the hole answered — refuses
    the whole value.
    """
    if isinstance(value, str):
        return make_string_literal(value)
    if isinstance(value, bool):
        return JsBooleanLiteral(value=value)
    if isinstance(value, (int, float)):
        number = to_js_number(value)
        if number != number:
            return make_nan_expression()
        return make_numeric_literal(number)
    if isinstance(value, JsBuffer):
        return None
    if isinstance(value, list):
        if _holes_present(value):
            return None
        elements: list[Expression | None] = []
        for item in value:
            el = value_to_node(item)
            if el is None:
                return None
            elements.append(el)
        return JsArrayExpression(elements=elements)
    if isinstance(value, dict):
        properties = []
        for k, v in value.items():
            if not isinstance(k, str):
                return None
            val_node = value_to_node(v)
            if val_node is None:
                return None
            properties.append(JsProperty(
                key=make_string_literal(k),
                value=val_node,
                computed=k == PROTO_KEY,
            ))
        return JsObjectExpression(properties=properties)
    if value is JS_NULL:
        return JsNullLiteral()
    if value is None:
        return make_undefined_expression()
    return None


def is_literal(node: Node) -> bool:
    """
    Whether *node* is a constant expression whose value the tree carries in full — the test a pass
    applies before cloning it to another position. `void 0` and `0 / 0` count for the same reason
    `extract_literal_value` reads them: they are what `undefined` and `NaN` have instead of a
    literal, and an operator applied to literals is as constant as a literal is.
    """
    if isinstance(node, JsStringLiteral):
        return node.terminated
    if isinstance(node, (JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'void' and isinstance(node.operand, VOID_LITERAL_OPERANDS):
            return True
        if node.operator == '-' and isinstance(node.operand, JsNumericLiteral):
            return True
    return denotes_nan(node)


def member_key(node: JsMemberExpression) -> str | None:
    """
    Flatten a chain of property accesses into a dot-separated key string. Handles both dot
    notation and computed access with string-literal keys. Returns `None` if the chain contains
    a dynamic computed access that cannot be resolved to a static key.
    """
    parts: list[str] = []
    cursor: Expression | None = node
    while isinstance(cursor, JsMemberExpression):
        key = access_key(cursor)
        if key is None:
            return None
        parts.append(key)
        cursor = cursor.object
    if not isinstance(cursor, JsIdentifier):
        return None
    parts.append(cursor.name)
    parts.reverse()
    return '.'.join(parts)


def is_while_true(node: JsWhileStatement) -> bool:
    """
    Check whether the while-loop condition is `true`, `!![]`, or `!0` — the forms the
    obfuscator uses for infinite loops.
    """
    test = node.test
    if isinstance(test, JsBooleanLiteral) and test.value is True:
        return True
    if not isinstance(test, JsUnaryExpression) or test.operator != '!':
        return False
    inner = test.operand
    if isinstance(inner, JsNumericLiteral) and inner.value == 0:
        return True
    if isinstance(inner, JsUnaryExpression) and inner.operator == '!':
        return True
    return False


def is_valid_identifier(name: str) -> bool:
    return bool(SIMPLE_IDENTIFIER.match(name)) and name not in JS_RESERVED


def is_valid_property_key(name: str) -> bool:
    return bool(SIMPLE_IDENTIFIER.match(name))


def is_simple_expression(node: Node) -> bool:
    """
    Check whether a node is a side-effect-free leaf expression: a literal value, an identifier, or
    a unary operator applied to a literal (e.g. `-42`).
    """
    if is_literal(node) or isinstance(node, JsIdentifier):
        return True
    if isinstance(node, JsUnaryExpression) and node.operand is not None:
        return is_literal(node.operand)
    return False


def is_write_target(node: JsIdentifier) -> bool:
    """
    Return whether this identifier is a write target: the left-hand side of an assignment
    expression, or the iteration variable of a `for-in` / `for-of` statement.
    """
    p = node.parent
    if isinstance(p, JsAssignmentExpression) and p.left is node:
        return True
    if isinstance(p, (JsForInStatement, JsForOfStatement)) and p.left is node:
        return True
    return False


def is_binding_site(node: JsIdentifier) -> bool:
    """
    Return whether this identifier is in a binding position (variable declarator id or function
    declaration name) rather than a reference/read position.
    """
    p = node.parent
    if isinstance(p, JsVariableDeclarator) and p.id is node:
        return True
    if isinstance(p, JsFunctionDeclaration) and p.id is node:
        return True
    return False


def is_reference(node: JsIdentifier) -> bool:
    """
    Whether this identifier reads or writes a binding rather than declaring one or naming something
    the program cannot refer to. `is_use_position` answers the second half and is the one statement
    of it; what is added here are the declarations `is_binding_site` recognizes by shape, so that
    this is the syntactic approximation of `SemanticModel.is_reference` and not a second opinion
    about what a name is.

    Every position naming a property, a label or something across a module boundary is excluded
    exactly as the model excludes it, and the local half of a sourceless export list reads exactly
    as the model reads it. The approximation is in the declarations, and it is a *permissive* one:
    a name bound by a destructuring pattern is written like a read and `is_binding_site` sees only
    a declarator id and a function declaration name, so `var { a } = o` is answered `True` here and
    `False` by the model. A caller that acts on a `True` answer — one that substitutes or renames
    rather than one that grows a conservative set — needs the model.
    """
    return not is_binding_site(node) and is_use_position(node)


def name_is_unbound(node: JsIdentifier, model: SemanticModel) -> bool:
    """
    Whether nothing in the program can have given *node*'s name a meaning of its own, so that it still
    denotes whatever the host supplies under that name. This is the question behind every table of
    well-known names the tool keeps — the values in `GLOBAL_VALUE_NAMES`, the built-ins in
    `BUILTIN_REGISTRY` — because what such a table records is a fact about the *host*, and whether the
    name still reaches the host is a fact about the *scope*.

    There are three ways a name can mean something else, and `resolve` reports only the first:

    - a declaration binds it, anywhere from a parameter or a `catch` clause to an assignment at top
      level, which the model records as an `IMPLICIT_GLOBAL`
    - the lookup crosses a `with` body, where the object may carry a property of that name and reading
      it may even run a getter. `resolve` answers `None` here as well, so `read_has_dynamic_effect` is
      what separates the two cases
    - a direct `eval` declared it, which no reference records at all;
      `free_name_reachable_by_direct_eval` reports the positions that could see such a binding
    """
    return (
        model.resolve(node) is None
        and not model.read_has_dynamic_effect(node)
        and not model.free_name_reachable_by_direct_eval(node)
    )


def names_global_value(node: JsIdentifier, model: SemanticModel) -> bool:
    """
    Whether *node* is one of `GLOBAL_VALUE_NAMES` still denoting its value. Every reader of those
    names has to come through here.
    """
    return node.name in GLOBAL_VALUE_NAMES and name_is_unbound(node, model)


def denoted_value(node: Node | None, model: SemanticModel) -> tuple[bool, Value]:
    """
    The value *node* denotes, as `(True, value)`, or `(False, None)` when nothing decides it. This is
    `extract_literal_value` widened by the two things a literal cannot express: a name that still
    denotes one of the global values, and an operator standing in front of either.
    """
    node = strip_parens(node)
    if node is None:
        return False, None
    if isinstance(node, JsIdentifier):
        if not names_global_value(node, model):
            return False, None
        return True, GLOBAL_VALUE_NAMES[node.name]
    if isinstance(node, JsUnaryExpression):
        apply = UNARY_OPS.get(node.operator)
        if apply is None:
            return False, None
        known, value = denoted_value(node.operand, model)
        return (True, apply(value)) if known else (False, None)
    return extract_literal_value(node)


def allocated_object_type(node: Node | None) -> str | None:
    """
    The `typeof` of the object *node* allocates, when it is a form that always evaluates to a freshly
    created one — `None` otherwise. Such a node has no value this module can extract: an object or
    function expression denotes an identity no literal reproduces, and an array whose elements are
    not themselves literals is the same. Its *type* is nevertheless fixed by the syntax alone, and so
    is its truthiness, since every object is truthy — which is why `!{}`, `typeof {}` and
    `if ([f()])` are all answerable from this one fact.

    Deciding an operand from its allocation says nothing about whether evaluating it is free of
    effects; `[f()]` allocates an array and calls `f`. A caller that discards the operand has to ask
    that separately.
    """
    node = strip_parens(node)
    if isinstance(node, (JsObjectExpression, JsArrayExpression)):
        return 'object'
    if isinstance(node, (JsFunctionExpression, JsArrowFunctionExpression, JsClassExpression)):
        return 'function'
    return None


def is_truthy(node: Node, cache: ModelCache) -> bool | None:
    """
    The JavaScript truthiness of *node*, or `None` when nothing decides it. The AST-node counterpart
    of the value-domain `to_boolean`, which it answers by asking wherever a value is known: the two
    used to agree by inspection, and now agree by construction.

    An allocation is the one case with no value to ask about, and it needs none — every object is
    truthy. This does not gate that on the allocation being effect-free, because deciding truthiness
    does not by itself discard the operand; the caller that goes on to drop it is the one that has to
    keep its effects.

    A local binding is the remaining case: resolved through the model to its single allocation, it
    answers truthy — an empty array included, since emptiness never decides truthiness — but only
    where every establishment site of the value runs before the read, because a never-reassigned
    `var` still reads `undefined` before its initializer runs and `!undefined` takes the other
    branch. The ordering is the interprocedural runs-before, which recurses through the reference
    points of the function a cross-function read sits in, so the guard a network callback carries is
    ordered through the callback's own creation. Value stability rides along: a binding any
    reflective surface could reach — a script-scope name under a whole-program surface or an opaque
    global write, a local a direct `eval`, `with` body, or unread span in its own function could
    rebind — is refused (`reflection_can_reach`), since none of those replacements leaves a rebind
    site the ordering could place; the suspecting model refuses the eval leg and the trusting model
    assumes it away. Negation is transparent to the question: `!a` answers the opposite of `a`,
    however many `!` spell it.
    """
    operand, negated = _strip_negation(node)
    model = cache.model
    known, value = denoted_value(operand, model)
    if known:
        answer = to_boolean(value)
    elif allocated_object_type(operand) is not None:
        answer = True
    elif isinstance(operand, JsIdentifier):
        binding = model.resolve(operand)
        if binding is None or model.reflection_can_reach(binding):
            return None
        if _established_allocation_of(binding, operand, cache) is None:
            return None
        answer = True
    else:
        return None
    return not answer if negated else answer


def _strip_negation(node: Node) -> tuple[Node, bool]:
    """
    The operand *node* negates, once every `!` spelling a negation is removed, and whether an odd
    or even number of them was stripped — the operand of an odd count answers the opposite of the
    whole expression.
    """
    negated = False
    while isinstance(node, JsUnaryExpression) and node.operator == '!':
        negated = not negated
        node = node.operand
    return node, negated


def _established_allocation_of(binding: Binding, node: Node, cache: ModelCache) -> Node | None:
    """
    The allocation *binding* provably holds at the read *node*, when every establishment site of its
    single value runs before that read; `None` when the binding holds no single value, the read may
    precede the value, or the value is no allocation. The value and its establishment sites come
    from the same complete-singleton answer, which no dynamic rebind the text does not spell
    satisfies under the suspecting model; the ordering is the interprocedural runs-before, which
    recurses through the reference points of the function the read sits in, so a guard carried by a
    callback is ordered through the callback's creation.
    """
    model = cache.model
    value = model.singular_value(binding)
    sites = model.binding_establishment_sites(binding)
    if value is None or sites is None:
        return None
    if allocated_object_type(value) is None:
        return None
    if not all(cache.dominance.runs_before(site, node) for site in sites):
        return None
    return value


def is_nullish(node: Node, model: SemanticModel) -> bool | None:
    """
    Whether *node* denotes `null` or `undefined` — the two values `??` treats as absent — or `None`
    when the value it denotes is not decided. A caller has to tell that third answer from `False`:
    `a ?? b` keeps `a` when `a` is known not to be nullish, and must be left alone when nothing is
    known about it at all.
    """
    known, value = denoted_value(node, model)
    if not known:
        return None
    return value is None or value is JS_NULL


def value_is_discarded(node: Node) -> bool:
    """
    Whether the context governing `node` throws its value away, so removing `node` changes no value
    the program goes on to read: an expression statement, or a sequence operand other than the last,
    whose value the sequence yields. Parentheses are looked through. A node whose value is consumed
    — a declarator initializer, a call argument, a `return` — is not discardable, and removing it
    would strand its consumer.
    """
    cur = node
    parent = cur.parent
    while isinstance(parent, JsParenthesizedExpression):
        cur, parent = parent, parent.parent
    if isinstance(parent, JsExpressionStatement):
        return True
    if isinstance(parent, JsSequenceExpression):
        return bool(parent.expressions) and parent.expressions[-1] is not cur
    return False


def definitely_answers_the_completion(stmt: Statement) -> bool:
    """
    Whether evaluating *stmt* certainly supplies a value — the value the statement list it stands
    in answers when nothing behind it does, which is what an `eval` of the file receives and what a
    function hands its caller when control falls off its end. A statement this answers for is one
    no statement ahead of it can be answering, so a reader deciding whether an inert statement may
    go finds here the shadow it needs to drop it.

    An expression statement supplies one even where evaluating it throws: the throw is what the
    program does then, and no earlier statement was the answer. A `return` supplies its function's
    value and a `throw` aborts, and neither leaves an earlier statement answering. A block or a
    label passes the question inward, unless a `break` or `continue` can carry control out of it
    before the value is reached: such a jump completes the block empty and lets the enclosing
    construct answer from an earlier value, so a block that holds one is not certain to answer and
    is refused. Everything else — a declaration, an empty statement, a `debugger`, and every
    conditional or iterative construct, whose run may skip the value it guards — answers `False`,
    which keeps the statement ahead of it standing.
    """
    if isinstance(stmt, (JsExpressionStatement, JsReturnStatement, JsThrowStatement)):
        return True
    if isinstance(stmt, JsBlockStatement):
        if any(
            isinstance(node, (JsBreakStatement, JsContinueStatement))
            for node in walk_scope(stmt)
        ):
            return False
        return any(definitely_answers_the_completion(inner) for inner in stmt.body)
    if isinstance(stmt, JsLabeledStatement):
        return stmt.body is not None and definitely_answers_the_completion(stmt.body)
    return False


def body_returns_undefined(statements: list[Statement]) -> bool:
    """
    Whether a function whose body is *statements* hands its caller `undefined` — it runs off its end,
    or its last statement is a valueless `return`. A trailing `return x` hands back `x`, which
    `sanitize_inlined_body` turns into the tail expression, so the inlined body already carries it and
    the caller must not force the end value back to `undefined`.
    """
    return not (
        statements
        and isinstance(statements[-1], JsReturnStatement)
        and statements[-1].argument is not None
    )


def preserve_script_end_value(
    statements: list[Statement],
    *,
    returns_undefined: bool,
    at_script_end: bool,
) -> list[Statement]:
    """
    Adapt an inlined body so that, where it replaces a call that stood at the script's own end, the
    script still hands back the value the call did. A call whose function ran off its end returned
    `undefined`, but the inlined body may leave a value of its own in the end position the call did not
    hold, so a `void 0` is appended to hold the end value at `undefined`. The append is unconditional
    under the gate: the end value of a statement list is its last *non-empty* completion, which a tail
    that itself completes empty (a declaration, a `break`) does not supply — it is supplied by an
    earlier statement — so testing only the last statement would miss the leak. A redundant `void 0`
    after a tail that already completes to `undefined` is inert. Nothing is appended where the call was
    not at the end (its value was already discarded) or where the function returned a value the splice
    already carries (a trailing `return x` became the tail expression, so *returns_undefined* is False).
    """
    if not (at_script_end and returns_undefined):
        return statements
    return [*statements, JsExpressionStatement(expression=make_undefined_expression())]


def insert_after_prologue(host: Node, statements: list[Statement]) -> None:
    """
    Insert *statements* into the body of *host* directly behind its Directive Prologue, adopting them
    and advancing the tree's mutation counter the one way every splice does.

    Index zero is where a hoisted declaration wants to go and the one place a directive cannot
    survive: a statement written ahead of `'use strict'` ends the prologue before it is reached, and
    the body quietly becomes sloppy — an assignment to an undeclared name stops throwing and starts
    creating a global instead. Behind the prologue is the same position for every purpose a hoist has,
    a directive declaring a mode and binding nothing.

    The whole prologue is stepped over and not merely the Use Strict Directive. A directive the
    language does not recognize is a directive all the same, and a statement wedged in front of one
    ends the run for everything standing behind it.

    *host* is taken rather than its statement list precisely so that this cannot be called the raw
    way: a caller holding only the list can reach `insert` and would not be asking this question.

    The list is read through `statement_list`, which answers for every node a prologue can open —
    including a class static block, which `get_body` does not know. Reading it through a narrower
    accessor than `is_prologue_host` accepts would make this a silent no-op for a host it advertises,
    and a hoist that vanishes leaves the references a pass already rewrote bound to nothing.
    """
    body = statement_list(host)
    if body is None:
        return
    index = len(directive_prologue(host)) if is_prologue_host(host) else 0
    set_body(host, [*body[:index], *statements, *body[index:]])


def get_body(node: Node) -> list[Statement] | None:
    """
    Return the statement body list of a node if it has one (JsScript or JsBlockStatement).
    """
    if isinstance(node, (JsScript, JsBlockStatement)):
        return node.body
    return None


def remove_declarator(declarator: JsVariableDeclarator) -> None:
    """
    Remove a `refinery.lib.scripts.js.model.JsVariableDeclarator` from its parent
    `refinery.lib.scripts.js.model.JsVariableDeclaration`. If the declaration has no remaining
    declarators afterward, remove it from the body as well.
    """
    var_decl = declarator.parent
    _remove_from_parent(declarator)
    if isinstance(var_decl, JsVariableDeclaration) and not var_decl.declarations:
        _remove_from_parent(var_decl)


def sanitize_inlined_body(stmts: list[Statement]) -> list[Statement] | None:
    """
    Adapt a spliced body's statements for the statement position they replace, where the call's
    return value is discarded and no `return` may escape into the container. A trailing `return x`
    becomes the bare expression `x` (its value was already being thrown away) and a trailing
    valueless `return` is dropped. Any other `return` — before the last statement, or nested in the
    control flow of any statement (an `if`, loop, or `try`) rather than at the body's own top level —
    declines the splice (`None`), since its early exit cannot be reproduced at statement position
    without reordering and declining is always sound. `walk_scope` finds a nested `return` without
    descending into a nested function, whose own `return` stays with it. This holds for every
    container, not only the script: a `return` spliced into a function body would return from that
    enclosing function, and into the script would be a syntax error.
    """
    if not stmts:
        return stmts
    trailing = stmts[-1] if isinstance(stmts[-1], JsReturnStatement) else None
    for stmt in stmts[:-1] if trailing is not None else stmts:
        if any(isinstance(node, JsReturnStatement) for node in walk_scope(stmt)):
            return None
    if trailing is None:
        return stmts
    if trailing.argument is not None:
        return [*stmts[:-1], JsExpressionStatement(expression=trailing.argument)]
    return stmts[:-1]


def references_new_target(root: Node) -> bool:
    """
    Whether *root* reads the `new.target` meta-property, which the parser models as a member access
    whose object is the reserved word `new`. A `Function`-constructed function is invoked as a call,
    so its `new.target` is always `undefined`; splicing the body into a real function would rebind
    `new.target` to the caller's, so a body that reads it cannot be inlined.
    """
    for node in root.walk():
        if (
            isinstance(node, JsMemberExpression)
            and isinstance(node.object, JsIdentifier)
            and node.object.name == 'new'
        ):
            return True
    return False


def hoist_path_is_clear(
    names: set[str],
    site_scope: Scope,
    var_scope: Scope,
    *,
    exclude: Collection[Binding] = (),
) -> bool:
    """
    Whether each hoisted `var`/function name can rise from the call site to *var_scope* without
    crossing a lexical binding of the same name. A `var` spliced into a block still hoists to the
    enclosing function or script, but it is a redeclaration SyntaxError if any block it passes
    through — from the site's own scope up to, but not including, *var_scope* — lexically binds the
    same name. Conflicts with a binding declared directly in *var_scope* are already caught by the
    capture check. A binding in *exclude* is read as absent: the edit the caller makes deletes it,
    taking the name with it out of the scope it passes through.
    """
    scope: Scope | None = site_scope
    while scope is not None and scope is not var_scope:
        if any(
            (binding := scope.bindings.get(name)) is not None and binding not in exclude
            for name in names
        ):
            return False
        scope = scope.parent
    return True


def inlined_declarations_safe(
    declared_scope: Scope,
    root_model: SemanticModel,
    site_scope: Scope,
    *,
    exclude: Collection[Binding] = (),
) -> bool:
    """
    Whether the names a spliced body declares at its own top level — the bindings of
    *declared_scope* — can be introduced at the site it is spliced into without capturing an
    identifier already meaningful there. Such declarations are local to the body's own function;
    inlining lifts `var` and function declarations into the caller's function or script scope and
    `let`/`const`/`class` into the caller's immediate block, where a same-named reference, an
    inherited binding, or a redeclaration would silently rebind to the inlined declaration or
    produce a duplicate lexical declaration. Each name is checked against the scope it would
    actually land in.

    *exclude* names the bindings the same edit deletes elsewhere: a use resolving to one is
    carried off by the deletion rather than captured, so the introduced declaration may share its
    name.
    """
    bindings = declared_scope.bindings
    hoisted = {name for name, binding in bindings.items() if binding.is_hoisted}
    lexical = {name for name, binding in bindings.items() if binding.is_lexical}
    if hoisted:
        var_scope = site_scope.var_scope
        if var_scope is None or root_model.would_capture(hoisted, var_scope, exclude=exclude):
            return False
        if not hoist_path_is_clear(hoisted, site_scope, var_scope, exclude=exclude):
            return False
    if lexical and root_model.would_capture(lexical, site_scope, exclude=exclude):
        return False
    return True


def extract_identifier_params(params: list) -> list[str] | None:
    """
    Extract plain identifier names from a function's parameter list. Returns `None` if any parameter
    is not a simple `refinery.lib.scripts.js.model.JsIdentifier` (e.g. destructuring or rest
    patterns).
    """
    names: list[str] = []
    for p in params:
        if not isinstance(p, JsIdentifier):
            return None
        names.append(p.name)
    return names


def is_closed_expression(node: Node, allowed_names: set[str]) -> bool:
    """
    Check whether every leaf in the expression tree is either a literal or an identifier whose
    name is in *allowed_names*. This ensures the expression has no free variables.
    """
    children = list(node.children())
    if not children:
        if isinstance(node, JsIdentifier):
            return node.name in allowed_names
        return is_simple_expression(node)
    return all(is_closed_expression(child, allowed_names) for child in children)


def _chain_short_circuits(node: Node | None) -> bool:
    """
    Whether the member/call spine at *node* holds an optional link, so that evaluation can
    short-circuit past every position above it: in `a?.b[c]` the read of `c` happens only when `a`
    is not nullish, and in `f?.().x[c]` only when `f` is not.
    """
    while isinstance(node, (JsMemberExpression, JsCallExpression)):
        if node.optional:
            return True
        node = node.object if isinstance(node, JsMemberExpression) else node.callee
    return False


def _collect_unconditional_evaluation(expr: Node) -> list[str | None]:
    """
    Walk *expr* in evaluation order, descending only into children that are unconditionally
    evaluated — not short-circuit branches, not ternary arms, not a logical assignment's right
    side, and not the positions past an optional link's short-circuit. Return the identifier names
    encountered, in evaluation order,
    interleaved with `None` for every operation that can run code or raise where it applies: a call,
    a `new`, a tagged template, a member access (its getter or setter), and an operator's coercion
    of its operands. An argument substituted at a name after such a marker no longer evaluates
    before the body's operations the way it did at the call site.
    """
    events: list[str | None] = []
    stack: list[Node | None] = [expr]
    while stack:
        node = stack.pop()
        if node is None:
            events.append(None)
            continue
        if isinstance(node, JsIdentifier):
            events.append(node.name)
            continue
        if isinstance(node, (JsCallExpression, JsNewExpression, JsTaggedTemplateExpression)):
            events.append(None)
            continue
        children: list[Node | None]
        if isinstance(node, JsAssignmentExpression):
            children = [c for c in (node.left, node.right) if c is not None]
            if node.operator in ('&&=', '||=', '??='):
                children = children[:1]
            children.append(None)
        elif isinstance(node, JsBinaryExpression):
            children = [c for c in (node.left, node.right) if c is not None]
            children.append(None)
        elif isinstance(node, JsUnaryExpression):
            children = [node.operand] if node.operand is not None else []
            children.append(None)
        elif isinstance(node, JsLogicalExpression):
            children = [node.left] if node.left is not None else []
        elif isinstance(node, JsConditionalExpression):
            children = [node.test] if node.test is not None else []
        elif isinstance(node, JsSequenceExpression):
            children = list(node.expressions)
        elif isinstance(node, JsMemberExpression):
            children = [node.object] if node.object is not None else []
            if (
                node.computed
                and node.property is not None
                and not node.optional
                and not _chain_short_circuits(node.object)
            ):
                children.append(node.property)
            children.append(None)
        else:
            continue
        for child in reversed(children):
            stack.append(child)
    return events


def _param_written(expr: Node, param_names: set[str]) -> bool:
    """
    Whether any of *param_names* occurs at a write position — an assignment, compound-assignment, or
    update target — within *expr*. Such a parameter is not read-only, so substituting the call
    argument for it would place the argument at a write target: assigning to a value (`(11 = 'x')`)
    or, for an lvalue argument, mutating the caller's binding. A wrapper with a written parameter is
    therefore not a pure function of its arguments and must not be inlined by substitution.
    """
    return any(
        isinstance(node, JsIdentifier)
        and node.name in param_names
        and reference_role(node) is not Role.READ
        for node in expr.walk()
    )


class ReturnedExpression(NamedTuple):
    """
    The one expression a call to a function answers, and the names its parameters bind.
    """
    return_expression: Expression
    param_names: list[str]


def arguments_substitutable(arguments: Sequence[Node], param_names: Sequence[str]) -> bool:
    """
    Whether *arguments* stand one for one against *param_names*, so that each parameter has exactly
    one node to be replaced by.

    A spread element denotes however many values the iterable behind it holds, which is not one and
    is not a count the syntax states. Counting it as one argument binds a parameter to the spread
    itself, and substituting that into an expression writes `...xs` where a value belongs.

    A duplicate parameter name breaks the correspondence from the other side: `function (a, a)`
    reads only the last `a`, so substitution by name drops every earlier argument along with its
    evaluation, and any per-name accounting over the parameters counts two positions as one.
    """
    if len(arguments) != len(param_names):
        return False
    if len(set(param_names)) != len(param_names):
        return False
    return not any(isinstance(argument, JsSpreadElement) for argument in arguments)


def expression_a_call_answers(func: JsFunctionNode) -> ReturnedExpression | None:
    """
    The expression a call to *func* answers, where a call answers an expression at all: a body that
    is one `return` of something, parameters that are all plain names, none of them written by that
    expression, and a call that answers the value rather than a wrapper around it.

    Whether that expression may be lifted to any particular call site is a different question and the
    caller's: which names it is allowed to be closed over, and which arguments may be substituted for
    which parameter, differ per site and are not decided here.
    """
    if wraps_return(func):
        return None
    body = func.body
    if not isinstance(body, JsBlockStatement) or len(body.body) != 1:
        return None
    stmt = body.body[0]
    if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
        return None
    param_names = extract_identifier_params(func.params)
    if param_names is None:
        return None
    if _param_written(stmt.argument, set(param_names)):
        return None
    return ReturnedExpression(stmt.argument, param_names)


def names_used_under_a_nested_scope(expr: Node) -> frozenset[str]:
    """
    The identifier names read at a use position inside a function or class nested in *expr* — or
    in all of *expr*, where *expr* is itself a function or class. A substitution there does not
    evaluate the argument where the call site did: the nested body runs later, any number of times,
    so a non-literal argument would be re-read per run — a binding's later value instead of the
    one the call captured, or a fresh allocation per run where the site produced one value.
    """
    names: set[str] = set()
    for node in expr.walk():
        if isinstance(node, (
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsFunctionDeclaration,
            JsClassExpression,
            JsClassDeclaration,
        )):
            names.update(
                n.name for n in node.walk()
                if isinstance(n, JsIdentifier) and is_use_position(n)
            )
    return frozenset(names)


def _param_read_tolerates_unresolvable(expr: Node, name: str) -> bool:
    """
    Whether a use of *name* inside *expr* stands where an unresolvable reference does not throw —
    the operand of a `typeof` or `delete` (`tolerates_unresolvable`). A bare-identifier argument
    read as a value at the call site throws a `ReferenceError` when it binds nothing, but
    substituted into such a position the same spelling names nothing and yields a value, so the
    throw the call raised is muted. `is_safe_iife_inline` refuses the substitution there for a
    may-throw argument, which is exactly the throw the position would erase.
    """
    return any(
        isinstance(node, JsIdentifier)
        and node.name == name
        and is_use_position(node)
        and tolerates_unresolvable(node)
        for node in expr.walk()
    )


def is_safe_iife_inline(
    expr: Node,
    param_names: Sequence[str],
    call_args: Sequence[Node],
    call_pure: Callable[..., bool] | None = None,
    read_effect: Callable[[Node], bool] | None = None,
    call_established: Callable[..., bool] | None = None,
    arg_may_throw: Callable[[Node], bool] | None = None,
) -> bool:
    """
    Verify that substituting IIFE arguments into the body expression preserves evaluation semantics.
    An argument used more than once must be a simple, identity-stable expression — a literal or a bare
    identifier: duplicating a fresh array/object/function literal (or a call) would split one value into
    distinct copies and break an identity comparison such as `x === x`. An effectful argument must
    additionally be used exactly once, in an unconditionally-evaluated position, and in declaration
    order relative to other effectful arguments, so its side effect is neither dropped, duplicated, nor
    reordered.

    A parameter read inside a function or class nested in the body admits only a literal argument:
    the nested body runs after the call, any number of times, so any other argument would be
    re-evaluated per run — `function (a) { return () => a; }` called with `x` must answer a
    closure over the value `x` held at the call, not a live read of `x`, and called with `[1]` must
    answer the one array the site produced, not a fresh one per run.

    An effect is also ordered against everything that can observe it. Once any argument is
    effectful, every argument that is not a literal is held to the same evaluation-order discipline
    — at the call site each was evaluated once, before the body and in declaration order, and an
    identifier read moved across another argument's write reads a different value (`o.m(x, x = 5)`
    with a body of `b + a`). And every effectful argument must evaluate before the body's first own
    operation — a call, a member access, an operator's coercion — because at the call site all
    arguments ran before the body did, and a body operation is code the substitution cannot see
    across (`o.m(f, g())` with a body of `a() + b` would run `f` before `g`). When *call_pure* is
    given (an
    `refinery.lib.scripts.js.analysis.effects.EffectModel.is_pure_call`), a call argument it proves pure
    counts as side-effect-free for the ordering rules — but only when *call_established* also certifies
    its callee is in place before the call runs, and, being a call, it is not simple, so it is still not
    duplicated. When *read_effect* is given (a
    `refinery.lib.scripts.js.analysis.model.SemanticModel.read_has_dynamic_effect`), an argument reading
    a bare name through a `with` body's dynamic scope counts as effectful — the read may fire the `with`
    object's getter or throw — so it too must not be dropped or reordered.

    An argument whose evaluation may throw a `ReferenceError` no completed write establishes throws
    it when read as a value, but not when it fills a position the call's own body never reads it as
    one. Substituting such an argument is refused at exactly those two positions, which
    *arg_may_throw* (an `refinery.lib.scripts.js.analysis.effects.EffectModel.is_side_effect_free`
    with *reads_may_throw*, over the whole argument so a throw nested in an operator is seen too)
    identifies: an argument bound to a parameter the body never reads is dropped, and a bare
    identifier moved into a `typeof` or `delete` operand — where an unresolvable reference yields
    a value rather than throwing (`_param_read_tolerates_unresolvable`) — is muted.

    This refuses only those two total losses; it does not order a may-throw read against the body's
    other effects, so a used argument whose read is reordered past a body operation's side effect is
    a separate, unpinned defect
    (`test_unfixed_defects.TestARelocatedMayThrowReadIsReorderedPastAnEffect`).

    Identity stability under duplication is the *may*-allocate direction and must not be merged with
    `EffectModel._fresh_kind`, which is *must*-allocate: a fresh literal is the thing this refuses to
    duplicate and the thing that predicate admits. The two agree on the syntax and disagree on the verdict,
    which is exactly why sharing one predicate between them would be wrong.
    """
    if _param_written(expr, set(param_names)):
        return False
    use_counts = Counter(
        n.name for n in expr.walk()
        if isinstance(n, JsIdentifier) and is_use_position(n)
    )
    for i, arg in enumerate(call_args):
        if use_counts[param_names[i]] > 1 and not is_simple_expression(arg):
            return False
    deferred = names_used_under_a_nested_scope(expr)
    for i, arg in enumerate(call_args):
        if param_names[i] in deferred and not is_literal(arg):
            return False
    if arg_may_throw is not None:
        for i, arg in enumerate(call_args):
            if use_counts[param_names[i]] == 0 and arg_may_throw(arg):
                return False
            stripped = strip_parens(arg)
            if (
                isinstance(stripped, JsIdentifier)
                and arg_may_throw(stripped)
                and _param_read_tolerates_unresolvable(expr, param_names[i])
            ):
                return False
    effectful_indices = [
        i for i, arg in enumerate(call_args)
        if not side_effect_free(
            arg, call_pure=call_pure, read_effect=read_effect, call_established=call_established,
        )
    ]
    if not effectful_indices:
        return True
    effectful = set(effectful_indices)
    for i in effectful_indices:
        if use_counts[param_names[i]] != 1:
            return False
    events = _collect_unconditional_evaluation(expr)
    param_order = {name: i for i, name in enumerate(param_names)}
    exposed = {i for i, arg in enumerate(call_args) if not is_literal(arg)}
    order: list[int] = []
    first_operation: int | None = None
    for event in events:
        if event is None:
            if first_operation is None:
                first_operation = len(order)
            continue
        index = param_order.get(event)
        if index is not None and index in exposed:
            order.append(index)
    for i in exposed:
        expected = 1 if i in effectful else use_counts[param_names[i]]
        if sum(1 for k in order if k == i) != expected:
            return False
    for p, i in enumerate(order):
        if i in effectful and first_operation is not None and p >= first_operation:
            return False
        for q, j in enumerate(order):
            if j in effectful and i != j and (i < j) != (p < q):
                return False
    return True


def substitute_params(
    expression: Node,
    params: Sequence[Node],
    arguments: Sequence[Node],
    transformer: Transformer | None = None,
) -> Node:
    """
    Deep-clone *expression* and replace every reference to one of the function parameters *params* with
    a clone of the positionally corresponding node from *arguments*. Only identifiers the parameter
    actually binds are replaced: a non-computed property key (the `a` in `b.a`) names a property, and a
    function or class nested in *expression* that reintroduces a parameter's name keeps its own
    identifiers rather than the outer parameter's. When *expression* nests no scope, no name under it
    can be rebound, so a parameter's references are exactly the use-position identifiers carrying its
    name and are substituted directly; only when it does nest a scope is a semantic model built to
    resolve each occurrence against the binding it reads. When *transformer* is given, that model is
    taken from its shared analysis cache; otherwise it is built standalone.
    """
    cloned = _clone_node(expression)
    mapping = {
        param.name: argument
        for param, argument in zip(params, arguments)
        if isinstance(param, JsIdentifier)
    }
    if isinstance(expression, JsIdentifier):
        if expression.name in mapping and is_use_position(expression):
            return _clone_node(mapping[expression.name])
        return cloned
    if not _introduces_nested_scope(expression):
        for node in list(cloned.walk()):
            if isinstance(node, JsIdentifier) and node.name in mapping and is_use_position(node):
                substitute_use_position(node, _clone_node(mapping[node.name]))
        return cloned
    root = expression
    while root.parent is not None:
        root = root.parent
    assert isinstance(root, JsScript)
    if transformer is None:
        model = build_semantic_model(root)
    else:
        model = model_cache(transformer, root).model
    bindings = {
        param.name: model.binding_of(param)
        for param in params
        if isinstance(param, JsIdentifier)
    }
    for original, clone in zip(list(expression.walk()), list(cloned.walk())):
        if not isinstance(original, JsIdentifier) or original.name not in mapping:
            continue
        binding = bindings.get(original.name)
        if binding is None or model.resolve(original) is not binding:
            continue
        if isinstance(clone, JsIdentifier) and clone.name == original.name:
            substitute_use_position(clone, _clone_node(mapping[original.name]))
    return cloned


def _introduces_nested_scope(node: Node) -> bool:
    """
    Whether the subtree at *node* contains a function or class — a scope in which an enclosing
    function's parameter name could be rebound. When it does not, no identifier under *node* can shadow
    such a parameter, so the parameter's references are exactly the use-position identifiers that carry
    its name.
    """
    return any(
        isinstance(child, (
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsFunctionDeclaration,
            JsClassExpression,
            JsClassDeclaration,
        ))
        for child in node.walk()
    )


def spelled_for_the_callee_position(position: Node, replacement: Node) -> Node:
    """
    The expression to write where *position* stands so that *replacement* reaches its value there
    without changing the call it lands in. Where *position* is a call's callee (or a tagged
    template's tag) and *replacement*'s own spelling as a callee would mean something a neutral
    spelling does not — a member access binds `this` to its object, a bare `eval` runs its text in
    the caller's own scope — the value is reached behind `(0, ...)`, which invokes it with no
    receiver and no direct-eval effect, exactly as the name that stood there did. Anywhere else, and
    for any other value, *replacement* is written as it is.

    Every pass that drops a value into a slot another node occupied shares this, so a member or a
    bare `eval` cannot become a receiver-bound or direct call at one substitution site while being
    neutralized at another.
    """
    if is_invocation_target(position) and callee_form_sensitive(replacement):
        assert isinstance(replacement, Expression)
        return JsSequenceExpression(expressions=[
            JsNumericLiteral(value=0, raw='0'),
            replacement,
        ])
    return replacement


def substitute_use_position(node: JsIdentifier, replacement: Node, *, as_spelled: bool = False) -> bool:
    """
    Put *replacement* where *node* reads a binding, and report whether it did. That *node* reads one
    is the caller's to establish, and it takes a model: a name bound by a destructuring pattern is
    written exactly like a read, so `SemanticModel.is_reference` answers it and the syntactic
    `is_reference` only approximates it, in the permissive direction.

    A name the program cannot refer to is not such a read and is left alone. `is_use_position` says
    which positions those are — the four that spell a property, and the label, the import specifier
    halves, the re-export name and the name an export list exports under besides — and substituting
    into one of them is not a rename but a different program: a replacement with no identifier
    spelling leaves text no engine parses (`o.5`, `{ -2: 1 }`), and a numeral put where a label
    stood leaves `5: while (0) break 5;`.

    The local half of an export list without a `from` clause is a read that predicate does record,
    and still no slot a replacement can stand in, because a list exports bindings and never values:
    `export { 1 };` is a module no engine links. It is declined here instead, which is what keeps
    the declaration the list reads alive under an inliner that substitutes every read it can.

    A shorthand property is the one position that is both at once. `{ a }` means `{ a: a }`, so the
    read is the value half and the key must keep the name it wrote; the property is written out in
    full and only the value replaced. Which half a caller hands over depends on where the tree came
    from — the parser builds one node for both and a clone builds two — so the value is asked for
    by identity rather than assumed, and a caller walking both halves substitutes once whichever
    order it visits them in. A shorthand carrying a computed key is a shape no source spells, which
    the parser builds only where it read a program no engine reads, and it is refused rather than
    written out as one of the two things it might have meant.

    `{ __proto__ }` is the one shorthand that does not mean `{ __proto__: __proto__ }`: written out
    with the colon it sets the object's prototype and gives it no property of that name at all, so
    `Object.keys({ __proto__ })` answers one name and `Object.keys({ __proto__: v })` answers none.
    Writing that one out is a different program, so it is left as it stands.

    A replacement standing where a callee stands is written behind `(0, ...)` where its own spelling
    as a callee would change the call, which `spelled_for_the_callee_position` decides and every
    substituting pass shares: the name that stood there invoked its value with no receiver and no
    direct-eval effect, whatever the value was, and the sequence spells exactly that call. That is
    the reading for a value put where a read stood. A caller that instead re-spells the reference
    itself — the flattening recovery qualifying a name to the namespaced home it was recovered
    from, whose member form is the very call being restored — passes `as_spelled=True` and takes
    the form it wrote.

    The answer is what a caller announcing a change has to read. A pass that reports one for a
    substitution this declined is a pass that reports one every round, and the fixpoint it sits in
    never reaches one. Nothing is written until the slot the replacement goes into is known, so a
    declined substitution leaves the tree exactly as it was.
    """
    parent = node.parent
    if not is_use_position(node):
        return False
    if isinstance(parent, JsExportSpecifier):
        return False
    if isinstance(parent, JsProperty) and parent.shorthand:
        if parent.computed or parent.value is not node:
            return False
        key = parent.key
        if isinstance(key, JsIdentifier) and key.name == PROTO_KEY:
            return False
        if key is node:
            set_child(parent, 'key', _clone_node(node))
        set_child(parent, 'value', replacement)
        set_value(parent, 'shorthand', False)
        return True
    if not as_spelled:
        replacement = spelled_for_the_callee_position(node, replacement)
    return _replace_in_parent(node, replacement)


def _effect_oracles(
    transformer: Transformer,
    node: Node,
) -> tuple[
    Callable[[JsCallExpression | JsNewExpression], bool] | None,
    Callable[[Node], bool] | None,
    Callable[[JsCallExpression | JsNewExpression], bool] | None,
    Callable[[Node], bool] | None,
]:
    """
    The purity, dynamic-read, establishment, and may-throw oracles `is_safe_iife_inline` sharpens
    its side-effect reading with, answering from *transformer*'s shared analysis cache over the
    script holding *node* — or four `None` when *node* stands in no script, leaving the purely
    syntactic reading. The may-throw oracle reports an argument whose evaluation may throw a
    `ReferenceError` no completed write establishes, whose throw the inliner keeps by refusing to
    drop the argument or move a bare one under a `typeof`. Each oracle reads the cache at the moment
    it is invoked rather than binding a model here: the models are built only when an argument
    actually needs one, and a caller that mutates the tree between inline attempts pays for a
    rebuild only where an oracle is consulted after the mutation.
    """
    root = tree_root(node)
    if not isinstance(root, JsScript):
        return None, None, None, None

    def call_pure(call: JsCallExpression | JsNewExpression) -> bool:
        return model_cache(transformer, root).effects.is_pure_call(call)

    def read_effect(read: Node) -> bool:
        return model_cache(transformer, root).model.read_has_dynamic_effect(read)

    def call_established(call: JsCallExpression | JsNewExpression) -> bool:
        return model_cache(transformer, root).call_established(call)

    def arg_may_throw(node: Node) -> bool:
        cache = model_cache(transformer, root)
        return not cache.effects.is_side_effect_free(
            node, reads_may_throw=True, read_established=cache.read_established)

    return call_pure, read_effect, call_established, arg_may_throw


def try_inline_trivial_function(
    func: JsFunctionExpression,
    call_args: Sequence[Node],
    *,
    transformer: Transformer,
) -> Node | None:
    """
    If *func* is a trivial wrapper (single return whose expression uses only the function's
    parameters), substitute call-site arguments into a clone of the return expression. Returns the
    inlined expression, or `None` when the function is not such a wrapper or when substituting the
    arguments would change what they do.

    Admission is `is_safe_iife_inline`, which is where the rule against dropping, duplicating,
    conditionalizing, or reordering an argument's evaluation lives; the effect oracles sharpening
    it are taken from *transformer*'s shared analysis cache, admitting a provably pure call
    argument the syntactic reading counts as effectful. The object fold and the IIFE fold both
    inline through this function. It is not the only substitution of call arguments into a body:
    the call-wrapper inliner and the evaluator's irreducible-call splice admit under their own,
    differently shaped rules.

    Which functions have a return expression to inline at all is `expression_a_call_answers`, which
    is where the refusal to inline an async function or a generator lives.
    """
    answered = expression_a_call_answers(func)
    if answered is None:
        return None
    expr, param_names = answered
    if not arguments_substitutable(call_args, param_names):
        return None
    if not is_closed_expression(expr, set(param_names)):
        return None
    call_pure, read_effect, call_established, arg_may_throw = _effect_oracles(transformer, func)
    if not is_safe_iife_inline(
        expr, param_names, call_args, call_pure, read_effect, call_established, arg_may_throw,
    ):
        return None
    return substitute_params(expr, func.params, call_args, transformer=transformer)


def walk_scope(root: Node, *, include_root_body: bool = False) -> Iterator[Node]:
    """
    Walk the AST under *root* without descending into nested function bodies. Function boundary
    nodes are yielded (so their identifiers can be inspected) but their subtrees are suppressed.
    Children are visited in source order.

    When *include_root_body* is True and *root* is itself a function, its body IS traversed (only
    inner functions are skipped). This is useful when *root* represents the scope being analyzed.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_NODES):
            if not (include_root_body and node is root):
                continue
        cc = node.children()
        stack.extend(reversed(cc))


def collect_identifier_names(node: Node) -> set[str]:
    """
    Collect the names of all `refinery.lib.scripts.js.model.JsIdentifier` nodes in the subtree
    rooted at *node*.
    """
    return {n.name for n in node.walk() if isinstance(n, JsIdentifier)}


def find_enclosing_body(node: Node) -> list[Statement] | None:
    """
    Walk up parent pointers from *node* to find the body list that directly contains it. Returns the
    `body` attribute of the nearest `refinery.lib.scripts.js.model.JsBlockStatement` or
    `refinery.lib.scripts.js.model.JsScript` ancestor whose body list includes *node* (or an
    ancestor of *node*).
    """
    child = node
    parent = node.parent
    while parent is not None:
        if isinstance(parent, (JsBlockStatement, JsScript)):
            if child in parent.body:
                return parent.body
        child = parent
        parent = parent.parent
    return None


def function_binds_name(func: Node, name: str) -> bool:
    """
    Check if a function creates a local binding for `name` (parameter, function name, or var
    declaration anywhere in its body — excluding nested functions).
    """
    if isinstance(func, JsFunctionDeclaration) and func.id is not None and func.id.name == name:
        return True
    for p in (getattr(func, 'params', None) or []):
        if isinstance(p, JsIdentifier) and p.name == name:
            return True
    body = getattr(func, 'body', None)
    if not isinstance(body, JsBlockStatement):
        return False
    stack: list[Node] = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, FUNCTION_NODES):
            continue
        if isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.VAR:
            for decl in node.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    if decl.id.name == name:
                        return True
        for child in node.children():
            stack.append(child)
    return False


def references_receiver_this(root: Node) -> bool:
    """
    Return whether relocating *root* would change the meaning of a `this` or `super` reference bound
    to its current receiver. Both are receiver-bound: `this` to the call's receiver and `super` to the
    method's home object, and `super` is a syntax error outside a method, so a value that uses either
    cannot be detached from its containing method. The receiver boundary is `walk_receiver_scope`:
    arrow functions inherit both lexically and are traversed; regular and generator functions nested
    below *root* rebind `this` (and cannot name the outer `super`) and are not descended into; a class
    rebinds `this` for its method bodies and field initializers, so only its `extends` clause and
    computed member keys are traversed. An identifier `super` that merely names a property (`x.super`)
    or an object-literal key is not a receiver-bound reference, so it is gated on `is_use_position` and
    does not count.
    """
    return any(
        isinstance(node, JsThisExpression)
        or (isinstance(node, JsIdentifier) and node.name == 'super' and is_use_position(node))
        for node in walk_receiver_scope(root)
    )


def is_receiver_binding_call(member: Node) -> bool:
    """
    Return whether *member* is evaluated in a position where the resulting call binds its object as the
    call's `this` receiver: the callee of a call `m(...)` (including an optional call `m?.(...)`) or the
    tag of a tagged template. Transparent parentheses are seen through; a comma-sequence callee
    `(0, m)()` yields a value rather than a Reference and so detaches the receiver, as does `new m()`
    (a constructor receives a fresh `this`). This is the dual of `references_receiver_this`: detaching
    *member* from its object preserves `this` unless the call site binds a receiver and the callee
    observes one.
    """
    node = member
    parent = node.parent
    while isinstance(parent, JsParenthesizedExpression):
        node, parent = parent, parent.parent
    if isinstance(parent, JsCallExpression) and parent.callee is node:
        return True
    if isinstance(parent, JsTaggedTemplateExpression) and parent.tag is node:
        return True
    return False


def rewrite_receiver_this_to_global(root: Node) -> bool:
    """
    Replace every `this` bound to *root*'s own receiver with a `globalThis` identifier, returning whether
    any replacement was made. The rewrite descends the receiver boundary `walk_receiver_scope` defines —
    through arrow functions and a class's `extends` clause and computed keys, but not into a nested
    regular or generator function, whose `this` is its own — so only *root*'s own `this` is rewritten.
    A caller uses this where *root* is invoked with no receiver, so its `this` is the global object: a
    `Function`-constructed body, or a recognized global-object finder whose `… || this` fallback yields
    the global. The synthesized `globalThis` identifiers stay subject to whatever free-name or shadow
    check the caller applies, so a binding named `globalThis` in scope declines the rewrite at the
    caller's discretion.
    """
    changed = False
    for node in list(walk_receiver_scope(root)):
        if isinstance(node, JsThisExpression):
            _replace_in_parent(node, JsIdentifier(name='globalThis'))
            changed = True
    return changed


def binding_has_references(
    model: SemanticModel,
    binding: Binding | None,
    *,
    exclude: Node | None = None,
    exclude_ids: set[int] | None = None,
) -> bool:
    """
    Whether *binding* is still read or written outside an excluded region. Resolution is
    binding-precise: only references that actually resolve to *binding* count, so a same-named
    variable in another scope never keeps it alive — this subsumes the name-based shadow check that
    `has_remaining_references` performs textually. A `None` binding (a name the model cannot resolve
    to a declaration) is conservatively reported as still referenced. References within the subtree
    of *exclude*, or whose node identity is in *exclude_ids*, are not counted.
    """
    if binding is None:
        return True
    for ref in model.references(binding, exclude=exclude):
        if exclude_ids and id(ref) in exclude_ids:
            continue
        return True
    return False


def a_host_reaches_the_binding(model: SemanticModel, binding: Binding, options: object) -> bool:
    """
    Whether *binding* is one the analyst declared a host reaches by name — a function the host
    invokes, or a global the host reads or may have rewritten — and one a host could actually reach:
    a top-level declaration under the script execution model. A pattern alone does not decide it:
    `refinery.lib.scripts.js.analysis.model.SemanticModel.reaches_global_object` is what keeps a
    pattern from protecting a nested binding, a `let`, or anything at all under the module model,
    where a top-level declaration never becomes a property of the global object.

    A pass that could delete such a declaration, fold a read of one into its value, or relocate one
    out of the global scope asks here before doing so, so that the answer is one predicate's rather
    than each pass's own. A pass whose removals only ever fall on obfuscation machinery — a string
    table, a control-flow state, an anti-debug guard, none of which an analyst names an entrypoint —
    never reaches a binding this protects, and does not consult it.
    """
    if not is_host_entrypoint(options, binding.name):
        return False
    return model.reaches_global_object(binding, module_scope=runs_as_module(options, model.root))


def nothing_still_names(model: SemanticModel, removed: Sequence[Node]) -> bool:
    """
    Whether deleting the nodes of *removed* would leave nothing naming what it takes away. A binding
    whose declarations all lie inside these nodes ceases to exist with them, so a reference to one
    from outside is a name the output would no longer declare, while a reference from within is one
    the deletion carries off and does not count. A name that is declared elsewhere as well survives
    the deletion and is not asked about.

    This is the question a pass asks before deleting the machinery it has finished reading: the calls
    it could answer are gone, and what is left decides whether the machinery may go too. Asking it of
    the model rather than of the call shapes the pass recognizes is what makes the answer cover a call
    the pass could not resolve, a name handed to something else, and an alias taken through a form the
    pass does not match. None of those is a call the pass would find, and each of them is a reference
    the model reports.

    A name inside a `with` body is asked for separately, because it resolves to no binding at all:
    the object supplies it or the binding does, and which one is a runtime question. It is counted as
    a reference here, since a removal made on the strength of it denoting the object is a removal that
    strands it whenever the object does not carry the property.
    """
    inside = {id(node) for root in removed for node in root.walk()}
    asked: set[Binding] = set()
    for root in removed:
        for node in root.walk():
            if not isinstance(node, JsIdentifier):
                continue
            binding = model.binding_of(node)
            if binding is None or binding in asked:
                continue
            asked.add(binding)
            if any(id(site) not in inside for site in binding.declarations):
                continue
            if binding_has_references(model, binding, exclude_ids=inside):
                return False
            if any(id(ref) not in inside for ref in model.dynamic_references(binding)):
                return False
    return True


class BodyProcessingTransformer(Transformer):
    """
    Intermediate base for JS deobfuscation transformers that process the statement list (body) of
    `refinery.lib.scripts.js.model.JsScript` and `refinery.lib.scripts.js.model.JsBlockStatement`
    nodes after visiting children. Subclasses override `_process_body`.
    """

    def visit_JsScript(self, node: JsScript):
        self.generic_visit(node)
        self._process_body(node, node.body)
        return None

    def visit_JsBlockStatement(self, node: JsBlockStatement):
        self.generic_visit(node)
        self._process_body(node, node.body)
        return None

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        raise NotImplementedError

    def _replace_body(self, parent: Node, replacement: list[Statement]) -> None:
        """
        Replace the body of *parent* with *replacement* through `refinery.lib.scripts.set_body`, so
        the adoption of the new statements and the advance of the tree's mutation counter happen the
        one way every splice performs them, and mark the transformer as changed.

        A Use Strict Directive the old body opened with is carried over to the head of the new one. A
        replacement drops a directive without removing anything — nothing is deleted, the statement
        simply is not among the statements handed in — so the rule that no removal may drop one has to
        be stated here as well, and stated as a repair rather than a refusal: a pass that has already
        rewritten the references it is about to install cannot be declined at this point without
        shipping a half-edited tree.
        """
        set_body(parent, keeping_directives(parent, replacement))
        self.mark_changed()


class ScopeProcessingTransformer(Transformer):
    """
    Base for transforms that process at function-scope boundaries. Visits
    `refinery.lib.scripts.js.model.JsScript` and each function body
    (`refinery.lib.scripts.js.model.JsFunctionDeclaration`,
    `refinery.lib.scripts.js.model.JsFunctionExpression`,
    `refinery.lib.scripts.js.model.JsArrowFunctionExpression`). Subclasses may override either
    `_process_scope` or `_process_scope_body`.
    """

    def visit_JsScript(self, node: JsScript):
        self.generic_visit(node)
        self._process_scope(node)
        return None

    def visit_JsFunctionDeclaration(self, node: JsFunctionDeclaration):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def visit_JsFunctionExpression(self, node: JsFunctionExpression):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def visit_JsArrowFunctionExpression(self, node: JsArrowFunctionExpression):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def _process_scope(self, scope: Node) -> None:
        body = get_body(scope)
        if body is not None:
            self._process_scope_body(scope, body)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        raise NotImplementedError


class ScriptLevelTransformer(Transformer):
    """
    Base for transforms that process the entire script manually rather than using the recursive
    visitor. Subclasses override `_process_script`.
    """

    def visit_JsScript(self, node: JsScript):
        self._process_script(node)
        return None

    def generic_visit(self, node: Node):
        pass

    def _process_script(self, node: JsScript) -> None:
        raise NotImplementedError
