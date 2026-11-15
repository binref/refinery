"""
Shared utilities for JavaScript deobfuscation transforms: the two bridges between the syntax tree
and the value domain of `refinery.lib.scripts.js.values` (`extract_literal_value`, `value_to_node`),
the own-property read on values (`read_data_property`), and the questions about a value that only
the program can answer, such as whether converting it runs code the file installed
(`coerces_uninterceptably`).
"""
from __future__ import annotations

import re
import string

from collections import Counter
from contextlib import contextmanager
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Callable,
    Collection,
    Generator,
    Generic,
    Iterable,
    Iterator,
    Mapping,
    NamedTuple,
    Sequence,
    TypeVar,
)

if TYPE_CHECKING:
    from typing import TypeAlias

    from refinery.lib.scripts.js.analysis.effects import EffectModel
    from refinery.lib.scripts.js.values import Value

    LiteralValue: TypeAlias = str | int | float | bool | list | dict | None

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
from refinery.lib.scripts.js.analysis.intrinsics import ESCAPE_WATCHED_ROOTS, PROTOTYPE_OWNERS
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    SAME_REALM_GLOBAL_OBJECT_ALIASES,
    Binding,
    Role,
    Scope,
    SemanticModel,
    enclosing_operator,
    is_invocation_target,
    is_member_write_target,
    is_use_position,
    pattern_identifiers,
    reference_role,
    tolerates_unresolvable,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.builtins import (
    CONSTRUCTORS,
    ITERATOR_METHODS,
    OBJECT_PROTOTYPE_MEMBERS,
    PROTOTYPE_CHAIN_PROPERTIES,
    PROTOTYPE_FUNCTIONS,
    PROTOTYPE_METHODS,
)
from refinery.lib.scripts.js.keys import UNHELD, key_text
from refinery.lib.scripts.js.lexer import is_identifier_name
from refinery.lib.scripts.js.model import (
    ACCESSOR_INSTALL_METHODS,
    LOGICAL_ASSIGNMENT_OPERATORS,
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsEmptyStatement,
    JsExportSpecifier,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsRegExpLiteral,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
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
    exact_integer,
    is_negative_zero,
    js_number_to_string,
    to_js_number,
)
from refinery.lib.scripts.js.strict import (
    directive_prologue,
    is_prologue_host,
    keeping_directives,
    statement_list,
)
from refinery.lib.scripts.js.synth import escape_js_string
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS
from refinery.lib.scripts.js.utf16 import SURROGATE_PAIR, code_units, from_code_units
from refinery.lib.scripts.js.values import (
    BINARY_OPS,
    COERCING_UNARY_OPERATORS,
    GLOBAL_VALUE_NAMES,
    JS_HOLE,
    JS_NULL,
    OBJECT_VALUE_TYPES,
    UNARY_OPS,
    ArrayIterator,
    BuiltinFunction,
    HostApproximated,
    JsBuffer,
    RegExpObject,
    converted_operands,
    converts_uninterceptably,
    to_boolean,
    to_string,
)

_Plan = TypeVar('_Plan')

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

UNDECLARABLE_NAMES = frozenset({
    'arguments',
    'eval',
    'NaN',
    'Infinity',
})
"""
The names beyond `JS_RESERVED` that a declaration cannot take everywhere: strict code refuses to
bind `arguments` and `eval`, and a declaration at the top of a script shares the read-only property
the global object holds for `NaN` and `Infinity`.
"""

VOID_LITERAL_OPERANDS = (JsNumericLiteral, JsStringLiteral, JsBooleanLiteral, JsNullLiteral)

FUNCTION_MEMBERS = OBJECT_PROTOTYPE_MEMBERS | PROTOTYPE_METHODS['Function'] | frozenset({
    'arguments',
    'caller',
    'length',
    'name',
    'prototype',
})
"""
The members a function object answers for before a program writes any: its own `length`, `name`
and `prototype`, the legacy `arguments` and `caller`, and what `Function.prototype` and
`Object.prototype` supply.
"""

STRING_PROTOTYPE_METHODS = PROTOTYPE_METHODS['String']

ARRAY_PROTOTYPE_METHODS = PROTOTYPE_METHODS['Array']

SEQUENCE_DATA_PROPERTIES = frozenset({'length'})
"""
The non-callable inherited properties of a string or array. `length` is the only one, which is why
it must never be reached through a method registry: `'abc'.length` is the number `3` and
`'abc'.length()` is a `TypeError`, whereas a registry entry would answer `3` to both.
"""


def _holes_present(values: list) -> bool:
    """
    Whether *values* holds at least one hole. The arms of the value domain that visit a list's
    elements decide per method whether a hole is skipped (`forEach`, `filter`), read as
    `undefined` (`find`, for-of, `includes`), or preserved in a result (`map`); this is the one
    test they would otherwise each spell out for itself.
    """
    return any(value is JS_HOLE for value in values)


PROTO_KEY = '__proto__'
"""
The one property key whose plain spelling in an object literal does not denote an own property.
`{__proto__: v}` and `{'__proto__': v}` install `v` as the prototype and leave the object with no own
property at all, whereas `{['__proto__']: v}` — and `JSON.parse` — create an ordinary own property of
that name. A runtime object modelled as a Python dict holds only own data properties, so a
`__proto__` entry in such a dict can only have come from one of the latter two, and may only be
rendered back as the computed form.
"""


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
    `EffectModel.read_chain_intact` answers. A function is an object the program holds, and it may
    have given the function a conversion of its own, which
    `refinery.lib.scripts.js.analysis.effects.EffectModel.function_conversion_untouched` rules out.
    An array converts element-wise, so each element has to answer this question too, and an array
    that holds itself is refused (`_converts_without_installed_code`).

    A caller with no effect model gets `False` for every object: the interpreter used on one
    expression in isolation cannot see the file the expression came from, and whether anything
    replaced a conversion is a question about that file.
    """
    return _converts_without_installed_code(
        effects,
        value,
        lambda model, value_type: model.read_chain_intact(value_type),
    )


def coerces_uninterceptably_from_written_chain(effects: EffectModel | None, value: Value) -> bool:
    """
    `coerces_uninterceptably` for a caller the tampering oracle has cleared at an anchor: the
    chain is asked `EffectModel.chain_roots_unwritten` — the same half
    `property_absent_from_written_chain` takes — so an anchored execution converts a value where
    the reflection term is what the oracle's clearance replaced. A caller that has not asked the
    oracle takes `coerces_uninterceptably` itself.
    """
    return _converts_without_installed_code(
        effects,
        value,
        lambda model, value_type: model.chain_roots_unwritten(value_type),
    )


def _converts_without_installed_code(
    effects: EffectModel | None,
    value: Value,
    chain_untouched: Callable[[EffectModel, type], bool],
) -> bool:
    """
    The walk `coerces_uninterceptably` and `coerces_uninterceptably_from_written_chain` share, which
    differ only in what *chain_untouched* asks of the prototype chain of each object's type. An
    array converts element-wise, so its elements answer in turn. An array that holds itself at any
    depth is refused: asking its elements would never end, and what converting it gives is the
    engine's cycle handling rather than anything the language says. An array reached along two
    paths is asked once.
    """
    cleared: set[int] = set()
    entered: set[int] = set()

    def answers(item: Value) -> bool:
        if converts_uninterceptably(item):
            return True
        if isinstance(item, ArrayIterator):
            return effects is not None and effects.array_iterator_conversion_untouched()
        if isinstance(item, RegExpObject):
            return False
        if isinstance(item, dict):
            if any(name in item for name in _TO_PRIMITIVE_METHODS):
                return False
        elif not isinstance(item, OBJECT_VALUE_TYPES):
            return False
        if effects is None or not chain_untouched(effects, type(item)):
            return False
        if isinstance(item, FUNCTION_NODES) and not effects.function_conversion_untouched(item):
            return False
        if not isinstance(item, list):
            return True
        key = id(item)
        if key in cleared:
            return True
        if key in entered:
            return False
        entered.add(key)
        if not all(answers(element) for element in item):
            return False
        cleared.add(key)
        return True

    return answers(value)


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
    `SAME_REALM_GLOBAL_OBJECT_ALIASES` and the bare name reaches what the host supplies under it
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.bare_name_reaches_the_host`): nothing
    binds it where it stands, and no `with` object or direct `eval` can supply it at runtime. Both
    halves are needed by every pass that acts on a property written through such a spelling, because
    a declaration of the name binds it and the access then reads an ordinary object the program may
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
    return model.bare_name_reaches_the_host(base.name, base)


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


def folded_literal(result: object) -> Expression | None:
    """
    The literal a fold writes in place of what computed *result*, or `None` where none may be
    written: no literal denotes it faithfully (`value_to_node`), or it is a list longer than
    `MAX_RESULT_ARRAY_LEN`. Every fold that writes a computed value into the text asks here, so the
    guard on what the text may receive is present at each of them. A value refused here may still
    answer a read, the guard being about the text:
    `refinery.lib.scripts.js.deobfuscation.admission.CallAdmission.binding_constant` reads it.
    """
    if isinstance(result, list) and len(result) > MAX_RESULT_ARRAY_LEN:
        return None
    return value_to_node(result)


def replace_with_value(node: Node, result: object) -> bool:
    """
    Replace *node* with the literal a fold may write for *result* (`folded_literal`), refusing where
    there is none. Announcing the change is the caller's — it owns `mark_changed`.
    """
    replacement = folded_literal(result)
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
    """
    Whether a declaration may bind *name* wherever it stands: an IdentifierName
    (`refinery.lib.scripts.js.lexer.is_identifier_name`) that is no keyword and no future reserved
    word (`JS_RESERVED`), and none of the names a declaration cannot take everywhere
    (`UNDECLARABLE_NAMES`).
    """
    return is_identifier_name(name) and name not in JS_RESERVED and name not in UNDECLARABLE_NAMES


def fresh_name(base: str, taken: Callable[[str], bool]) -> str:
    """
    The first of *base*, `base_1`, `base_2` and so on for which *taken* is false.
    """
    candidate = base
    suffix = 0
    while taken(candidate):
        suffix += 1
        candidate = F'{base}_{suffix}'
    return candidate


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


def integer_literal(node: Node | None) -> int | None:
    """
    The value of the numeric literal *node* when it is a finite integer.
    """
    node = strip_parens(node)
    return exact_integer(node.value) if isinstance(node, JsNumericLiteral) else None


def names_global_value(node: JsIdentifier, model: SemanticModel) -> bool:
    """
    Whether *node* is one of `GLOBAL_VALUE_NAMES` still denoting its value. Every reader of those
    names has to come through here.
    """
    return node.name in GLOBAL_VALUE_NAMES and name_is_unbound(node, model)


def denoted_value(
    node: Node | None,
    model: SemanticModel,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel] | None = None,
    undecided: set[Node] | None = None,
) -> tuple[bool, Value]:
    """
    The value *node* denotes, as `(True, value)`, or `(False, None)` when nothing decides it. This is
    `extract_literal_value` widened by the two things a literal cannot express: a name that still
    denotes one of the global values, and an operator standing in front of either.

    An operator that converts its operand converts an array by running a method the program can
    replace, so `+[]` denotes `0` only where *uninterceptable* vouches that converting the array
    runs no code the program installed: `coerces_uninterceptably` against an effect model, or
    `refinery.lib.scripts.js.values.converts_uninterceptably` for a caller without one, which
    vouches for no object at all. It is asked only of a value an operator converts, so a caller
    whose effect model is built on demand pays for it only there.

    A caller that hands in the *effects* of the program it rewrites has three more forms decided: a
    name still holding one of the constructors `refinery.lib.scripts.js.builtins.CONSTRUCTORS` keeps
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.trusted_intrinsic_name`), a member read
    (`denoted_member`), and a binary operator of `refinery.lib.scripts.js.values.BINARY_OPS` over
    two decided operands, each object operand it converts converted as `converted_operand` converts
    it. Only such a caller ever holds a `refinery.lib.scripts.js.values.BuiltinFunction`. The model
    is asked for on every question rather than held, so a pass renewing its models asks the renewed
    ones.

    A caller asking about the operands of one tree again and again hands in a set *undecided*, which
    remembers every node nothing decided and answers it at once the next time. Each operator of a
    chain no fold decides would otherwise ask the whole chain below it again. The answer holds while
    neither the node nor the facts the models report change, so the set is the caller's to drop.
    """
    node = strip_parens(node)
    if node is None:
        return False, None
    if undecided is None:
        return _denoted_value(node, model, uninterceptable, effects, None)
    if node in undecided:
        return False, None
    known, value = _denoted_value(node, model, uninterceptable, effects, undecided)
    if not known:
        undecided.add(node)
    return known, value


def _denoted_value(
    node: Node,
    model: SemanticModel,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel] | None,
    undecided: set[Node] | None,
) -> tuple[bool, Value]:
    """
    The value `denoted_value` answers for *node*, which no parentheses wrap.
    """
    if isinstance(node, JsIdentifier):
        if effects is not None and node.name in CONSTRUCTORS and name_is_unbound(node, model):
            if effects().trusted_intrinsic_name(node.name):
                return True, CONSTRUCTORS[node.name]
        if not names_global_value(node, model):
            return False, None
        return True, GLOBAL_VALUE_NAMES[node.name]
    if isinstance(node, JsUnaryExpression):
        apply = UNARY_OPS.get(node.operator)
        if apply is None:
            return False, None
        known, value = denoted_value(node.operand, model, uninterceptable, effects, undecided)
        if not known:
            return False, None
        if node.operator in COERCING_UNARY_OPERATORS:
            known, value = converted_operand(value, uninterceptable, effects, gated=False)
            if not known:
                return False, None
        return True, apply(value)
    if effects is not None:
        if isinstance(node, JsMemberExpression) and not is_member_write_target(node):
            return denoted_member(node, model, uninterceptable, effects, undecided)
        if isinstance(node, JsBinaryExpression) and node.operator in BINARY_OPS:
            return _denoted_binary(node, model, uninterceptable, effects, undecided)
        if isinstance(node, (JsCallExpression, JsNewExpression)):
            return _denoted_construction(node, model, uninterceptable, effects, undecided)
        if isinstance(node, JsRegExpLiteral):
            if node.flags or not node.terminated or not is_plain_pattern(node.pattern):
                return False, None
            return True, RegExpObject(node.pattern)
    return extract_literal_value(node)


PLAIN_PATTERN_CHARACTERS = frozenset(F'{string.ascii_letters}{string.digits} !"#%&\',-:;<=>@_`~')
"""
The characters a regular expression pattern holds that stand for themselves wherever they appear:
the letters, the digits, and the printable ASCII characters with no meaning in a pattern. The
characters of a group, a class, a quantifier or an escape are left out, and so is the slash, which
ends a literal.
"""


def is_plain_pattern(pattern: str, *, slash: bool = False) -> bool:
    """
    Whether *pattern* holds only `PLAIN_PATTERN_CHARACTERS`, and slashes where *slash* allows them,
    so that the regular expression it builds matches exactly that text and its source is that text
    with every slash escaped.
    """
    return all(c in PLAIN_PATTERN_CHARACTERS or slash and c == '/' for c in pattern)


_ITERATOR_FUNCTIONS = frozenset(PROTOTYPE_FUNCTIONS['Array', method] for method in ITERATOR_METHODS)


def _denoted_construction(
    node: JsCallExpression | JsNewExpression,
    model: SemanticModel,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel],
    undecided: set[Node] | None,
) -> tuple[bool, Value]:
    """
    The object a call or a construction builds where the language alone decides it, for
    `denoted_value`: an array iterator (`refinery.lib.scripts.js.values.ArrayIterator`), which
    `entries`, `keys` or `values` called without arguments on a decided array returns where the
    host has that method, and a regular expression (`refinery.lib.scripts.js.values.RegExpObject`),
    which `RegExp` called or constructed without arguments, or with a decided string of
    `PLAIN_PATTERN_CHARACTERS` and slashes, builds. Neither runs code the program installed, and
    each evaluation builds a new object.
    """
    if isinstance(node, JsCallExpression) and node.optional:
        return False, None
    callee = strip_parens(node.callee)
    known, function = denoted_value(callee, model, uninterceptable, effects, undecided)
    if not known or not isinstance(function, BuiltinFunction):
        return False, None
    arguments = node.arguments
    if function is CONSTRUCTORS['RegExp']:
        if not arguments:
            return True, RegExpObject('')
        if len(arguments) != 1:
            return False, None
        known, pattern = denoted_value(arguments[0], model, uninterceptable, effects, undecided)
        if not known or not isinstance(pattern, str) or not is_plain_pattern(pattern, slash=True):
            return False, None
        return True, RegExpObject(pattern)
    if function not in _ITERATOR_FUNCTIONS or arguments or isinstance(node, JsNewExpression):
        return False, None
    if not isinstance(callee, JsMemberExpression):
        return False, None
    known, receiver = denoted_value(callee.object, model, uninterceptable, effects, undecided)
    if not known or type(receiver) is not list:
        return False, None
    if not effects().model.environment.has_function('Array', function.name):
        return False, None
    return True, ArrayIterator()


def _denoted_binary(
    node: JsBinaryExpression,
    model: SemanticModel,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel],
    undecided: set[Node] | None,
) -> tuple[bool, Value]:
    """
    The value the binary operator *node* computes from its two decided operands, for
    `denoted_value`. Each operand the operator converts
    (`refinery.lib.scripts.js.values.converted_operands`) is converted as `converted_operand`
    converts it first. A power whose value the language leaves to the engine is not decided.
    """
    known, left = denoted_value(node.left, model, uninterceptable, effects, undecided)
    if not known:
        return False, None
    known, right = denoted_value(node.right, model, uninterceptable, effects, undecided)
    if not known:
        return False, None
    convert_left, convert_right = converted_operands(node.operator, left, right)
    if convert_left:
        known, left = converted_operand(left, uninterceptable, effects, gated=True)
        if not known:
            return False, None
    if convert_right:
        known, right = converted_operand(right, uninterceptable, effects, gated=True)
        if not known:
            return False, None
    try:
        return True, BINARY_OPS[node.operator](left, right)
    except HostApproximated:
        return False, None


def converted_operand(
    value: Value,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel] | None,
    gated: bool,
) -> tuple[bool, Value]:
    """
    *value* as an operator or a computed key converts it, as `(True, value)`, or `(False, None)`
    where converting it may run code the program installed. A primitive converts by an operation no
    program replaces. A function the language installs converts to the text the host writes for it
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.builtin_function_text`). Any other
    object converts where *uninterceptable* vouches for its conversion and, where *gated*, where
    the scan follows every write the program makes on a built-in object
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.builtin_writes_followed`), which a
    binary operator and a key ask; a unary operator asks *uninterceptable* alone.
    """
    if isinstance(value, BuiltinFunction):
        text = None if effects is None else effects().builtin_function_text(value)
        return (False, None) if text is None else (True, text)
    if isinstance(value, RegExpObject):
        text = None if effects is None else effects().regexp_text(value)
        return (False, None) if text is None else (True, text)
    if converts_uninterceptably(value):
        return True, value
    if gated and (effects is None or not effects().builtin_writes_followed()):
        return False, None
    if not uninterceptable(value):
        return False, None
    return True, value


def denoted_member(
    node: JsMemberExpression,
    model: SemanticModel,
    uninterceptable: Callable[[Value], bool],
    effects: Callable[[], EffectModel],
    undecided: set[Node] | None = None,
) -> tuple[bool, Value]:
    """
    The value the member read *node* yields off a decided object under a decided key, for
    `denoted_value`, whose *undecided* this shares: an own data property of the object
    (`read_data_property`), and otherwise what its prototype chain answers (`inherited_member`).
    Naming the property converts a computed key as an operator converts an operand
    (`converted_operand`). A read off `null` or `undefined` throws and is not decided.
    """
    if node.computed:
        known, key = denoted_value(node.property, model, uninterceptable, effects, undecided)
        if not known:
            return False, None
        known, key = converted_operand(key, uninterceptable, effects, gated=True)
        if not known:
            return False, None
        name = to_string(key)
    elif isinstance(node.property, JsIdentifier):
        name = node.property.name
    else:
        return False, None
    known, obj = denoted_value(node.object, model, uninterceptable, effects, undecided)
    if not known or obj is None or obj is JS_NULL:
        return False, None
    outcome, value = read_data_property(obj, name)
    if outcome is MemberRead.FOUND:
        return True, value
    return inherited_member(obj, name, effects())


def inherited_member(value: Value, key: str, effects: EffectModel) -> tuple[bool, Value]:
    """
    What the prototype chain of *value*, which does not own *key*, answers for a read of it, as
    `(True, value)`, or `(False, None)` where nothing decides it. Every answer needs the scan to
    follow every write the program makes on a built-in object
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.builtin_writes_followed`): the chain
    questions ask about names, and `[].constructor.prototype.x = 1` writes the chain of every array
    through none.

    On an intact chain (`refinery.lib.scripts.js.analysis.effects.EffectModel.read_chain_intact`),
    `constructor` is the constructor owning the prototype of the value's type. Where
    `refinery.lib.scripts.js.builtins.PROTOTYPE_METHODS` lists the methods of that prototype, a
    method key is the function that prototype, or `Object.prototype` behind it, holds
    (`refinery.lib.scripts.js.builtins.PROTOTYPE_FUNCTIONS`), where the host has it
    (`refinery.lib.scripts.js.analysis.environment.HostEnvironment.has_function`). A key no
    prototype of the chain holds is `undefined` (`property_provably_absent`). A function the
    language installs answers only for the keys `_builtin_function_member` reads.
    """
    if not effects.builtin_writes_followed():
        return False, None
    if isinstance(value, BuiltinFunction):
        return _builtin_function_member(value, key, effects)
    owner = PROTOTYPE_OWNERS.get(type(value).__name__)
    if owner in CONSTRUCTORS and effects.read_chain_intact(type(value)):
        if key == 'constructor':
            return True, CONSTRUCTORS[owner]
        if owner not in PROTOTYPE_METHODS:
            return False, None
        environment = effects.model.environment
        for holder in (owner, 'Object'):
            method = PROTOTYPE_FUNCTIONS.get((holder, key))
            if method is not None:
                return (True, method) if environment.has_function(holder, key) else (False, None)
    if property_provably_absent(effects, type(value), key):
        return True, None
    return False, None


def _builtin_function_member(function: BuiltinFunction, key: str, effects: EffectModel) -> tuple[bool, Value]:
    """
    What a read of *key* off the built-in *function* answers, for `inherited_member`: the `name` the
    function owns (`refinery.lib.scripts.js.analysis.effects.EffectModel.builtin_function_named`),
    the `Function` its `constructor` reaches
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.builtin_function_constructor_untouched`),
    and a method of `Function.prototype` on an intact chain. Any other key is not decided.
    """
    if key == 'name':
        if not effects.builtin_function_named(function):
            return False, None
        return True, function.name
    if key == 'constructor':
        if not effects.builtin_function_constructor_untouched(function):
            return False, None
        return True, CONSTRUCTORS['Function']
    method = PROTOTYPE_FUNCTIONS.get(('Function', key))
    if method is None or not effects.read_chain_intact(JsFunctionExpression):
        return False, None
    return True, method


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
    known, value = denoted_value(
        operand,
        model,
        lambda converted: coerces_uninterceptably(cache.effects, converted),
    )
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
    The allocation *binding* provably holds at the read *node*, when its single value is in place
    before that read
    (`refinery.lib.scripts.js.analysis.dominance.DominanceModel.binding_established_before`); `None`
    when the binding holds no single value, the read may precede the value, or the value is no
    allocation. The value and its establishment sites come from the same complete-singleton answer,
    which no dynamic rebind the text does not spell satisfies under the suspecting model; the
    ordering is the interprocedural one, which recurses through the reference points of the function
    the read sits in, so a guard carried by a callback is ordered through the callback's creation.
    """
    value = cache.model.singular_value(binding)
    if value is None or allocated_object_type(value) is None:
        return None
    if not cache.dominance.binding_established_before(binding, node):
        return None
    return value


def is_nullish(node: Node, model: SemanticModel, uninterceptable: Callable[[Value], bool]) -> bool | None:
    """
    Whether *node* denotes `null` or `undefined` — the two values `??` treats as absent — or `None`
    when the value it denotes is not decided. A caller has to tell that third answer from `False`:
    `a ?? b` keeps `a` when `a` is known not to be nullish, and must be left alone when nothing is
    known about it at all.
    """
    known, value = denoted_value(node, model, uninterceptable)
    if not known:
        return None
    return value is None or value is JS_NULL


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


def body_completes_empty(statements: list[Statement]) -> bool:
    """
    Whether a statement list run to its end supplies no completion value, so an `eval` of it hands
    back `undefined`. The completion of a list is the value of its last statement that answers the
    completion; a list where none does — every statement a declaration, an empty statement, or a
    construct whose run may skip the value it guards — completes empty. This is the value a script or
    a direct `eval` yields, distinct from what a constructed function returns, which is `undefined`
    unless the body ends in a `return x` (`body_returns_undefined`).
    """
    return not any(definitely_answers_the_completion(stmt) for stmt in statements)


def reaches_script_completion(stmt: Node, root: JsScript) -> bool:
    """
    Whether *stmt* can supply *root*'s top-level completion value — the value an `eval` of the whole
    script receives. Climbing from *stmt* to the script, at each statement-list ancestor a later
    sibling that certainly answers the completion (`definitely_answers_the_completion`) shadows
    everything before it, so *stmt*'s value can never reach the end and the answer is `False`. A
    conditional or iterative ancestor is passed through: its branch may or may not run, so a statement
    it guards is conservatively still able to reach the completion. A function boundary is the end of
    the walk: a statement inside a function supplies that function's return, not the script's, so a
    body reached through a function node never reaches the script completion. Only a *reachable* later
    sibling can shadow: the scan for one stops at a `break` or `continue`, which ends the block's
    straight-line run so nothing behind it executes — the value the abrupt exit carries out to the
    loop it targets is the one standing when it runs, which the climb then follows into that loop.
    This is the position every pass that would drop or rewrite a completion-supplying statement must
    spare under `preserve_script_return`.
    """
    node: Node = stmt
    while node is not root:
        parent = node.parent
        if parent is None or isinstance(parent, JsFunctionNode):
            return False
        body = get_body(parent)
        if body is not None:
            index = next((k for k, s in enumerate(body) if s is node), None)
            if index is not None:
                for later in body[index + 1:]:
                    if definitely_answers_the_completion(later):
                        return False
                    if isinstance(later, (JsBreakStatement, JsContinueStatement)):
                        break
        node = parent
    return True


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
    reaches_completion: bool,
) -> list[Statement]:
    """
    Adapt an inlined body so that, where it replaces a call whose value reached the script's
    completion, the script still hands back the value the call did. A call whose function ran off its
    end returned `undefined`, but the inlined body may leave a value of its own in the completion
    position the call did not hold, so a `void 0` is appended to hold the completion at `undefined`.
    The append is unconditional under the gate: the completion of a statement list is its last
    *non-empty* completion, which a tail that itself completes empty (a declaration, a `break`) does
    not supply — it is supplied by an earlier statement — so testing only the last statement would
    miss the leak. A redundant `void 0` after a tail that already completes to `undefined` is inert.
    Nothing is appended where the call's value never reached the completion (it was already discarded)
    or where the function returned a value the splice already carries (a trailing `return x` became
    the tail expression, so *returns_undefined* is False).
    """
    if not (reaches_completion and returns_undefined):
        return statements
    return [*statements, JsExpressionStatement(expression=make_undefined_expression())]


def seed_script_end_value(
    statements: list[Statement],
    *,
    reaches_completion: bool,
) -> list[Statement]:
    """
    Adapt an inlined `eval` body so that, where it replaces an `eval` whose value reached the script's
    completion, the script still hands back the value the `eval` did. A direct or indirect `eval`
    returns its own code's completion — a value the code answers with, or `undefined` where the code
    completes empty. The inlined body reproduces that value on its own wherever the body answers the
    completion; where it completes empty (`body_completes_empty`) the completion is instead the value
    of an earlier statement standing before the splice, which the `eval` had washed away to
    `undefined`. A `void 0` prepended ahead of such a body seeds the completion at `undefined`, so an
    empty run yields `undefined` while a value the body does supply at run time — from a branch or a
    loop no static test could prove would answer — still overrides the seed through the language's
    completion rule. This holds the `eval` in both outcomes, unlike a `void 0` appended, which would
    force `undefined` even over a value the body answers with. The seed is placed only where the body
    answers no completion, so no Directive Prologue that a statement ahead of it could end is ever
    present at its head.
    """
    if not (reaches_completion and body_completes_empty(statements)):
        return statements
    return [JsExpressionStatement(expression=make_undefined_expression()), *statements]


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
    `refinery.lib.scripts.js.model.JsVariableDeclaration`. A declaration left with no declarator is
    removed as well: from the statement list that holds it, as the initializer of a `for` loop, and
    by an empty statement where it stands as the one statement of another, such as the body of a
    label or of an `if`. The one declarator of a `for-in` or `for-of` head stays where it is, since
    that head cannot do without it.
    """
    var_decl = declarator.parent
    if (
        isinstance(var_decl, JsVariableDeclaration)
        and len(var_decl.declarations) == 1
        and isinstance(var_decl.parent, (JsForInStatement, JsForOfStatement))
    ):
        return
    _remove_from_parent(declarator)
    if not isinstance(var_decl, JsVariableDeclaration) or var_decl.declarations:
        return
    if _remove_from_parent(var_decl):
        return
    holder = var_decl.parent
    if isinstance(holder, JsForStatement) and holder.init is var_decl:
        set_child(holder, 'init', None)
    elif holder is not None:
        _replace_in_parent(var_decl, JsEmptyStatement())


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
    renamed: Mapping[Binding, str],
) -> bool:
    """
    Whether the names a spliced body declares at its own top level — the bindings of
    *declared_scope*, each under the name *renamed* gives it, if any — can be introduced at the
    site it is spliced into without capturing an identifier already meaningful there. Such
    declarations are local to the body's own function; inlining lifts `var` and function
    declarations into the caller's function or script scope and `let`/`const`/`class` into the
    caller's immediate block, where a same-named reference, an inherited binding, or a
    redeclaration would silently rebind to the inlined declaration or produce a duplicate lexical
    declaration. Each name is checked against the scope it would actually land in.

    *exclude* names the bindings the same edit deletes elsewhere: a use resolving to one is
    carried off by the deletion rather than captured, so the introduced declaration may share its
    name. A declaration lands only where it may
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.declaration_may_land`), which no name a
    CommonJS host binds around the file does at its top.
    """
    bindings = declared_scope.bindings
    hoisted = {
        renamed.get(binding, name) for name, binding in bindings.items() if binding.is_hoisted
    }
    lexical = {
        renamed.get(binding, name) for name, binding in bindings.items() if binding.is_lexical
    }
    if hoisted:
        var_scope = site_scope.var_scope
        if var_scope is None:
            return False
        if not root_model.declaration_may_land(hoisted, var_scope, exclude=exclude):
            return False
        if not hoist_path_is_clear(hoisted, site_scope, var_scope, exclude=exclude):
            return False
    return not lexical or root_model.declaration_may_land(lexical, site_scope, exclude=exclude)


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
            if node.operator in LOGICAL_ASSIGNMENT_OPERATORS:
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
            arg,
            call_pure=call_pure,
            read_effect=read_effect,
            call_established=call_established,
            assumptions=UNHELD,
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
    transformer: Transformer,
) -> Node:
    """
    Deep-clone *expression* and replace every reference to one of the function parameters *params* with
    a clone of the positionally corresponding node from *arguments*. Only identifiers the parameter
    actually binds are replaced: a non-computed property key (the `a` in `b.a`) names a property, and a
    function or class nested in *expression* that reintroduces a parameter's name keeps its own
    identifiers rather than the outer parameter's. When *expression* nests no scope, no name under it
    can be rebound, so a parameter's references are exactly the use-position identifiers carrying its
    name and are substituted directly; only when it does nest a scope is a semantic model built to
    resolve each occurrence against the binding it reads, taken from the shared analysis cache of
    *transformer*.
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
    the caller's own scope, a bare name in a `with` body binds `this` to the statement's object —
    the value is reached behind `(0, ...)`, which invokes it with no receiver and no direct-eval
    effect, exactly as the name that stood there did. Anywhere else, and for any other value,
    *replacement* is written as it is.

    Every pass that drops a value into a slot another node occupied shares this, so a member or a
    bare `eval` cannot become a receiver-bound or direct call at one substitution site while being
    neutralized at another.
    """
    if is_invocation_target(position) and callee_form_sensitive(replacement, position):
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
        if not shorthand_can_be_written_out(node):
            return False
        if parent.key is node:
            set_child(parent, 'key', _clone_node(node))
        set_child(parent, 'value', replacement)
        set_value(parent, 'shorthand', False)
        return True
    if not as_spelled:
        replacement = spelled_for_the_callee_position(node, replacement)
    return _replace_in_parent(node, replacement)


def shorthand_can_be_written_out(node: JsIdentifier) -> bool:
    """
    Whether *node* is the value of a shorthand property that can be written out in full with
    another value in its place, as `substitute_use_position` does to `{ a }`: neither is its key
    computed, a shape no source spells, nor is it `__proto__`, since `{ __proto__ }` gives the
    object a property of that name where `{ __proto__: v }` sets its prototype.
    """
    holder = node.parent
    if not isinstance(holder, JsProperty) or not holder.shorthand:
        return False
    if holder.computed or holder.value is not node:
        return False
    key = holder.key
    return not isinstance(key, JsIdentifier) or key.name != PROTO_KEY


def spelled_by_a_shorthand(name: JsIdentifier) -> bool:
    """
    Whether the binding identifier *name* is written by a shorthand property of a pattern, alone or
    with a default, as in `{ a }` or `{ a = 1 }`: the identifier is also the key the pattern reads,
    so a binding of another name has to read the same key.
    """
    holder = name.parent
    if isinstance(holder, JsAssignmentPattern) and holder.left is name:
        holder = holder.parent
    return isinstance(holder, JsProperty) and holder.shorthand


def binding_renamable(binding: Binding, model: SemanticModel) -> bool:
    """
    Whether *binding*, a binding of *model*, can take another name by respelling the identifiers
    the model records for it (`rename_binding`), with nothing that tells the two names apart.

    No code names it at run time from its own scope, as a direct `eval` or a `with` body would go
    on naming the old one
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_can_reach_from_its_scope`),
    and no body the program hands the global object to reaches it
    (`refinery.lib.scripts.js.analysis.model.Binding.reachable_through_a_handed_object`), where the
    model records the object handed over as one of its references. No Annex B copy ties it to a
    binding of another scope, and no function declared in a block of its scope bears its name:
    the binding blocks the copy Annex B makes of that function, which is made once the two names
    differ. Every declaration of it stores into it, where one in a `catch` clause binding the same
    name stores into the parameter and one in a `with` body may store into the object.

    Every reference is an identifier spelling its name where it reads or writes it, one no export
    list names and the key of no shorthand property (`spelled_by_a_shorthand`) but one a rename
    can write out in full (`shorthand_can_be_written_out`): `{ a }` and `({ a } = o)` become
    `{ a: b }` and `({ a: b } = o)`, while `({ a = 1 } = o)`, `{ __proto__ }` and a declaration
    `var { a } = o` are refused.
    """
    if (
        binding.copies_made
        or binding.copies_received
        or binding.reachable_through_a_handed_object
        or model.reflection_can_reach_from_its_scope(binding)
    ):
        return False
    for declaration in binding.declarations:
        if spelled_by_a_shorthand(declaration):
            return False
        if model.lookup(binding.name, model.scope_of(declaration)) is not binding:
            return False
    for reference in (*binding.reads, *binding.writes, *binding.indefinite_writes):
        if (
            not isinstance(reference, JsIdentifier)
            or reference.name != binding.name
            or not is_use_position(reference)
            or isinstance(reference.parent, JsExportSpecifier)
        ):
            return False
        if spelled_by_a_shorthand(reference) and not shorthand_can_be_written_out(reference):
            return False
    return not any(
        isinstance(node, JsFunctionDeclaration)
        and node.id is not None
        and node.id.name == binding.name
        and node.id not in binding.declarations
        for node in walk_scope(binding.scope.node, include_root_body=True)
    )


def rename_binding(binding: Binding, name: str) -> None:
    """
    Give *binding*, which `binding_renamable` admits, the name *name*: every identifier declaring
    it and every reference to it is respelled, and a shorthand property `{ a }` reading it is
    written out in full, `{ a: name }`, so that its key stays.
    """
    for declaration in binding.declarations:
        set_value(declaration, 'name', name)
    respelled: set[int] = set()
    for reference in (*binding.reads, *binding.writes, *binding.indefinite_writes):
        if id(reference) in respelled:
            continue
        respelled.add(id(reference))
        assert isinstance(reference, JsIdentifier)
        parent = reference.parent
        if isinstance(parent, JsProperty) and parent.shorthand:
            spelled = JsIdentifier(name=name, offset=reference.offset)
            written_out = substitute_use_position(reference, spelled)
            assert written_out
        else:
            set_value(reference, 'name', name)


def name_off_the_host(
    base: str,
    scope: Scope,
    model: SemanticModel,
    taken: Callable[[str], bool],
) -> str | None:
    """
    The name a declaration of *base* takes in *scope*, a scope of *model*: *base* itself where
    *taken* leaves it free and a declaration of it there is no property of the global object a
    host reads (`refinery.lib.scripts.js.analysis.model.SemanticModel.lands_on_the_host`), and
    otherwise the first suffix `fresh_name` finds that *taken* leaves free, or `None` where a host
    reads that one as well. No host environment reads a name with a suffix, but a pattern the
    analyst names entry points by holds for every suffix of a name it holds for, as `*` and `On*`
    do, so the host is asked about the one suffix the search settles on: asked of every suffix,
    the search would never end.
    """
    if not taken(base) and not model.lands_on_the_host(base, scope):
        return base
    name = fresh_name(base, lambda candidate: candidate == base or taken(candidate))
    if model.lands_on_the_host(name, scope):
        return None
    return name


def host_landing_names(
    bindings: Iterable[Binding],
    landing: Callable[[Binding], Scope | None],
    model: SemanticModel,
    text: Iterable[Node],
    declared_by: SemanticModel,
) -> dict[Binding, str] | None:
    """
    A new name for each of *bindings*, which *declared_by* holds, whose declaration would be a
    property of the global object a host reads
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.lands_on_the_host`) once moved into the
    scope of *model* that *landing* gives it, or `None` where one of them cannot take another name
    (`binding_renamable`) or finds none (`name_off_the_host`). The declaration that bound a name of
    its own scope keeps doing so under the new name, where the old one would store into what the
    host reads: a `var location` lifted out of a function body would navigate the window. No
    identifier of the trees in *text* spells a new name, nor does another binding here take it;
    the trees are read only once a binding needs one.
    """
    chosen: dict[Binding, str] = {}
    spelled: set[str] | None = None
    for binding in bindings:
        scope = landing(binding)
        if scope is None or not model.lands_on_the_host(binding.name, scope):
            continue
        if not binding_renamable(binding, declared_by):
            return None
        if spelled is None:
            spelled = set()
            for tree in text:
                spelled |= collect_identifier_names(tree)
        name = name_off_the_host(binding.name, scope, model, spelled.__contains__)
        if name is None:
            return None
        spelled.add(name)
        chosen[binding] = name
    return chosen


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
    Children are visited in source order. The walk is textual: it enters the initializer of a class
    field, which runs at each construction rather than where it is written; the nodes one run
    evaluates are those `refinery.lib.scripts.js.analysis.evaluation.walk_run` yields.

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


def receiver_this_expressions(root: Node) -> list[JsThisExpression]:
    """
    Every `this` bound to *root*'s own receiver, found along the receiver boundary
    `walk_receiver_scope` defines — through arrow functions and a class's `extends` clause and
    computed keys, but not into a nested regular or generator function, whose `this` is its own.
    """
    return [node for node in walk_receiver_scope(root) if isinstance(node, JsThisExpression)]


def rewrite_receiver_this_to_global(root: Node) -> list[JsIdentifier]:
    """
    Replace every `this` in `receiver_this_expressions` of *root* with a `globalThis` identifier,
    returning the identifiers it synthesized. A caller uses this where *root* is invoked with no
    receiver, so its `this` is the global object, as for a `Function`-constructed body. Each landing
    has to be one where a bare `globalThis` reaches the global object
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.bare_name_reaches_the_host`): a binding
    of that name inside *root*, or a `with` body resolving it at runtime, captures the synthesized
    read where the `this` it replaced read the receiver. A caller holding a model of the tree
    before the rewrite asks it of each `this`; one that builds its model afterwards asks it of the
    returned identifiers.
    """
    synthesized: list[JsIdentifier] = []
    for node in receiver_this_expressions(root):
        replacement = JsIdentifier(name='globalThis')
        _replace_in_parent(node, replacement)
        synthesized.append(replacement)
    return synthesized


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
    of *exclude*, or whose node identity is in *exclude_ids*, are not counted. The block binding of
    a function declared in a block counts the references of each `var` Annex B copies it into as
    its own, since the value the copy stores is the value the block binding holds.
    """
    if binding is None:
        return True
    for ref in model.references(binding, exclude=exclude):
        if exclude_ids and id(ref) in exclude_ids:
            continue
        return True
    for copy in binding.copies_made:
        var = copy.var
        if var.dynamic_refs or var.exported or var.reachable_through_a_handed_object:
            return True
        for ref in model.references(var, exclude=exclude):
            if exclude_ids and id(ref) in exclude_ids:
                continue
            return True
    return False


def _is_expression_wrapper(node: JsFunctionDeclaration) -> bool:
    """
    Test whether a function declaration matches the self-disabling wrapper pattern:

        function NAME() {
            NAME = function() {};
        }
    """
    if node.id is None or node.body is None:
        return False
    if node.params:
        return False
    if not isinstance(node.body, JsBlockStatement):
        return False
    body = node.body.body
    if len(body) != 1:
        return False
    stmt = body[0]
    if not isinstance(stmt, JsExpressionStatement):
        return False
    expr = stmt.expression
    if not isinstance(expr, JsAssignmentExpression):
        return False
    if expr.operator != '=':
        return False
    if not isinstance(expr.left, JsIdentifier):
        return False
    if expr.left.name != node.id.name:
        return False
    rhs = expr.right
    if not isinstance(rhs, JsFunctionExpression):
        return False
    if wraps_return(rhs):
        return False
    if rhs.params:
        return False
    if isinstance(rhs.body, JsBlockStatement) and rhs.body.body:
        return False
    return True


def _stands_as_a_statement_of_a_function_or_the_script(node: JsFunctionDeclaration) -> bool:
    """
    Whether *node* is a statement of the script or of a function body, which is the only placement
    the whole of a declaration can be read from.

    A block-scoped function declaration is one thing in strict code, where it is scoped to the
    block, and another in sloppy code, where the enclosing scope holds the name from the start and
    reaching the block is what puts the function in it; a labeled or exported declaration sits in a
    slot `_remove_from_parent` cannot take it from.

    The three placements a Directive Prologue can open are the same three, which is why
    `refinery.lib.scripts.js.strict.is_prologue_host` answers this. A class static block is the one
    of them left out: it is a scope of its own that nothing here has measured the model against, and
    admitting it would buy a shape no obfuscator writes.
    """
    parent = node.parent
    return is_prologue_host(parent) and not isinstance(parent, JsStaticBlock)


def _a_bare_var_declarator_outside_a_loop_head(declared: Node) -> bool:
    """
    Whether *declared* declares a `var` with no initializer outside a loop head, which is the one
    further declaration of a wrapper's name that says nothing about what the name holds.

    An initializer is a declaration and not a write, and the store a `for-in` or `for-of` head makes
    is neither, so the model reports no reference for either of them. A binding carrying one is a
    binding something puts a value into that the expansion would never have seen.
    """
    declarator = declared.parent
    if not isinstance(declarator, JsVariableDeclarator) or declarator.init is not None:
        return False
    declaration = declarator.parent
    if declaration is None:
        return False
    return not isinstance(declaration.parent, (JsForInStatement, JsForOfStatement))


def _the_calls_that_reach(
    model: SemanticModel,
    binding: Binding,
    declaration: JsFunctionDeclaration,
) -> list[JsCallExpression] | None:
    """
    Every call that reaches the wrapper *declaration* declares, or `None` where the expansion is not
    equivalent for *binding*, the binding it declares, at all.

    Expanding a call to the statements its arguments carry is equivalent only where the name holds
    this wrapper when the call runs and nothing observes that the call then disabled it. That is
    three questions about the binding:

    - it is declared once, here, but for a bare `var` of the same name, which stores nothing;
    - every write to it is the self-disabling assignment inside this declaration, so nothing else
      ever puts a value into the name;
    - every reference to it is the callee of a call, so that no read of the name can tell the
      wrapper from what it left behind. The parentheses around a callee and around the call itself
      are looked through, which is what `refinery.lib.scripts.js.analysis.model.enclosing_operator`
      and `refinery.lib.scripts.js.model.strip_parens` are for;
      `refinery.lib.scripts.js.analysis.model.is_invocation_target` answers a wider question than
      this one, counting the tag of a tagged template, which no expansion here is written for. An
      export list naming the wrapper is such a reference — the local half of a sourceless list
      reads the binding — and is never the callee of a call, so an exported wrapper is refused
      here without being looked for separately.

    A reference that is not an identifier stands in for an access made through an object aliasing
    the binding, which is not a name this pass can follow.

    `refinery.lib.scripts.js.analysis.effects.EffectModel.function_escapes` asks a question the
    same shape as this one and answers `True` for every self-disabling wrapper there is: it refuses
    a written binding, a dynamic reference and a second declaration outright, and those three are
    exactly what the carve-outs above are about. It cannot stand in for this.

    A reference a `with` body resolves at run time is counted as a call that reaches the wrapper,
    which the object supplying the name instead would make wrong. That acceptance, and the reason
    it is made rather than refused, is
    `test.lib.scripts.js.test_unfixed_defects.TestAWithObjectMayCarryTheNameAWrapperAnswersTo`; the
    opaque reflective surfaces are accepted for the reason
    `test.lib.scripts.js.test_unfixed_defects.TestAnUnreadableEvalMayRebindAWrapper` states. A
    dynamic reference that resolves to another binding is not such a reference: it reaches this
    wrapper only in the reading where that binding is absent
    (`refinery.lib.scripts.js.analysis.model.Binding.may_be_absent`) and reaches the other one in
    the reading where it is not, so the wrapper is refused.
    """
    for name in binding.declarations:
        if name is not declaration.id and not _a_bare_var_declarator_outside_a_loop_head(name):
            return None
    for write in (*binding.writes, *binding.indefinite_writes):
        if not isinstance(write, JsIdentifier) or not write.is_descendant_of(declaration):
            return None
    if any(model.resolve(reference) is not None for reference in binding.dynamic_refs):
        return None
    calls: list[JsCallExpression] = []
    for reference in (*binding.reads, *binding.dynamic_refs):
        if not isinstance(reference, JsIdentifier):
            return None
        call = enclosing_operator(reference)
        if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not reference:
            return None
        calls.append(call)
    return calls


def declares_a_self_disabling_wrapper(node: JsFunctionDeclaration) -> bool:
    """
    Whether *node* declares a self-disabling wrapper (`_is_expression_wrapper`) standing where the
    whole of it can be read (`_stands_as_a_statement_of_a_function_or_the_script`), whose call
    answers neither a promise nor a generator object: the shape, asked before any model is read.
    """
    return (
        not wraps_return(node)
        and _stands_as_a_statement_of_a_function_or_the_script(node)
        and _is_expression_wrapper(node)
    )


def self_disabling_wrapper_calls(
    model: SemanticModel,
    binding: Binding,
) -> list[JsCallExpression] | None:
    """
    Every call through *binding* where it names a self-disabling wrapper
    (`declares_a_self_disabling_wrapper`) and each of these calls does nothing but evaluate its
    arguments (`_the_calls_that_reach`), or `None`. A wrapper code outside the file may reach by
    name (`refinery.lib.scripts.js.analysis.model.SemanticModel.reached_from_outside`) is none: that
    code may have replaced it before any of these calls runs. The template matcher reads such a
    call as its arguments
    (`refinery.lib.scripts.js.deobfuscation.templates.empty_functions_called`), and the wrapper pass
    expands it into them (`refinery.lib.scripts.js.deobfuscation.argwrap`).
    """
    if model.reached_from_outside(binding):
        return None
    for declared in binding.declarations:
        declaration = declared.parent
        if (
            isinstance(declaration, JsFunctionDeclaration)
            and declaration.id is declared
            and declares_a_self_disabling_wrapper(declaration)
        ):
            return _the_calls_that_reach(model, binding, declaration) or None
    return None


def binding_constant(effects: EffectModel, binding: Binding) -> tuple[bool, Value]:
    """
    The value *binding* holds wherever it has been established, as `(True, value)`, or
    `(False, None)` where it holds no constant a read may be answered with. That is the one value
    the text gives it, `refinery.lib.scripts.js.analysis.model.SemanticModel.singular_value`, when
    that value denotes a primitive or an array of primitives. An array must also be a container
    nothing changes or hands out, which is
    `refinery.lib.scripts.js.analysis.effects.EffectModel.binding_is_immutable_container`,
    and a binding code outside the file may rewrite
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.reached_from_outside`) holds nothing the
    file decides. Nor does one that code no reference records may reach under the run's execution
    model and trust setting,
    `refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_can_reach`: a table of a
    script is a property of the global object that an indirect `eval` or a store under a runtime
    key can rewrite, while a table of a module is out of reach of every such surface. An array
    holding an array or an object is refused: an element read out of it is a container the program
    shares between reads, where a folded read hands out a fresh copy of it.

    Whether the value is in place when a given read runs is an ordering question this does not ask.
    """
    model = effects.model
    known, value = denoted_value(
        model.singular_value(binding),
        model,
        lambda converted: coerces_uninterceptably(effects, converted),
    )
    if not known:
        return False, None
    return held_constant(effects, binding, value)


def held_constant(effects: EffectModel, binding: Binding, value: Value) -> tuple[bool, Value]:
    """
    *value*, the one value *binding* is given, as `(True, value)` where a read of the binding may
    be answered with it, as `binding_constant` decides for the value the text spells, or
    `(False, None)`.
    """
    model = effects.model
    if isinstance(value, dict):
        return False, None
    if isinstance(value, list):
        if any(isinstance(item, (list, dict)) for item in value):
            return False, None
        if not effects.binding_is_immutable_container(binding):
            return False, None
    if model.reached_from_outside(binding):
        return False, None
    if model.reflection_can_reach(binding):
        return False, None
    return True, value


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
    strands it whenever the object does not carry the property. An exported binding is named by the
    export itself, which an importer reads and which a removal would leave declaring nothing.
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
            if binding.exported or binding_has_references(model, binding, exclude_ids=inside):
                return False
            if any(id(ref) not in inside for ref in model.dynamic_references(binding)):
                return False
    return True


class Landing(Enum):
    """
    Where a value lands, named for what the semantic model and the intrinsic-write scan read off
    the position that receives it (`value_landing`).
    """
    BINDING = auto()
    PROPERTY = auto()
    MEMBER = auto()
    KEY = auto()
    INSTALL = auto()
    ARGUMENT = auto()
    CALLEE = auto()
    ELSEWHERE = auto()


def value_landing(node: Node, root: Node | None = None) -> Landing | None:
    """
    Where the value at *node* lands. It is followed outward through the forms that hand it on
    unchanged, those `refinery.lib.scripts.js.analysis.intrinsics.denoting_leaves` looks through
    and a spread, to the first position that receives it:

    - `Landing.BINDING`: the initializer of a declarator, or the right side of an assignment to a
      name or a pattern. The scan follows a value through the bindings that hold it, and the
      semantic model finds the names holding the global object among them.
    - `Landing.PROPERTY`: the right side of an assignment to a member. The models follow it into a
      binding where the member is one of the global object or of an `arguments` object.
    - `Landing.MEMBER`: the object of a member access. A write, `delete` or descriptor install
      through the access is attributed to the foot of its chain, and an access on the global object
      reads, writes or reflects on a global.
    - `Landing.KEY`: the computed key of a member access, or the key a descriptor install is handed.
      A string there makes the access or the install one of the property it names.
    - `Landing.INSTALL`: the object a descriptor install is handed, the first argument of
      `Object.defineProperty` and of its kin.
    - `Landing.ARGUMENT`: any other argument of a call or `new`. The scan reads an intrinsic handed
      over as one that escapes, and the semantic model reads the global object as one the callee
      may write a global through.
    - `Landing.CALLEE`: the function a call or `new` invokes, which the semantic model reads by
      its name where that name runs a string of code.
    - `Landing.ELSEWHERE`: anywhere else, such as an operand, a test, an element of a literal, or a
      value returned or discarded.

    A value that reaches *root* still being handed on lands nowhere yet, which is `None`: the
    caller places what *root* stands for, as an inlined call puts the expression it answers where
    the call stood.
    """
    cursor = node
    while cursor is not root and (parent := cursor.parent) is not None:
        if isinstance(parent, JsMemberExpression):
            if parent.object is cursor:
                return Landing.MEMBER
            return Landing.KEY if parent.computed else Landing.ELSEWHERE
        if isinstance(parent, (JsCallExpression, JsNewExpression)):
            return _call_landing(parent, cursor)
        if isinstance(parent, JsVariableDeclarator):
            return Landing.BINDING if parent.init is cursor else Landing.ELSEWHERE
        if isinstance(parent, JsAssignmentExpression):
            if parent.right is not cursor:
                return Landing.ELSEWHERE
            if isinstance(strip_parens(parent.left), JsMemberExpression):
                return Landing.PROPERTY
            return Landing.BINDING
        if isinstance(parent, JsConditionalExpression):
            if parent.test is cursor:
                return Landing.ELSEWHERE
        elif isinstance(parent, JsSequenceExpression):
            if not parent.expressions or parent.expressions[-1] is not cursor:
                return Landing.ELSEWHERE
        elif not isinstance(parent, (
            JsParenthesizedExpression,
            JsLogicalExpression,
            JsSpreadElement,
        )):
            return Landing.ELSEWHERE
        cursor = parent
    return None if cursor is root else Landing.ELSEWHERE


def _call_landing(call: JsCallExpression | JsNewExpression, part: Node) -> Landing:
    """
    Where the value at *part*, the callee or an argument of *call*, lands. An install is read the
    way `refinery.lib.scripts.js.analysis.intrinsics` reads one: `defineProperty` and
    `defineProperties` install on their first argument, and `defineProperty` under the key its
    second one names, whatever object the method is read off; `__defineGetter__` and
    `__defineSetter__` install on the object they are read off, under the key their first argument
    names.
    """
    arguments = call.arguments
    if all(argument is not part for argument in arguments):
        return Landing.CALLEE
    callee = strip_parens(call.callee)
    if not isinstance(call, JsCallExpression) or not isinstance(callee, JsMemberExpression):
        return Landing.ARGUMENT
    method = key_text(callee)
    if method not in ACCESSOR_INSTALL_METHODS:
        return Landing.ARGUMENT
    if method.startswith('__define'):
        return Landing.KEY if arguments[0] is part else Landing.ARGUMENT
    if arguments[0] is part:
        return Landing.INSTALL
    if method == 'defineProperty' and len(arguments) > 1 and arguments[1] is part:
        return Landing.KEY
    return Landing.ARGUMENT


def declares_a_watched_name(roots: Iterable[Node]) -> bool:
    """
    Whether code under *roots* declares or assigns a name in
    `refinery.lib.scripts.js.analysis.intrinsics.ESCAPE_WATCHED_ROOTS`. The scan behind
    `refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites` records every binding of every
    scope by name, the one an assignment to an undeclared name creates among them, so code doing
    either changes what a rebuilt scan says of the name. A name of the global object is not one: a
    local of that name only takes a reading of the global object away.
    """
    for root in roots:
        for node in root.walk():
            if isinstance(node, JsIdentifier):
                if (
                    node.name in ESCAPE_WATCHED_ROOTS
                    and is_use_position(node)
                    and reference_role(node) is not Role.READ
                ):
                    return True
            elif any(name.name in ESCAPE_WATCHED_ROOTS for name in _declared_identifiers(node)):
                return True
    return False


def _declared_identifiers(node: Node) -> Iterator[JsIdentifier]:
    """
    The identifiers the construct *node* itself declares: the targets of a declarator, the own name
    and the parameters of a function, the own name of a class, and the parameter of a catch clause.
    """
    if isinstance(node, JsVariableDeclarator):
        yield from pattern_identifiers(node.id)
    elif isinstance(node, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        if not isinstance(node, JsArrowFunctionExpression) and node.id is not None:
            yield node.id
        for param in node.params:
            yield from pattern_identifiers(param)
    elif isinstance(node, (JsClassDeclaration, JsClassExpression)):
        if node.id is not None:
            yield node.id
    elif isinstance(node, JsCatchClause):
        yield from pattern_identifiers(node.param)


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


class BatchedTransformer(Transformer):
    """
    Intermediate base for transforms that take every decision of one invocation against the models
    of the tree the invocation entered on, and make the edits afterwards. This is a third freshness
    regime beside the two the codebase already documents: a pin holds the models across a pass
    whose edits only remove facts, and a re-read-per-rewrite pass rebuilds them for a pass whose
    edits make facts more restrictive. A batched pass asks no model anything once its first edit
    has landed, so every decision reads models that describe the tree it was taken on, without
    holding them past an edit and without rebuilding them after one.

    A subclass owes the regime four obligations:

    - Every node an edit holds from the decision — an anchor statement, a declarator, a
      substitution target — is attached to the live tree when the edit lands: either it is checked
      through `refinery.lib.scripts.is_attached`, or the edit is made by a walk that reaches only
      what the tree still holds. A decision that carries a node from the entry tree can otherwise
      be pointed at a subtree an earlier edit already detached.
    - A value an edit writes at a position other than where the entry tree holds it is a copy made
      at decision. An earlier edit, another decision's or the decision's own, may rewrite the
      original before the edit lands, and the edit would then write something its decision never
      checked. An edit that moves a subtree instead of copying one carries the edits made inside it
      before, and its pass's docstring shows those edits leave the decision valid.
    - A decision stands down, whole or in part, only where an earlier edit of the same invocation
      edited a node it holds. That edit marked the invocation changed, so the group runs the pass
      again, and the next invocation re-decides whatever the stand-down held back.
    - A per-pass non-interference docstring of its own: which model facts the decisions read, which
      edits of the invocation can invalidate them, and in which direction. A decision valid on the
      tree the invocation entered on must remain valid on the tree it leaves.

    The mid-invocation freshness a per-edit model rebuild would supply is not replaced by anything
    here: its recall half comes from the group fixpoint, which re-runs a changed group, and its
    correctness half is the non-interference contract above. The `--no-batch` differential
    (`test/conftest.py`) runs every batched pass with `batching` off, taking each decision where the
    edit is made and against the models the tree then warrants.
    """

    batching: bool = True


class PinnedTransformer(Transformer):
    """
    Intermediate base for transforms that hold the models of the tree an invocation entered on
    across their own edits, through `refinery.lib.scripts.modelcache.ModelCacheBase.pinned`, and
    renew them in place where an edit may have made a held answer more permissive than a rebuilt
    one. It is the pin's regime for a pass whose walk it cannot leave and enter again: a renewal
    (`refinery.lib.scripts.modelcache.ModelCacheBase.renew`) holds the models of the current tree,
    as leaving the pin and entering it again would, and the walk goes on where it was.

    A subclass owes the regime four obligations:

    - It names the models it reads in `reads`, empty for the cache's warm set, and reads no other.
      It holds them through `holding_models` and takes them from `held_models`, whose first call it
      makes at its first decision, before its first edit.
    - It renews (`renew_models`) before a decision that reads code the invocation made or edited
      since the last renewal: a held model knows that code as it was, or not at all.
    - After an edit that may show the models a fact the held ones do not record, it renews before it
      next reads a fact from them: an edit that puts a value the models follow only through bindings
      (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.follows_only_through_bindings`)
      where they read one (`value_landing`), a string where it names a property, a name where it
      makes a call run a string of code, the last piece of a concatenation the models read as one
      string, that removes the `with` statement between a name and a binding holding such a value,
      or that declares or assigns a name the intrinsic-write scan watches
      (`declares_a_watched_name`).
    - A per-pass docstring of its own shows that every other edit leaves the answers it reads no
      more permissive than rebuilt ones.

    What the pass records of its edits to decide the second obligation is forgotten at every
    renewal, through `_forget_edits`. The `--no-pin` differential (`test/conftest.py`) runs every
    such pass with the pin neutralized, where every read is answered by models of the current tree.
    """

    reads: tuple[str, ...] = ()

    def __init__(self):
        super().__init__()
        self._held_cache: ModelCache | None = None
        self._models_built = False

    @contextmanager
    def holding_models(self, root: JsScript) -> Generator[None, None, None]:
        """
        Hold the models of *root* for the block, which a subclass wraps around its walk.
        """
        models = model_cache(self, root)
        with models.pinned():
            self._held_cache = models
            self._models_built = False
            try:
                yield
            finally:
                self._held_cache = None

    def held_models(self) -> ModelCache:
        """
        The models the invocation holds. The first call builds the models in `reads` over the
        tree as it stands, which is the tree the invocation entered on.
        """
        if not self._models_built:
            self.renew_models()
        models = self._held_cache
        assert models is not None, 'models are held only inside holding_models'
        return models

    def renew_models(self) -> None:
        """
        Hold the models in `reads` of the current tree, and forget the edits recorded since the
        last renewal.
        """
        models = self._held_cache
        assert models is not None, 'models are held only inside holding_models'
        models.renew(*self.reads)
        self._models_built = True
        self._forget_edits()

    def _forget_edits(self) -> None:
        """
        Forget what the pass recorded of its edits since the last renewal.
        """


class BatchedScopeTransformer(BatchedTransformer, ScopeProcessingTransformer, Generic[_Plan]):
    """
    Intermediate base for scope-processing transforms in the regime of `BatchedTransformer` whose
    decisions are plans: each is collected as it is decided, and the whole batch is applied once
    the traversal ends. A batched scope pass emits bindings, and a plan lands after every other
    plan was decided, so it owes two obligations beyond the regime's:

    - Every binding the batch emits or exposes — the `var` and `function` declarations it installs,
      and the bare identifiers its rewrites create — is registered through `emits` at decision time,
      and a later candidate in the same scope holds a colliding key back through `name_emitted_in`.
      Without it, the later candidate decides against an entry tree that does not yet carry the
      earlier emission and the two installs collide. A key held back for an emission that never
      landed is re-decided by the next invocation like any other stand-down.
    - The attachment the regime requires is checked: every node a plan holds from the decision is
      tested through `refinery.lib.scripts.is_attached` when the plan is applied.
    """

    def __init__(self):
        super().__init__()
        self._plans: list[_Plan] = []
        self._emitted: dict[Node, set[str]] = {}

    def visit_JsScript(self, node: JsScript):
        self._plans.clear()
        self._emitted.clear()
        super().visit_JsScript(node)
        for plan in self._plans:
            self._apply_plan(plan)
        self._plans.clear()
        return None

    def _submit(self, plan: _Plan) -> None:
        """
        Hand one decided plan to the batch. Batched, it joins the plans applied at the end of the
        invocation; with `batching` off, it applies at once, against the tree its decision read.
        """
        if self.batching:
            self._plans.append(plan)
        else:
            self._apply_plan(plan)

    def _apply_plan(self, plan: _Plan) -> None:
        raise NotImplementedError

    def emits(self, scope: Node, name: str) -> None:
        """
        Record that the batch binds *name* in *scope*, through a declaration it installs or a bare
        identifier one of its rewrites creates there. Registered at decision time so every later
        candidate of the same scope reads the accumulated set, whatever mode the pass runs in.
        """
        self._emitted.setdefault(scope, set()).add(name)

    def name_emitted_in(self, scope: Node, name: str) -> bool:
        """
        Whether an earlier plan of this batch already binds *name* in *scope*.
        """
        return name in self._emitted.get(scope, ())


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
