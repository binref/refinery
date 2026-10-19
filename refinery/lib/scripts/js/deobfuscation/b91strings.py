"""
Decode the strings an obfuscator conceals behind base91 decoders. Every string literal becomes a
call of an accessor. One kind of accessor decodes an element of a shared table of encoded strings
once and keeps the result in a cache:

    var table = ["fOg=r", ...];
    var cache = {};
    function decode(str) { var alphabet = "..."; ...; return bufferToString(bytes); }
    function accessor(index) {
        if (typeof cache[index] === "undefined") { return cache[index] = decode(table[index]); }
        return cache[index];
    }

The other kind slices the encoded string out of one long string and keeps no cache:

    var text = "...fOg=r...";
    function accessor(start, length) { return decode(text.slice(start, start + length)); }

Every scope gets a decoder with an alphabet of its own. A decoder and an accessor are recognized by
their templates (`refinery.lib.scripts.js.deobfuscation.templates`), whatever their names are and
wherever they stand, through the names that hold them. A call of an accessor whose decoder, table
and cache are in place before it runs becomes the string it decodes, and the machinery goes once
nothing names it any longer.
"""
from __future__ import annotations

from typing import Callable, Iterator, NamedTuple

from refinery.lib.scripts import Node, Statement, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    FunctionNames,
    SemanticModel,
    enclosing_operator,
    statement_list_of,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    denoted_value,
    integer_literal,
    make_string_literal,
    nothing_still_names,
    reaches_script_completion,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.templates import (
    Shuffle,
    Template,
    match,
    matches,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsVariableDeclarator,
    static_property_key,
    strip_parens,
)
from refinery.lib.scripts.js.options import preserves_script_return
from refinery.lib.scripts.js.utf16 import to_code_units


def _decode_base91(encoded: str, alphabet: str) -> str:
    """
    Decode a base91-encoded string using the given 91-character alphabet. The encoding pairs
    characters from the alphabet into 13-or-14-bit values that are accumulated into a byte stream,
    which is then interpreted as UTF-8. The result is the string a program holds, one UTF-16 code
    unit to a character, so a character above the basic plane is its surrogate pair.
    """
    result: list[int] = []
    b = 0
    n = 0
    v = -1
    for ch in encoded:
        p = alphabet.find(ch)
        if p == -1:
            continue
        if v < 0:
            v = p
        else:
            v += p * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                result.append(b & 0xFF)
                b >>= 8
                n -= 8
            v = -1
    if v > -1:
        result.append((b | v << n) & 0xFF)
    return to_code_units(bytes(result).decode('utf-8'))


def _is_base91_alphabet(s: str) -> bool:
    return len(s) == 91 and len(set(s)) == 91


_DECODER_BODY = (
    'var raw = "" + (str || ""); var len = raw.length; var ret = []; var b = 0; var n = 0; var v = -1;'
    ' for (var i = 0; i < len; i++) { var p = ALPHABET.indexOf(raw[i]); if (p === -1) continue;'
    ' if (v < 0) { v = p; } else { v += p * 91; b |= v << n; n += (v & 8191) > 88 ? 13 : 14;'
    ' do { ret.push(b & 0xff); b >>= 8; n -= 8; } while (n > 7); v = -1; } }'
    ' if (v > -1) { ret.push((b | (v << n)) & 0xff); } return BUFFER(ret);'
)

_DECODER_BODY_READING_A_VARIABLE = _DECODER_BODY.replace('ALPHABET.', 'table.')

_DECODER_TEMPLATES = (
    Template(
        F'function DECODE(str) {{ {_DECODER_BODY} }}',
        frozenset({'ALPHABET', 'BUFFER'}),
    ),
    Template(
        F'function DECODE(str) {{ var table = ALPHABET; {_DECODER_BODY_READING_A_VARIABLE} }}',
        frozenset({'ALPHABET', 'BUFFER'}),
    ),
)
"""
The decoder as the obfuscator writes it, with its alphabet inlined and in a variable of its own.
`ALPHABET` stands for the literal holding the alphabet and `BUFFER` for the callee of the call that
turns the decoded bytes into a string.
"""

_CACHING_ACCESSOR = (
    Template(
        'function ACCESSOR(index) { if (typeof CACHE[index] === "undefined") {'
        ' return CACHE[index] = DECODE(TABLE[index]); } return CACHE[index]; }',
        frozenset({'CACHE', 'DECODE', 'TABLE'}),
    ),
    Template(
        'function ACCESSOR(index) { if (typeof CACHE[index] === "undefined") {'
        ' return CACHE[index] = DECODE(TABLE[index]); } else { return CACHE[index]; } }',
        frozenset({'CACHE', 'DECODE', 'TABLE'}),
    ),
)
"""
The accessor keeping a cache as the obfuscator writes it, its last `return` after the `if` or in an
`else`. `CACHE`, `DECODE` and `TABLE` stand for the names holding the cache, the decoder and the
table.
"""

_SLICING_ACCESSOR = (
    Template(
        'function ACCESSOR(start, length) { return DECODE(TABLE.slice(start, start + length)); }',
        frozenset({'DECODE', 'TABLE'}),
    ),
)
"""
The accessor slicing its string out of one long string as the obfuscator writes it. `DECODE` stands
for the name holding the decoder and `TABLE` for the name holding the long string or for the string
literal the accessor spells it out with.
"""


_DEFAULTS = (
    'if (typeof a === "undefined") { a = DECODE; }'
    ' if (typeof b === "undefined") { b = CACHE; }'
    ' if (x !== y) { return b[x] || (b[x] = a(TABLE[x])); }'
)

_DEFAULTED_ACCESSOR = (
    Template(
        F'function ACCESSOR(x, y, z, a, b) {{ {_DEFAULTS} }}',
        frozenset({'CACHE', 'DECODE', 'TABLE'}),
    ),
)
"""
The accessor keeping its decoder and its cache in two parameters it defaults. `CACHE`, `DECODE` and
`TABLE` stand for the names holding the cache, the decoder and the table.
"""

_DECOYED_ACCESSOR = Template(
    F'function TEMPLATE(x, y, z, a, b) {{ {_DEFAULTS}'
    ' if (z == x) { return y[CACHE[z]] = ACCESSOR(x, y); }'
    ' if (y) { [b, y] = [a(b), x || z]; return ACCESSOR(x, b, z); }'
    ' if (z && a !== DECODE) { ACCESSOR = DECODE; return ACCESSOR(x, -1, z, a, b); }'
    ' if (a === ACCESSOR) { DECODE = y; return DECODE(z); }'
    ' if (a === undefined) { ACCESSOR = b; }'
    ' if (z == a) { return y ? x[b[y]] : CACHE[x] || (z = b[x] || a, CACHE[x] = z(TABLE[x])); } }',
    frozenset({'ACCESSOR', 'CACHE', 'DECODE', 'TABLE'}),
    Shuffle(2, 1),
)
"""
The accessor of `_DEFAULTED_ACCESSOR` as the obfuscator writes it: after the two defaults, its
working branch and some of six decoys, in an order of its choosing. `ACCESSOR` stands for the name
holding the accessor.
"""


class _Held(NamedTuple):
    """
    A function each of its names holds as its one value, and the node installing it there, which
    goes when the function goes: the declaration, the declarator, or the statement assigning it.
    """
    names: FunctionNames
    function: JsFunctionNode
    definition: Node | None


class _Decoder(NamedTuple):
    held: _Held
    alphabet: str


class _Parts(NamedTuple):
    """
    What stands where an accessor template has its decoder, its table and its cache: the names
    holding the decoder and the cache, if the accessor keeps one, and the name holding the table or
    the string literal the accessor spells it out with.
    """
    decoder: Binding
    table: Binding | JsStringLiteral
    cache: Binding | None


class _StringArray(NamedTuple):
    """
    A table that is an array of encoded strings, held by *binding*. A call passes the index of the
    one it decodes.
    """
    binding: Binding
    strings: list[str]

    def encoded(self, numbers: list[int]) -> str | None:
        if len(numbers) != 1 or not 0 <= (index := numbers[0]) < len(self.strings):
            return None
        return self.strings[index]


class _LongString(NamedTuple):
    """
    A table that is one long string the encoded strings stand in, held by *binding*, or spelled out
    by the accessor where *binding* is `None`. A call passes where the one it decodes starts and how
    long it is, both counted in UTF-16 code units, which is what the string holds.
    """
    binding: Binding | None
    text: str

    def encoded(self, numbers: list[int]) -> str | None:
        if len(numbers) != 2:
            return None
        start, length = numbers
        if start < 0 or length < 0 or start + length > len(self.text):
            return None
        return self.text[start:start + length]


_Table = _StringArray | _LongString


class _Kind(NamedTuple):
    """
    A kind of accessor: its templates, the reader of what stands where they have their decoder,
    table and cache, the reader of what its table holds, and the question whether the program calls
    an accessor of the kind only as its templates assume, asked of the names holding it.
    """
    templates: tuple[Template, ...]
    parts: Callable[[SemanticModel, JsFunctionNode], _Parts | None]
    table: Callable[[EffectModel, Binding | JsStringLiteral], _Table | None]
    called: Callable[[SemanticModel, FunctionNames | None], bool]


class _Accessor(NamedTuple):
    """
    An accessor, the decoder it calls and the name it calls it through, the table it reads, and the
    cache it keeps the decoded strings in, if it keeps any.
    """
    held: _Held
    decoder: _Decoder
    decoder_name: Binding
    table: _Table
    cache: Binding | None

    def stores(self) -> list[Binding]:
        """
        The names holding the table and the cache.
        """
        return [store for store in (self.table.binding, self.cache) if store is not None]


def _definition(function: JsFunctionNode) -> Node | None:
    if isinstance(function, JsFunctionDeclaration):
        return function
    parent = enclosing_operator(function)
    if isinstance(parent, JsVariableDeclarator):
        return parent
    if isinstance(parent, JsAssignmentExpression) and isinstance(parent.parent, JsExpressionStatement):
        return parent.parent
    return None


def _held_functions(model: SemanticModel, root: Node) -> Iterator[_Held]:
    """
    Every function that each name invoking it holds as its only value.
    """
    for node in root.walk():
        if not isinstance(node, FUNCTION_NODES):
            continue
        names = model.function_names(node)
        if names is None or not all(
            len(binding.declarations) == 1 and strip_parens(model.singular_value(binding)) is node
            for binding in names.bindings
        ):
            continue
        yield _Held(names, node, _definition(node))


def _declared_outside(model: SemanticModel, function: Node, callee: Node | None) -> bool:
    """
    Whether *callee* names something *function* does not declare: a name or fixed keys read off
    one, possibly behind numbers a comma operator discards, as in `(0, Buffer.from)`.
    """
    callee = strip_parens(callee)
    if isinstance(callee, JsSequenceExpression):
        *discarded, callee = callee.expressions
        if not all(isinstance(strip_parens(part), JsNumericLiteral) for part in discarded):
            return False
        callee = strip_parens(callee)
    while isinstance(callee, JsMemberExpression) and not callee.computed:
        callee = strip_parens(callee.object)
    if not isinstance(callee, JsIdentifier):
        return False
    binding = model.resolve(callee)
    return binding is None or not binding.declared_within(function)


def _decoder(model: SemanticModel, held: _Held) -> _Decoder | None:
    """
    The decoder *held* is, when it is the decoder template: its alphabet is the one string literal
    of its own that is a base91 alphabet, and the call it returns through calls a function it does
    not declare, which turns the decoded bytes into a string. The name holding it is asked about
    reflection as the name of a table is (`_table_value`): an accessor reading a table it spells out
    has no such name to ask, and code reaching the scope of the machinery may rebind the decoder as
    well as the table.
    """
    function = held.function
    if len(function.params) != 1:
        return None
    if any(model.reflection_can_reach_from_its_scope(name) for name in held.names.bindings):
        return None
    alphabets = [
        node for node in walk_scope(function, include_root_body=True)
        if isinstance(node, JsStringLiteral) and node.value is not None and _is_base91_alphabet(node.value)
    ]
    values = {node.value for node in alphabets if node.value is not None}
    if len(values) != 1:
        return None
    statements = statement_list_of(function)
    if not statements or not isinstance(last := statements[-1], JsReturnStatement):
        return None
    call = strip_parens(last.argument)
    if not isinstance(call, JsCallExpression) or len(call.arguments) != 1:
        return None
    if not _declared_outside(model, function, call.callee):
        return None
    nodes = {id(node): 'ALPHABET' for node in alphabets}
    nodes[id(call.callee)] = 'BUFFER'
    if not matches(model, function, _DECODER_TEMPLATES, {}, nodes):
        return None
    return _Decoder(held, values.pop())


def _outer(model: SemanticModel, function: Node, node: Node | None) -> Binding | None:
    """
    The binding *node* names when it is a name *function* does not declare.
    """
    node = strip_parens(node)
    if not isinstance(node, JsIdentifier) or (binding := model.resolve(node)) is None:
        return None
    if binding.declared_within(function):
        return None
    return binding


def _caching_parts(model: SemanticModel, function: JsFunctionNode) -> _Parts | None:
    """
    The names *function* reads an element of at its one parameter, the one of them it hands to a
    call taking one argument, and that call's callee: the cache, the table and the decoder, if
    *function* is a caching accessor and the cache holds an empty object.
    """
    if len(function.params) != 1 or not isinstance(index := function.params[0], JsIdentifier):
        return None
    if not 0 < len(statement_list_of(function) or ()) <= 2:
        return None
    parameter = model.binding_of(index)
    owners: dict[int, Binding] = {}
    decoder = table = None
    for node in walk_scope(function, include_root_body=True):
        if not isinstance(node, JsMemberExpression) or not node.computed:
            continue
        owner = strip_parens(node.object)
        key = strip_parens(node.property)
        if not isinstance(owner, JsIdentifier) or not isinstance(key, JsIdentifier):
            continue
        if model.resolve(key) is not parameter or (binding := model.resolve(owner)) is None:
            continue
        owners[id(binding)] = binding
        call = enclosing_operator(node)
        if not isinstance(call, JsCallExpression) or len(call.arguments) != 1:
            continue
        callee = strip_parens(call.callee)
        if strip_parens(call.arguments[0]) is node and isinstance(callee, JsIdentifier):
            decoder = model.resolve(callee)
            table = binding
    if decoder is None or table is None or len(owners) != 2:
        return None
    cache = next(binding for binding in owners.values() if binding is not table)
    if decoder is cache or decoder is table:
        return None
    empty = strip_parens(model.singular_value(cache))
    if not isinstance(empty, JsObjectExpression) or empty.properties:
        return None
    return _Parts(decoder, table, cache)


def _slicing_parts(model: SemanticModel, function: JsFunctionNode) -> _Parts | None:
    """
    The callee of the call *function* returns and what it slices the argument of that call out of:
    the decoder and the table, if *function* is a slicing accessor.
    """
    if len(function.params) != 2 or len(statements := statement_list_of(function) or ()) != 1:
        return None
    if not isinstance(body := statements[0], JsReturnStatement):
        return None
    call = strip_parens(body.argument)
    if not isinstance(call, JsCallExpression) or len(call.arguments) != 1:
        return None
    sliced = strip_parens(call.arguments[0])
    if not isinstance(sliced, JsCallExpression):
        return None
    if not isinstance(member := strip_parens(sliced.callee), JsMemberExpression):
        return None
    decoder = _outer(model, function, call.callee)
    text = strip_parens(member.object)
    table = text if isinstance(text, JsStringLiteral) else _outer(model, function, text)
    if decoder is None or table is None or decoder is table:
        return None
    return _Parts(decoder, table, None)


def _default(model: SemanticModel, function: Node, statement: Node | None) -> Binding | None:
    """
    The name *statement* stores into a parameter of *function* when it is
    `if (...) { parameter = name; }` and *function* does not declare the name.
    """
    if not isinstance(statement, JsIfStatement) or statement.alternate is not None:
        return None
    consequent = statement.consequent
    if isinstance(consequent, JsBlockStatement):
        if len(consequent.body) != 1:
            return None
        consequent = consequent.body[0]
    if not isinstance(consequent, JsExpressionStatement):
        return None
    assignment = strip_parens(consequent.expression)
    if not isinstance(assignment, JsAssignmentExpression):
        return None
    return _outer(model, function, assignment.right)


def _defaulted_parts(model: SemanticModel, function: JsFunctionNode) -> _Parts | None:
    """
    The names the first two statements of *function* store into its fourth and fifth parameter, the
    decoder and the cache, and the other name it reads an element of at its first parameter, the
    table, if *function* is a defaulted accessor and the cache holds an empty array.
    """
    params = function.params
    if len(params) != 5 or not all(isinstance(parameter, JsIdentifier) for parameter in params):
        return None
    statements = statement_list_of(function) or []
    if len(statements) < 3:
        return None
    decoder = _default(model, function, statements[0])
    cache = _default(model, function, statements[1])
    if decoder is None or cache is None or decoder is cache:
        return None
    first = params[0]
    assert isinstance(first, JsIdentifier)
    index = model.binding_of(first)
    tables: dict[int, Binding] = {}
    for node in walk_scope(function, include_root_body=True):
        if not isinstance(node, JsMemberExpression) or not node.computed:
            continue
        key = strip_parens(node.property)
        if not isinstance(key, JsIdentifier) or model.resolve(key) is not index:
            continue
        if (owner := _outer(model, function, node.object)) is not None and owner is not cache:
            tables[id(owner)] = owner
    if len(tables) != 1 or (table := next(iter(tables.values()))) is decoder:
        return None
    empty = strip_parens(model.singular_value(cache))
    if not isinstance(empty, JsArrayExpression) or empty.elements:
        return None
    return _Parts(decoder, table, cache)


def _called_with_one_argument(model: SemanticModel, names: FunctionNames | None) -> bool:
    """
    Whether every reference of the names of an accessor but their declarations is the callee of a
    call passing one argument, so the accessor is never handed a decoder or a cache of a caller's
    choosing. An accessor no name holds may be called any way.
    """
    if names is None:
        return False
    for binding in names.bindings:
        if binding.dynamic_refs or binding.has_indefinite_write:
            return False
        declarations = {id(node) for node in binding.declarations}
        for reference in names.references_of(binding):
            if id(reference) in declarations:
                continue
            call = enclosing_operator(reference)
            if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not reference:
                return False
            if len(call.arguments) != 1 or isinstance(call.arguments[0], JsSpreadElement):
                return False
    return True


def _called_any_way(model: SemanticModel, names: FunctionNames | None) -> bool:
    """
    Whether the program calls an accessor only as the templates of a kind assume, for a kind whose
    templates assume nothing about the calls.
    """
    return True


def _table_value(effects: EffectModel, table: Binding | JsStringLiteral) -> tuple[bool, object]:
    """
    What *table* denotes as `refinery.lib.scripts.js.deobfuscation.helpers.denoted_value` reads it:
    the string a literal spells, or the one value the name *table* holds wherever it is in place,
    unless code the model cannot read may reach that name.

    The table is machinery under a name the obfuscator makes up, like the decoder, the accessor and
    the cache. A constant of the program is also asked whether a host or code running in the global
    scope may reach it (`refinery.lib.scripts.js.deobfuscation.helpers.binding_constant`), while
    the table is asked only about code in its own scope the model cannot read: a direct `eval`
    there, or a span the parser could not read
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_can_reach_from_its_scope`).
    A script the obfuscator writes stores on the global object under keys this very table holds,
    and the wider question would refuse the table of every script.
    """
    model = effects.model
    if isinstance(table, JsStringLiteral):
        return denoted_value(table, model)
    if model.reflection_can_reach_from_its_scope(table):
        return False, None
    return denoted_value(model.singular_value(table), model)


def _string_array(effects: EffectModel, table: Binding | JsStringLiteral) -> _StringArray | None:
    """
    The strings the name *table* holds (`_table_value`): the one array of at least ten strings the
    text gives it, in a container nothing changes or hands out
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.binding_is_immutable_container`).
    """
    if not isinstance(table, Binding):
        return None
    known, value = _table_value(effects, table)
    if not known or not isinstance(value, list) or len(value) < 10:
        return None
    strings = [string for string in value if isinstance(string, str)]
    if len(strings) != len(value) or not effects.binding_is_immutable_container(table):
        return None
    return _StringArray(table, strings)


def _long_string(effects: EffectModel, table: Binding | JsStringLiteral) -> _LongString | None:
    """
    The string *table* spells out, or the string the name *table* holds (`_table_value`).
    """
    known, value = _table_value(effects, table)
    if not known or not isinstance(value, str):
        return None
    return _LongString(table if isinstance(table, Binding) else None, value)


_KINDS = (
    _Kind(_CACHING_ACCESSOR, _caching_parts, _string_array, _called_any_way),
    _Kind(_SLICING_ACCESSOR, _slicing_parts, _long_string, _called_any_way),
    _Kind(_DEFAULTED_ACCESSOR, _defaulted_parts, _string_array, _called_with_one_argument),
)


def _parts(model: SemanticModel, function: JsFunctionNode) -> tuple[_Kind, _Parts] | None:
    """
    The first kind of accessor whose reader of parts recognizes *function*, and what stands where
    the templates of that kind have their decoder, table and cache. Whether *function* has the
    normal form of one of those templates is asked apart from this (`_is_accessor`), after the
    cheaper questions, since building that form copies the whole function.
    """
    for kind in _KINDS:
        if (parts := kind.parts(model, function)) is not None:
            return kind, parts
    return None


def _is_accessor(model: SemanticModel, function: JsFunctionNode, kind: _Kind, parts: _Parts) -> bool:
    """
    Whether *function* has the normal form of a template of *kind*, with the names and the literal
    of *parts* standing for the placeholders they fill.
    """
    placeholders = {id(parts.decoder): 'DECODE'}
    nodes: dict[int, str] = {}
    if isinstance(parts.table, Binding):
        placeholders[id(parts.table)] = 'TABLE'
    else:
        nodes[id(parts.table)] = 'TABLE'
    if parts.cache is not None:
        placeholders[id(parts.cache)] = 'CACHE'
    return matches(model, function, kind.templates, placeholders, nodes)


def _accessor(
    effects: EffectModel,
    held: _Held,
    decoders: dict[int, _Decoder],
    tables: dict[tuple[int, int], _Table | None],
) -> _Accessor | None:
    """
    The accessor *held* is, when it is an accessor template over a decoder of *decoders* and a table
    holding strings. What a table holds is kept in *tables* by the identity of the kind reading it
    and of what stands for it, since every accessor of a kind reads the one table.
    """
    model = effects.model
    if (found := _parts(model, held.function)) is None:
        return None
    kind, parts = found
    if (decoder := decoders.get(id(parts.decoder))) is None:
        return None
    if not _is_accessor(model, held.function, kind, parts):
        return None
    if not kind.called(model, held.names):
        return None
    if (key := (id(kind), id(parts.table))) not in tables:
        tables[key] = kind.table(effects, parts.table)
    if (table := tables[key]) is None:
        return None
    return _Accessor(held, decoder, parts.decoder, table, parts.cache)


def _cache_confined(model: SemanticModel, cache: Binding) -> bool:
    """
    Whether nothing but an accessor keeping *cache* reads or writes it: every reference, a `with`
    body's included, lies in its declarator, in a write establishing its value, or in a function
    that is an accessor template over it. Such a function need not be held by a name: the
    moved-declaration setting hands an accessor to a function through a parameter.
    """
    declarator = cache.declarations[0].parent if len(cache.declarations) == 1 else None
    sites = model.binding_establishment_sites(cache) or []
    accessors: dict[int, bool] = {}
    for reference in [*model.references(cache), *model.dynamic_references(cache)]:
        if declarator is not None and reference.is_descendant_of(declarator):
            continue
        if any(reference is site or reference.is_descendant_of(site) for site in sites):
            continue
        function = reference.parent
        while function is not None and not isinstance(function, FUNCTION_NODES):
            function = function.parent
        if function is None:
            return False
        if (known := accessors.get(id(function))) is None:
            found = _parts(model, function)
            known = accessors[id(function)] = (
                found is not None
                and found[1].cache is cache
                and _is_accessor(model, function, *found)
                and found[0].called(model, model.function_names(function))
            )
        if not known:
            return False
    return True


def _decoded_calls(dominance: DominanceModel, accessor: _Accessor) -> Iterator[tuple[JsCallExpression, str]]:
    """
    Every call of *accessor* passing integer literals that say which encoded string of its table to
    decode, after the accessor, the decoder, the table and the cache are in place, with the string
    the call returns. A string that does not decode or starts with a byte order mark is left a call:
    the function turning the bytes into a string strips a byte order mark where the host has a
    `TextDecoder` and keeps it elsewhere.
    """
    model = dominance.model
    needed = [accessor.decoder_name, *accessor.stores()]
    for read in accessor.held.names.reads:
        if not isinstance(read, JsIdentifier):
            continue
        call = enclosing_operator(read)
        if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not read:
            continue
        numbers = [number for argument in call.arguments if (number := integer_literal(argument)) is not None]
        if len(numbers) != len(call.arguments) or (encoded := accessor.table.encoded(numbers)) is None:
            continue
        bindings = [model.resolve(read), *needed]
        if not all(dominance.binding_established_before(binding, call) for binding in bindings):
            continue
        try:
            decoded = _decode_base91(encoded, accessor.decoder.alphabet)
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded.startswith('\N{BYTE ORDER MARK}'):
            continue
        yield call, decoded


def _stands_in_a_list(definition: Node) -> bool:
    """
    Whether *definition* can be taken out of the tree without leaving a hole: a statement standing
    in a statement list, or a declarator of a declaration that does. One written under an `export`
    or a label stands in a slot of its own, which nothing may be left empty in.
    """
    statement = definition.parent if isinstance(definition, JsVariableDeclarator) else definition
    holder = None if statement is None else statement.parent
    return holder is not None and any(item is statement for item in statement_list_of(holder) or ())


def _remove_machinery(
    model: SemanticModel,
    accessors: list[_Accessor],
    replaced: list[Node],
    root: JsScript,
    keeps_the_end_value: bool,
) -> None:
    """
    Remove the accessors, then the decoders, then the tables and caches whose every reference, a
    `with` body's included, lies in a replaced call or in a definition removed with them, when
    `refinery.lib.scripts.js.deobfuscation.helpers.nothing_still_names` agrees for all of them. A
    name an importer reads stays, and so does a definition that does not stand in a statement list
    (`_stands_in_a_list`) or, where *keeps_the_end_value* asks for the value the script ends on, a
    statement assigning one that may set that value. Each decoder, table and cache is asked about
    once, however many accessors share it.
    """
    inside: set[int] = {id(node) for call in replaced for node in call.walk()}
    removed: dict[int, Node] = {}

    def remove(definition: Node | None, *bindings: Binding) -> None:
        if definition is None or id(definition) in removed:
            return
        if any(binding.exported for binding in bindings) or not _stands_in_a_list(definition):
            return
        if (
            keeps_the_end_value
            and isinstance(definition, JsExpressionStatement)
            and reaches_script_completion(definition, root)
        ):
            return
        own = {id(node) for node in definition.walk()}
        for binding in bindings:
            for reference in [*model.references(binding), *model.dynamic_references(binding)]:
                if id(reference) not in inside and id(reference) not in own:
                    return
        removed[id(definition)] = definition
        inside.update(own)

    for accessor in accessors:
        remove(accessor.held.definition, *accessor.held.names.bindings)
    decoders = {id(accessor.decoder.held.function): accessor.decoder.held for accessor in accessors}
    for held in decoders.values():
        remove(held.definition, *held.names.bindings)
    stores = {id(store): store for accessor in accessors for store in accessor.stores()}
    for store in stores.values():
        declarator = store.declarations[0].parent if len(store.declarations) == 1 else None
        if isinstance(declarator, JsVariableDeclarator):
            remove(declarator, store)
    if not removed or not nothing_still_names(model, [*removed.values(), *replaced]):
        return
    for node in removed.values():
        if isinstance(node, JsVariableDeclarator):
            remove_declarator(node)
        else:
            _remove_from_parent(node)


class JsBase91StringDecoder(ScriptLevelTransformer):
    """
    Replace every call of a base91 string accessor the module describes by the string it returns,
    and remove the machinery nothing names any longer.
    """

    def _process_script(self, node: JsScript):
        cache = model_cache(self, node)
        model = cache.model
        held = list(_held_functions(model, node))
        decoders: dict[int, _Decoder] = {}
        for item in held:
            if (decoder := _decoder(model, item)) is not None:
                decoders.update((id(name), decoder) for name in item.names.bindings)
        if not decoders:
            return
        accessors: list[_Accessor] = []
        tables: dict[tuple[int, int], _Table | None] = {}
        confined: dict[int, bool] = {}
        replacements: list[tuple[JsCallExpression, str]] = []
        for item in held:
            if id(item.names.own) in decoders:
                continue
            if (accessor := _accessor(cache.effects, item, decoders, tables)) is None:
                continue
            accessors.append(accessor)
            if accessor.cache is not None:
                if (known := confined.get(id(accessor.cache))) is None:
                    known = confined[id(accessor.cache)] = _cache_confined(model, accessor.cache)
                if not known:
                    continue
            replacements.extend(_decoded_calls(cache.dominance, accessor))
        if not replacements:
            return
        for call, decoded in replacements:
            _replace_in_parent(call, make_string_literal(decoded))
        replaced: list[Node] = [call for call, _ in replacements]
        _remove_machinery(model, accessors, replaced, node, preserves_script_return(self.options))
        self.mark_changed()


def _index_call(
    effects: EffectModel,
    reference: Node,
) -> tuple[JsCallExpression, JsNumericLiteral] | None:
    """
    The call *reference* is the callee of, passing one number literal as its only argument, and that
    literal: `f(7)`, `f.call(undefined, 7)` or `f.apply(undefined, [7])`, the receiver `undefined`
    spelled as the name or as `void` of a number. The last two only where the program writes no
    member of `Function.prototype`, and neither through an optional chain, which calls nothing where
    `f` holds no function yet. Code the model cannot read is not asked about, for the reason the
    table is not (`_table_value`): every script the obfuscator writes reads the global object
    through a reflective surface of its own.
    """
    model = effects.model
    parent = enclosing_operator(reference)
    if isinstance(parent, JsCallExpression) and strip_parens(parent.callee) is reference:
        arguments = parent.arguments
        if len(arguments) == 1 and isinstance(number := arguments[0], JsNumericLiteral):
            return parent, number
        return None
    if not isinstance(parent, JsMemberExpression) or strip_parens(parent.object) is not reference:
        return None
    method = static_property_key(parent)
    call = enclosing_operator(parent)
    if method not in ('call', 'apply') or not isinstance(call, JsCallExpression):
        return None
    if strip_parens(call.callee) is not parent or len(call.arguments) != 2:
        return None
    if parent.optional or call.optional:
        return None
    if not effects.prototype_name_unwritten(JsFunctionExpression):
        return None
    receiver, argument = call.arguments
    known, value = denoted_value(receiver, model)
    if not known or value is not None:
        return None
    argument = strip_parens(argument)
    if method == 'apply':
        if not isinstance(argument, JsArrayExpression) or len(argument.elements) != 1:
            return None
        argument = argument.elements[0]
    if not isinstance(argument, JsNumericLiteral):
        return None
    return call, argument


def _written_only_inside(
    model: SemanticModel,
    binding: Binding,
    function: Node,
    *,
    besides: Node | None = None,
) -> bool:
    """
    Whether every write of *binding* lies in *function* or in *besides*, and nothing writes it in a
    way no reference records.
    """
    if binding.dynamic_refs or binding.has_indefinite_write or binding.exported:
        return False
    if binding.reachable_through_a_handed_object:
        return False
    if model.reflection_can_reach_from_its_scope(binding):
        return False
    for write in binding.writes:
        if besides is not None and (write is besides or write.is_descendant_of(besides)):
            continue
        if not write.is_descendant_of(function):
            return False
    return True


class _Decoys(NamedTuple):
    """
    The decoy branches of a decoyed accessor, and each call of it written through `call` or `apply`
    with the name it calls and the number it passes.
    """
    decoys: list[Statement]
    calls: list[tuple[JsCallExpression, JsIdentifier, JsNumericLiteral]]


def _decoys(effects: EffectModel, function: JsFunctionNode) -> _Decoys | None:
    """
    The decoys of *function* and its calls written through `call` or `apply`, when it is the decoyed
    accessor and no decoy can run: the name holding it holds nothing but what a decoy stores, the
    name of its decoder holds a function declared in the scope it names and nothing but what a decoy
    stores, and every reference of the accessor outside it passes one number as its only argument.
    """
    model = effects.model
    if not isinstance(function, (JsArrowFunctionExpression, JsFunctionExpression)):
        return None
    declarator = enclosing_operator(function)
    if not isinstance(declarator, JsVariableDeclarator):
        return None
    if strip_parens(declarator.init) is not function:
        return None
    names = model.function_names(function)
    if names is None or len(names.own.declarations) != 1:
        return None
    holder = names.own
    if (parts := _defaulted_parts(model, function)) is None or parts.cache is None:
        return None
    decoder = parts.decoder
    assert isinstance(parts.table, Binding)
    placeholders = {
        id(holder): 'ACCESSOR',
        id(decoder): 'DECODE',
        id(parts.cache): 'CACHE',
        id(parts.table): 'TABLE',
    }
    if (found := match(model, function, (_DECOYED_ACCESSOR,), placeholders)) is None:
        return None
    _, fit = found
    if len(decoder.declarations) != 1:
        return None
    if not isinstance(decoder.declarations[0].parent, JsFunctionDeclaration):
        return None
    if model.binding_of(decoder.declarations[0]) is not decoder:
        return None
    if not _written_only_inside(model, decoder, function):
        return None
    if not _written_only_inside(model, holder, function, besides=declarator):
        return None
    calls: list[tuple[JsCallExpression, JsIdentifier, JsNumericLiteral]] = []
    for reference in holder.reads:
        if reference.is_descendant_of(function):
            continue
        if not isinstance(reference, JsIdentifier):
            return None
        if (indexed := _index_call(effects, reference)) is None:
            return None
        call, number = indexed
        if strip_parens(call.callee) is not reference:
            calls.append((call, reference, number))
    statements = statement_list_of(function) or []
    if len(statements) != len(fit) or (shuffled := _DECOYED_ACCESSOR.shuffled) is None:
        return None
    always = shuffled.start + shuffled.kept
    decoys = [statement for statement, position in zip(statements, fit) if position >= always]
    if not decoys and not calls:
        return None
    return _Decoys(decoys, calls)


class JsBase91AccessorDecoys(ScriptLevelTransformer):
    """
    Remove the decoy branches of a defaulted base91 accessor that no call runs, and write each call
    of it through `call` or `apply` as a plain call.
    """

    def _process_script(self, node: JsScript):
        candidates = [
            function for function in node.walk()
            if isinstance(function, (JsArrowFunctionExpression, JsFunctionExpression))
            and len(function.params) == 5
        ]
        if not candidates:
            return
        effects = model_cache(self, node).effects
        found: list[_Decoys] = []
        for function in candidates:
            if (decoys := _decoys(effects, function)) is not None:
                found.append(decoys)
        if not found:
            return
        for item in found:
            for statement in item.decoys:
                _remove_from_parent(statement)
            for call, callee, argument in item.calls:
                plain = JsCallExpression(
                    callee=JsIdentifier(name=callee.name),
                    arguments=[argument],
                )
                _replace_in_parent(call, plain)
        self.mark_changed()
