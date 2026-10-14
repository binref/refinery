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

from refinery.lib.scripts import Node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
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
from refinery.lib.scripts.js.deobfuscation.templates import Template, matches
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsAssignmentExpression,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsVariableDeclarator,
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


class _Held(NamedTuple):
    """
    A function a name holds as its one value, and the node installing it there, which goes when the
    function goes: the declaration, the declarator, or the statement assigning it.
    """
    binding: Binding
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
    table and cache, and the reader of what its table holds.
    """
    templates: tuple[Template, ...]
    parts: Callable[[SemanticModel, JsFunctionNode], _Parts | None]
    table: Callable[[EffectModel, Binding | JsStringLiteral], _Table | None]


class _Accessor(NamedTuple):
    """
    An accessor, the decoder it calls, the table it reads, and the cache it keeps the decoded
    strings in, if it keeps any.
    """
    held: _Held
    decoder: _Decoder
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
    Every function that the one name invoking it holds as its only value.
    """
    for node in root.walk():
        if not isinstance(node, FUNCTION_NODES):
            continue
        binding = model.invocation_binding(node)
        if binding is None or len(binding.declarations) != 1:
            continue
        if strip_parens(model.singular_value(binding)) is not node:
            continue
        yield _Held(binding, node, _definition(node))


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
    if model.reflection_can_reach(held.binding, module_scope=True):
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


def _table_value(effects: EffectModel, table: Binding | JsStringLiteral) -> tuple[bool, object]:
    """
    What *table* denotes as `refinery.lib.scripts.js.deobfuscation.helpers.denoted_value` reads it:
    the string a literal spells, or the one value the name *table* holds wherever it is in place,
    unless code the model cannot read may reach that name.

    The table is machinery under a name the obfuscator makes up, like the decoder, the accessor and
    the cache. A constant of the program is also asked whether a host or code running in the global
    scope may reach it (`refinery.lib.scripts.js.deobfuscation.helpers.binding_constant`), while
    the table is asked only about code in its own scope the model cannot read: a direct `eval`
    there, or a span the parser could not read, which is what
    `refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_can_reach` answers for a name
    scoped to the file. A script the obfuscator writes stores on the global object under keys this
    very table holds, and the wider question would refuse the table of every script.
    """
    model = effects.model
    if isinstance(table, JsStringLiteral):
        return denoted_value(table, model)
    if model.reflection_can_reach(table, module_scope=True):
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
    _Kind(_CACHING_ACCESSOR, _caching_parts, _string_array),
    _Kind(_SLICING_ACCESSOR, _slicing_parts, _long_string),
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
    if (key := (id(kind), id(parts.table))) not in tables:
        tables[key] = kind.table(effects, parts.table)
    if (table := tables[key]) is None:
        return None
    return _Accessor(held, decoder, table, parts.cache)


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
    bindings = [accessor.held.binding, accessor.decoder.held.binding, *accessor.stores()]
    for read in accessor.held.binding.reads:
        if not isinstance(read, JsIdentifier):
            continue
        call = enclosing_operator(read)
        if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not read:
            continue
        numbers = [number for argument in call.arguments if (number := integer_literal(argument)) is not None]
        if len(numbers) != len(call.arguments) or (encoded := accessor.table.encoded(numbers)) is None:
            continue
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

    def remove(definition: Node | None, binding: Binding) -> None:
        if definition is None or id(definition) in removed:
            return
        if binding.exported or not _stands_in_a_list(definition):
            return
        if (
            keeps_the_end_value
            and isinstance(definition, JsExpressionStatement)
            and reaches_script_completion(definition, root)
        ):
            return
        own = {id(node) for node in definition.walk()}
        for reference in [*model.references(binding), *model.dynamic_references(binding)]:
            if id(reference) not in inside and id(reference) not in own:
                return
        removed[id(definition)] = definition
        inside.update(own)

    for accessor in accessors:
        remove(accessor.held.definition, accessor.held.binding)
    decoders = {id(accessor.decoder.held.binding): accessor.decoder.held for accessor in accessors}
    for held in decoders.values():
        remove(held.definition, held.binding)
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
                decoders[id(item.binding)] = decoder
        if not decoders:
            return
        accessors: list[_Accessor] = []
        tables: dict[tuple[int, int], _Table | None] = {}
        confined: dict[int, bool] = {}
        replacements: list[tuple[JsCallExpression, str]] = []
        for item in held:
            if id(item.binding) in decoders:
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
