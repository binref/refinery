"""
A loader keeping the functions of a program as text decodes and builds each one the first time it is
asked for, from a map of encoded sources, and hands out the one it built every time after:

    var MM = {key: '<base64 source>', ...};
    var e = {};
    function c(M) {
      if (M in e == false) {
        if (M in MM != true) { throw new Error(''); }
        const I = atob(MM[M]);
        e[M] = new Function(I)();
      }
      return e[M];
    }

This transformer decodes every entry and writes each source as a function at the top of the
script, the map then holds the functions, and the construction becomes a call of the entry:

    const __inlined_fn_1a2b3c4d = function () { <decoded source> };
    ...
    var MM = {key: __inlined_fn_1a2b3c4d, ...};
    ...
        e[M] = (0, MM[M])();

The rewrite is exact because of where the function is written. A function a `Function` construction
builds is sloppy code whose scope is the global scope, wherever the construction stands, and a
function written at the top of a sloppy classic script is the same: every name it uses, including a
name some text it evaluates spells only at runtime, resolves where it did, so nothing about the
decoded source has to be read to know that. The call is made without a receiver, which gives a
sloppy function the global object as `this`, as the construction's call did. The name holding the
function is a `const`, a binding of the global scope that is no property of the global object, so
code listing the properties of that object sees nothing new; it is a name no text of the file
spells. The text and the name the function owns are recorded as those of the function the
construction builds, so a fold reading either reads what the program reads.

The cache, the two tests and every call of the getter stay as they are, so each entry is still built
once, at the call that first asks for it, and handed out as the same value afterwards. Everything is
decided before the first edit, and a map any of whose entries cannot move stays whole.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple

from refinery.lib.crypto.murmur import mmh32
from refinery.lib.scripts import BodyEdit, Node, _replace_in_parent, set_child
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import (
    BindingKind,
    enclosing_operator,
    is_invocation_target,
    is_member_write_target,
)
from refinery.lib.scripts.js.analysis.tampering import denotes_function_intrinsic
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    fresh_name,
    remove_declarator,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    forgiving_base64_decode,
    registered_builtin,
)
from refinery.lib.scripts.js.deobfuscation.reflection import _parse_construction_function
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsTemplateLiteral,
    JsThrowStatement,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
    object_sets_prototype,
    strip_parens,
)
from refinery.lib.scripts.js.strict import declares_use_strict, directive_prologue

if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel

_CODECS: dict[str, Callable[[str], str | None]] = {
    'atob': forgiving_base64_decode,
}
"""
The functions a map's entries may be decoded with, by the global name the construction calls, each
answering what that global answers for a string, or `None` where it throws on it.
"""

_FUNCTION = 'Function'
_OBJECT = 'Object'
_PROTO = '__proto__'


@dataclass
class _Site:
    """
    A construction that builds an entry of a map: the call that runs what it builds, the
    construction, the decode it reads its text from, the read of the map that decode is handed, and
    the declarator the text is held in on the way, where there is one.
    """
    invocation: JsCallExpression
    construction: JsNewExpression | JsCallExpression
    decode: JsCallExpression
    read: JsMemberExpression
    holder: JsVariableDeclarator | None

    @property
    def codec(self) -> str:
        codec = strip_parens(self.decode.callee)
        assert isinstance(codec, JsIdentifier)
        return codec.name

    @property
    def key(self) -> JsIdentifier:
        key = strip_parens(self.read.property)
        assert isinstance(key, JsIdentifier)
        return key

    @property
    def statement(self) -> Node:
        """
        The statement the site runs in: the declaration holding the text, or the construction's own.
        """
        node: Node = self.invocation if self.holder is None else self.holder
        while not isinstance(node.parent, (JsBlockStatement, JsScript)):
            assert node.parent is not None
            node = node.parent
        return node


@dataclass
class _Entry:
    """
    An entry of a map that can move out of it: its property, its key, the source it decodes to, and
    the function a construction builds from that source.
    """
    prop: JsProperty
    key: str
    text: str
    function: JsFunctionExpression


_NAME_PREFIX = '__inlined_fn_'

_BUILT_FUNCTION_NAME = 'anonymous'
"""
The `name` the language gives a function a `Function` construction builds, which is also the name
its text spells.
"""


def _built_function_text(parameters: str, body: str) -> str:
    """
    The text `Function.prototype.toString` answers for the function a `Function` construction
    builds from the source of its *parameters* and of its *body*: the language writes both inside
    the source of a function named `anonymous`, each ended with a line feed.
    """
    return F'function {_BUILT_FUNCTION_NAME}({parameters}\n) {{\n{body}\n}}'


def _built_function(construction: Node, text: str) -> JsFunctionExpression | None:
    """
    The function the construction *construction* builds from the decoded source *text*, as a
    function expression that answers what that function answers for its text and its name, or
    `None` where the source is no function body the construction would build: it does not parse,
    or the language would refuse it before running it
    (`refinery.lib.scripts.js.deobfuscation.reflection._parse_construction_function`), which the
    construction raises as an error at the call that asks for the entry and the file would raise
    before anything ran.
    """
    if (parsed := _parse_construction_function(construction, text)) is None:
        return None
    _, function = parsed
    if function.body is None:
        return None
    function.parent = None
    function.source_text = _built_function_text('', text)
    function.source_name = _BUILT_FUNCTION_NAME
    return function


def _inlined_name(text: str) -> str:
    """
    The name a function decoded from *text* is first offered: the prefix and the MurmurHash3 of the
    text in eight hexadecimal digits, so that the same source has the same name in every file.
    """
    return F'{_NAME_PREFIX}{mmh32(text.encode("utf8")):08x}'


class _Membership(NamedTuple):
    """
    The two names of a test `key in container`.
    """
    key: JsIdentifier
    container: JsIdentifier


def _is_boolean(node: Node | None, value: bool) -> bool:
    node = strip_parens(node)
    return isinstance(node, JsBooleanLiteral) and node.value is value


def _membership(node: Node | None) -> _Membership | None:
    """
    The names of the test `key in container` *node* is, where both operands are names.
    """
    node = strip_parens(node)
    if not isinstance(node, JsBinaryExpression) or node.operator != 'in':
        return None
    key = strip_parens(node.left)
    container = strip_parens(node.right)
    if not isinstance(key, JsIdentifier) or not isinstance(container, JsIdentifier):
        return None
    return _Membership(key, container)


def _absence(node: Node | None) -> _Membership | None:
    """
    The names of the membership test in a test that is true exactly where the key is not in the
    container: `!(key in container)`, `key in container == false` and `key in container != true`,
    strictly or not.
    """
    node = strip_parens(node)
    if isinstance(node, JsUnaryExpression) and node.operator == '!':
        return _membership(node.operand)
    if not isinstance(node, JsBinaryExpression):
        return None
    if node.operator in ('==', '===') and _is_boolean(node.right, False):
        return _membership(node.left)
    if node.operator in ('!=', '!==') and _is_boolean(node.right, True):
        return _membership(node.left)
    return None


def _throws(statement: Node | None) -> bool:
    """
    Whether *statement* is a `throw`, or a block holding one and nothing else.
    """
    if isinstance(statement, JsBlockStatement):
        return len(statement.body) == 1 and isinstance(statement.body[0], JsThrowStatement)
    return isinstance(statement, JsThrowStatement)


def _ancestors(node: Node) -> Iterator[tuple[Node, Node]]:
    """
    Each ancestor of *node*, innermost first, paired with its child on the way down to *node*.
    """
    child = node
    while (parent := child.parent) is not None:
        yield parent, child
        child = parent


def _entry_key(prop: JsProperty) -> str | None:
    """
    The key of *prop*, spelled as a name or as a string, computed or not.
    """
    key = prop.key
    if isinstance(key, JsStringLiteral):
        return key.value
    if isinstance(key, JsIdentifier) and not prop.computed:
        return key.name
    return None


def _fixed(model: SemanticModel, name: Node | None) -> Binding | None:
    """
    The binding the name *name* reads, where it holds one value wherever it is read: a parameter or
    a declaration that no reference writes and nothing outside the text can reach.
    """
    if not isinstance(name, JsIdentifier):
        return None
    binding = model.resolve(name)
    if (
        binding is None
        or binding.kind is BindingKind.IMPLICIT_GLOBAL
        or binding.writes
        or binding.indefinite_writes
        or binding.dynamic_refs
        or binding.written_at_entry
        or len(binding.declarations) != 1
        or model.reflection_can_reach(binding)
    ):
        return None
    return binding


def _held_once(model: SemanticModel, binding: Binding) -> JsObjectExpression | None:
    """
    The object literal *binding* holds for good: it is declared once with it, no reference writes
    it, nothing outside the text can reach it, and it is not exported.
    """
    if (
        binding.writes
        or binding.indefinite_writes
        or binding.dynamic_refs
        or binding.exported
        or len(binding.declarations) != 1
        or model.reflection_can_reach(binding)
    ):
        return None
    literal = model.declared_value(binding)
    if not isinstance(literal, JsObjectExpression) or object_sets_prototype(literal):
        return None
    return literal


class JsModuleMapUnwrapper(ScriptLevelTransformer):
    """
    Write every entry of a map of encoded function sources as a function at the top of the script,
    where the only thing the program does with the map is build its entries behind a test that the
    key is the map's own, and rewrite each such construction into a call of the entry. Where any of
    that cannot be done without changing what the program computes, the map stays whole.
    """

    def _process_script(self, node: JsScript) -> None:
        cache = model_cache(self, node)
        if not self._writes_at_the_top(cache.model, node):
            return
        for statement in list(node.walk()):
            if not isinstance(statement, JsVariableDeclaration) or len(statement.declarations) != 1:
                continue
            declarator = statement.declarations[0]
            if not isinstance(declarator, JsVariableDeclarator) or not isinstance(declarator.id, JsIdentifier):
                continue
            table = declarator.init
            if not isinstance(table, JsObjectExpression) or not table.properties:
                continue
            if not all(
                isinstance(prop, JsProperty) and isinstance(prop.value, JsStringLiteral)
                for prop in table.properties
            ):
                continue
            if self._unwrap(node, declarator.id, table):
                return

    @staticmethod
    def _writes_at_the_top(model: SemanticModel, root: JsScript) -> bool:
        """
        Whether a function written at the top of *root* has the global scope as its scope and runs
        as sloppy code, as one a `Function` construction builds does: the file is a classic
        script, whose top level is the global scope, and its text does not make it strict. The
        scope of a CommonJS file is the function its host wraps around the text, and an ES module
        is strict code with a scope of its own, so neither has such a place.
        """
        return model.file_kind is FileKind.script and not declares_use_strict(root)

    def _unwrap(self, root: JsScript, name: JsIdentifier, table: JsObjectExpression) -> bool:
        """
        Decide the whole rewrite of the map *table* on the tree as it stands, then make it in one
        go, and answer whether it was made. No model is asked anything after the first edit.
        """
        cache = model_cache(self, root)
        model = cache.model
        if (binding := model.binding_of(name)) is None or _held_once(model, binding) is not table:
            return False
        if not self._data_only(table):
            return False
        if (sites := self._sites(cache, binding)) is None:
            return False
        if (entries := self._entries(table, sites)) is None:
            return False
        names = self._choose_names(root, entries)
        declarations: list[Node] = []
        for entry in entries:
            set_child(entry.prop, 'value', JsIdentifier(name=names[entry.key]))
            declarations.append(JsVariableDeclaration(
                kind=JsVarKind.CONST,
                declarations=[JsVariableDeclarator(
                    id=JsIdentifier(name=names[entry.key]),
                    init=entry.function,
                )],
            ))
        for site in sites:
            _replace_in_parent(site.invocation, JsCallExpression(
                callee=JsSequenceExpression(expressions=[
                    JsNumericLiteral(value=0, raw='0'),
                    JsMemberExpression(
                        object=JsIdentifier(name=name.name),
                        property=JsIdentifier(name=site.key.name),
                        computed=True,
                    ),
                ]),
                arguments=list(site.invocation.arguments),
            ))
            if site.holder is not None:
                remove_declarator(site.holder)
        edit = BodyEdit(root, 'body')
        prologue = directive_prologue(root)
        if prologue:
            edit.splice(prologue[-1], [prologue[-1], *declarations])
        elif root.body:
            edit.splice(root.body[0], [*declarations, root.body[0]])
        edit.apply()
        self.mark_changed()
        return True

    @staticmethod
    def _data_only(table: JsObjectExpression) -> bool:
        """
        Whether every property of *table* is a plain data property holding a string, under a key
        the text spells that no other property of it repeats.
        """
        keys: set[str] = set()
        for prop in table.properties:
            if not isinstance(prop, JsProperty) or prop.kind is not JsPropertyKind.INIT:
                return False
            if prop.method or prop.shorthand:
                return False
            if (key := _entry_key(prop)) is None or key in keys:
                return False
            keys.add(key)
        return True

    def _sites(self, cache: ModelCache, binding: Binding) -> list[_Site] | None:
        """
        Every construction that builds an entry of the map *binding*, or `None` where some reference
        to the map is neither the read such a construction decodes nor a test whether a key is in
        the map, or where some site is not behind the tests `_guarded` reads.
        """
        model = cache.model
        sites: list[_Site] = []
        for reference in model.references(binding):
            if not isinstance(reference, JsIdentifier):
                return None
            outer = enclosing_operator(reference)
            if isinstance(outer, JsBinaryExpression):
                if outer.operator != 'in' or strip_parens(outer.right) is not reference:
                    return None
                continue
            if not isinstance(outer, JsMemberExpression) or strip_parens(outer.object) is not reference:
                return None
            if (site := self._site(cache, outer)) is None:
                return None
            if not self._guarded(model, site, binding):
                return None
            sites.append(site)
        if not sites or not self._runs_no_other_code(cache, sites):
            return None
        return sites

    def _site(self, cache: ModelCache, read: JsMemberExpression) -> _Site | None:
        """
        The construction the map read *read* is decoded for: the read under a fixed name is the one
        argument of a codec, whose result is the one argument of a construction of the `Function`
        intrinsic called in place, either as written or through a `const` declared right before the
        statement of the construction, which nothing else reads.
        """
        model = cache.model
        if not read.computed or read.optional or is_member_write_target(read):
            return None
        if _fixed(model, read.property) is None:
            return None
        decode = enclosing_operator(read)
        if (
            not isinstance(decode, JsCallExpression)
            or decode.optional
            or len(decode.arguments) != 1
            or strip_parens(decode.arguments[0]) is not read
            or not isinstance(codec := strip_parens(decode.callee), JsIdentifier)
            or codec.name not in _CODECS
        ):
            return None
        holder: JsVariableDeclarator | None = None
        argument: Node = decode
        outer = enclosing_operator(decode)
        if isinstance(outer, JsVariableDeclarator):
            if (held := self._held_text(model, outer)) is None:
                return None
            holder = outer
            argument = held
            outer = enclosing_operator(held)
        construction = outer
        if (
            not isinstance(construction, (JsNewExpression, JsCallExpression))
            or isinstance(construction, JsCallExpression) and construction.optional
            or len(construction.arguments) != 1
            or strip_parens(construction.arguments[0]) is not argument
        ):
            return None
        invocation = enclosing_operator(construction)
        if (
            not isinstance(invocation, JsCallExpression)
            or invocation.optional
            or strip_parens(invocation.callee) is not construction
        ):
            return None
        callee = strip_parens(construction.callee)
        if not isinstance(callee, JsIdentifier) or callee.name != _FUNCTION:
            return None
        if denotes_function_intrinsic(callee, model, cache.effects, cache.dominance) is not True:
            return None
        site = _Site(invocation, construction, decode, read, holder)
        if holder is not None and not self._holder_runs_right_before(site):
            return None
        if not self._codec_reaches_the_host(cache, codec):
            return None
        return site

    @staticmethod
    def _held_text(model: SemanticModel, holder: JsVariableDeclarator) -> JsIdentifier | None:
        """
        The one read of the `const` *holder* declares, where it holds the decoded text and nothing
        else reads it.
        """
        declaration = holder.parent
        if (
            not isinstance(declaration, JsVariableDeclaration)
            or declaration.kind is not JsVarKind.CONST
            or len(declaration.declarations) != 1
            or not isinstance(held := holder.id, JsIdentifier)
            or (binding := model.binding_of(held)) is None
            or binding.writes
            or binding.dynamic_refs
            or len(binding.reads) != 1
            or model.reflection_can_reach(binding)
        ):
            return None
        read = binding.reads[0]
        return read if isinstance(read, JsIdentifier) else None

    @staticmethod
    def _holder_runs_right_before(site: _Site) -> bool:
        """
        Whether the declaration holding the decoded text is the statement right before the one the
        construction stands in, in one list, so nothing runs between the decode and the build.
        """
        assert site.holder is not None
        declaration = site.holder.parent
        statement: Node = site.invocation
        while not isinstance(statement.parent, (JsBlockStatement, JsScript)):
            if statement.parent is None:
                return False
            statement = statement.parent
        if not isinstance(statement, JsExpressionStatement):
            return False
        holder_list = statement.parent
        if declaration is None or declaration.parent is not holder_list:
            return False
        assert isinstance(holder_list, (JsBlockStatement, JsScript))
        body = holder_list.body
        index = next(i for i, item in enumerate(body) if item is declaration)
        return index + 1 < len(body) and body[index + 1] is statement

    @staticmethod
    def _codec_reaches_the_host(cache: ModelCache, codec: JsIdentifier) -> bool:
        """
        Whether *codec* reads the decoding function the host has under that name: nothing binds it,
        no `with` body or direct `eval` may supply another, the host has it, and the program writes
        it nowhere. That nothing else replaces it, or `Function`, before a construction runs is
        `_runs_no_other_code`'s question.
        """
        model = cache.model
        if not model.bare_name_reaches_the_host(codec.name, codec):
            return False
        if registered_builtin((None, codec.name), model.environment) is None:
            return False
        return cache.effects.intrinsic_name_unwritten(codec) is not None

    @staticmethod
    def _runs_no_other_code(cache: ModelCache, sites: list[_Site]) -> bool:
        """
        Whether no code of the file may replace the codec or `Function` before a construction of
        *sites* runs: the program writes neither `Function` nor the key `__proto__` on `Object`, on
        which every cache test rests (`_guarded`); it holds no `with` statement; every point at
        which it may run code it does not spell is the `Function` read of one of *sites*; and no
        store under a key only the runtime knows may run before any of them. What the entries
        themselves run once built is not asked, since one may replace the codec before another
        entry is built only from a source the decode answers ahead of time, which is the residual
        the rewrite concedes.
        """
        model = cache.model
        effects = cache.effects
        if _FUNCTION in effects.intrinsic_writes.names:
            return False
        if effects.global_key_written(_OBJECT, _PROTO):
            return False
        if any(isinstance(node, JsWithStatement) for node in model.root.walk()):
            return False
        callees = {id(strip_parens(site.construction.callee)) for site in sites}
        if any(id(site) not in callees for site in model.opaque_reflection_sites()):
            return False
        if not model.has_opaque_global_write():
            return True
        return all(cache.builtins_intact_at(site.construction) for site in sites)

    def _guarded(self, model: SemanticModel, site: _Site, map_binding: Binding) -> bool:
        """
        Whether two tests in front of *site* make the key it reads the map's own: a test that the
        key is not in a cache object, whose consequent holds the site and begins with a test that
        the key is in the map, which throws where it is not. A key not in an object whose prototype
        is `Object.prototype` is no name the map inherits, since the map's prototype is that object
        too, and nothing runs between the two tests, so a key that passes both is the map's own,
        and stays its own until the site: no reference writes the map. The cache is read by
        `_cache_keeps_its_prototype`.
        """
        key_binding = model.resolve(site.key)
        anchor = site.statement
        for parent, child in _ancestors(anchor):
            if isinstance(parent, (JsFunctionDeclaration, JsFunctionExpression, JsScript)):
                return False
            if not isinstance(parent, JsIfStatement) or parent.consequent is not child:
                continue
            if parent.alternate is not None or (outer := _absence(parent.test)) is None:
                continue
            if model.resolve(outer.key) is not key_binding:
                continue
            cache_binding = model.resolve(outer.container)
            if cache_binding is None or cache_binding is map_binding:
                continue
            block = parent.consequent
            if not isinstance(block, JsBlockStatement) or not block.body:
                return False
            first = block.body[0]
            if not isinstance(first, JsIfStatement) or first.alternate is not None or not _throws(first.consequent):
                return False
            if (inner := _absence(first.test)) is None:
                return False
            if model.resolve(inner.key) is not key_binding or model.resolve(inner.container) is not map_binding:
                return False
            if not self._after_in_block(block, first, anchor):
                return False
            return self._cache_keeps_its_prototype(model, cache_binding)
        return False

    @staticmethod
    def _after_in_block(block: JsBlockStatement, first: Node, anchor: Node) -> bool:
        """
        Whether *anchor* is a statement of *block* after *first*, or stands in one through blocks
        alone.
        """
        cursor = anchor
        while (parent := cursor.parent) is not block:
            if not isinstance(parent, JsBlockStatement):
                return False
            cursor = parent
        body: list[Node] = list(block.body)
        return body.index(cursor) > body.index(first)

    def _cache_keeps_its_prototype(self, model: SemanticModel, binding: Binding) -> bool:
        """
        Whether the cache *binding* holds an object whose prototype is `Object.prototype` wherever
        it is read: it holds one object literal for good that sets no prototype (`_held_once`), and
        every reference to it tests whether a key is in it, reads a property of it without calling
        it, or stores a property of it under a key that cannot be `__proto__`, the one key whose
        store sets a prototype. A store under a computed key is admitted behind a test that the key
        is not in the cache: `__proto__` is a key every object with that prototype holds.
        """
        if _held_once(model, binding) is None:
            return False
        for reference in model.references(binding):
            if not isinstance(reference, JsIdentifier):
                return False
            outer = enclosing_operator(reference)
            if isinstance(outer, JsBinaryExpression):
                if outer.operator != 'in' or strip_parens(outer.right) is not reference:
                    return False
                continue
            if not isinstance(outer, JsMemberExpression) or strip_parens(outer.object) is not reference:
                return False
            if outer.optional or is_invocation_target(outer):
                return False
            if not is_member_write_target(outer):
                holder = enclosing_operator(outer)
                if isinstance(holder, JsUnaryExpression) and holder.operator == 'delete':
                    return False
                continue
            store = enclosing_operator(outer)
            if (
                not isinstance(store, JsAssignmentExpression)
                or store.operator != '='
                or strip_parens(store.left) is not outer
            ):
                return False
            key = strip_parens(outer.property)
            if not outer.computed:
                if not isinstance(key, JsIdentifier) or key.name == _PROTO:
                    return False
                continue
            if isinstance(key, JsStringLiteral):
                if key.value == _PROTO:
                    return False
                continue
            if (key_binding := _fixed(model, key)) is None:
                return False
            if not self._behind_an_absence_test(model, store, key_binding, binding):
                return False
        return True

    @staticmethod
    def _behind_an_absence_test(
        model: SemanticModel,
        store: Node,
        key: Binding,
        cache: Binding,
    ) -> bool:
        """
        Whether *store* runs only where the key *key* holds is not in the object *cache* holds: in
        the consequent of an `if` whose test is or conjoins such a test, or as the right operand of
        an `&&` whose left is or conjoins one, in the function the store stands in.
        """
        def tests_absence(test: Node | None) -> bool:
            test = strip_parens(test)
            if isinstance(test, JsLogicalExpression) and test.operator == '&&':
                return tests_absence(test.left) or tests_absence(test.right)
            if (absence := _absence(test)) is None:
                return False
            return model.resolve(absence.key) is key and model.resolve(absence.container) is cache

        for parent, child in _ancestors(store):
            if isinstance(parent, JsIfStatement) and parent.consequent is child:
                if tests_absence(parent.test):
                    return True
            elif isinstance(parent, JsLogicalExpression) and parent.operator == '&&' and parent.right is child:
                if tests_absence(parent.left):
                    return True
            elif isinstance(parent, (JsFunctionDeclaration, JsFunctionExpression, JsScript)):
                return False
        return False

    @staticmethod
    def _entries(table: JsObjectExpression, sites: list[_Site]) -> list[_Entry] | None:
        """
        Each entry of *table* as the function the constructions of *sites* build from it, or `None`
        where one builds none: the sites decode with more than one codec, an entry does not decode
        with theirs, or what it decodes to is no function body a construction builds
        (`_built_function`). Nothing else is asked of the decoded source, since the function is
        written where it runs as the construction's function does.
        """
        codecs = {site.codec for site in sites}
        if len(codecs) != 1:
            return None
        decode = _CODECS[codecs.pop()]
        construction = sites[0].construction
        entries: list[_Entry] = []
        for prop in table.properties:
            assert isinstance(prop, JsProperty) and isinstance(prop.value, JsStringLiteral)
            key = _entry_key(prop)
            encoded = prop.value.value
            if key is None or encoded is None or (text := decode(encoded)) is None:
                return None
            if (function := _built_function(construction, text)) is None:
                return None
            entries.append(_Entry(prop, key, text, function))
        return entries

    @staticmethod
    def _choose_names(root: JsScript, entries: list[_Entry]) -> dict[str, str]:
        """
        The name each function is written under, by key: the name its source is first offered
        (`_inlined_name`), with a numbered suffix where that name is taken. A name is taken where
        some text the file spells holds it, as a name, in a string or in a template, the decoded
        sources included, or where another of the functions has it: no binding of the file can then
        be that name, no use can read it instead of one, and no text the file cuts out of what it
        spells can name it.
        """
        spelled: list[str] = []
        for node in (root, *(entry.function for entry in entries)):
            for part in node.walk():
                if isinstance(part, JsIdentifier):
                    spelled.append(part.name)
                elif isinstance(part, JsStringLiteral) and part.value is not None:
                    spelled.append(part.value)
                elif isinstance(part, JsTemplateLiteral):
                    spelled.extend(quasi.value for quasi in part.quasis if quasi.value is not None)
        texts = '\0'.join(spelled)
        used: set[str] = set()
        chosen: dict[str, str] = {}

        def taken(name: str) -> bool:
            return name in used or name in texts

        for entry in entries:
            name = fresh_name(_inlined_name(entry.text), taken)
            chosen[entry.key] = name
            used.add(name)
        return chosen
