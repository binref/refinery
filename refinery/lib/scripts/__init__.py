"""
Minimal unified AST base for script parsers. Provides abstract node types shared
across language-specific parsers.
"""
from __future__ import annotations

import copy
import dataclasses
import enum
import io
import typing

from dataclasses import dataclass, field
from typing import Callable, Generator, Protocol, TypeVar
from weakref import WeakKeyDictionary


class Kind(enum.IntEnum):
    ChildNode = 1
    ChildList = 2
    TupleList = 3


_SKIP_FIELDS = frozenset(('offset', 'parent', 'leading_comments', 'errors'))

_child_fields_cache: dict[type, list[tuple[str, Kind]]] = {}

_value_fields_cache: dict[type, tuple[str, ...]] = {}


def _has_node_type(hint) -> bool:
    if isinstance(hint, type):
        return issubclass(hint, Node)
    return any(_has_node_type(a) for a in typing.get_args(hint))


def _classify_fields(node_type: type[Node]) -> list[tuple[str, Kind]]:
    try:
        return _child_fields_cache[node_type]
    except KeyError:
        pass
    result: list[tuple[str, Kind]] = []
    try:
        hints = typing.get_type_hints(node_type)
    except Exception:
        _child_fields_cache[node_type] = result
        return result
    for f in dataclasses.fields(node_type):
        if f.name in _SKIP_FIELDS:
            continue
        hint = hints.get(f.name)
        if hint is None:
            continue
        origin = typing.get_origin(hint)
        if origin is list:
            args = typing.get_args(hint)
            if not args:
                continue
            inner = args[0]
            inner_origin = typing.get_origin(inner)
            if inner_origin is tuple:
                inner_args = typing.get_args(inner)
                if any(_has_node_type(a) for a in inner_args):
                    result.append((f.name, Kind.TupleList))
            elif _has_node_type(inner):
                result.append((f.name, Kind.ChildList))
        elif _has_node_type(hint):
            result.append((f.name, Kind.ChildNode))
    _child_fields_cache[node_type] = result
    return result


def _compute_children(node: Node) -> tuple[Node, ...]:
    result: list[Node] = []
    for name, kind in _classify_fields(type(node)):
        field = getattr(node, name)
        if kind == Kind.ChildNode:
            if isinstance(field, Node):
                result.append(field)
        elif kind == Kind.ChildList:
            for item in field:
                if isinstance(item, Node):
                    result.append(item)
        elif kind == Kind.TupleList:
            for item in field:
                for elem in item:
                    if isinstance(elem, Node):
                        result.append(elem)
    return tuple(result)


def child_list_fields(node: Node) -> list[tuple[str, list]]:
    """
    The child-list fields of `node`, as name and list pairs. A caller that wants to know where a
    tree branches into a variable number of children — how many arguments a call has, how many
    clauses an `if` has — asks here rather than matching on node types, so a node class added later
    is covered without the caller changing.
    """
    return [
        (name, getattr(node, name))
        for name, kind in _classify_fields(type(node))
        if kind in (Kind.ChildList, Kind.TupleList)
    ]


def _value_fields(node_type: type[Node]) -> tuple[str, ...]:
    try:
        return _value_fields_cache[node_type]
    except KeyError:
        pass
    skip = _SKIP_FIELDS | node_type.spelling_fields
    result = tuple(f.name for f in dataclasses.fields(node_type) if f.name not in skip)
    _value_fields_cache[node_type] = result
    return result


#: How often `canonical` follows `Node.canonical_form` before it concludes that the identifications
#: a model declares are cyclic. A parenthesis around a parenthesis is two steps, and the shapes that
#: chain at all are wrappers around wrappers, so the bound is never approached by a real tree.
_IDENTIFICATION_LIMIT = 64


def _canonical_value(value):
    if isinstance(value, Node):
        return canonical(value)
    if isinstance(value, enum.Enum):
        return (enum.Enum, type(value).__name__, value.name, value.value)
    if isinstance(value, (list, tuple)):
        return tuple(_canonical_value(item) for item in value)
    return value


def canonical(node: Node):
    """
    A hashable value that identifies the *program* a node spells, so that two trees compare equal
    exactly when they mean the same thing. This is what makes "the parser and the synthesizer are
    inverses" a checkable statement: a synthesizer is faithful when `canonical(parse(synth(T)))`
    equals `canonical(T)` for every well-formed `T`.

    Three things are deliberately compared away, each declared by the model rather than known here:
    the bookkeeping fields in `_SKIP_FIELDS`, which record where a node came from; the fields a node
    declares as its `spelling`, which record how a value was written; and the identifications a node
    makes through `Node.canonical_form`. Everything else is compared, including scalars such as an
    operator string. Enumerations compare by name as well as value, because an `IntEnum` member is
    equal to the integer it wraps and would otherwise collide with an unrelated field holding it.
    """
    for _ in range(_IDENTIFICATION_LIMIT):
        form = node.canonical_form()
        if form is None:
            break
        node = form
    else:
        raise RecursionError(F'cyclic canonical form at {type(node).__name__}')
    return (
        type(node).canonical_type,
        *(_canonical_value(getattr(node, name)) for name in _value_fields(type(node))),
    )


def is_well_formed(root: Node) -> bool:
    """
    Whether every node in the tree at `root` spells something, which is the domain over which
    `canonical` states a fidelity law. A tree containing a node that `Node.has_spelling` rejects
    cannot be printed at all, and one containing an `unparsed` node prints source that no parser
    agreed to read, so re-reading it yields whatever the recovery happens to make of the text.
    Neither says anything about whether a synthesizer is faithful.
    """
    return all(node.has_spelling() and not node.unparsed for node in root.walk())


@dataclass(repr=False, eq=False)
class Node:
    """
    Base class for all AST nodes.

    A subclass declares how it relates to the program it spells using class keywords:

        class Ps1IntegerLiteral(Expression, spelling='raw'):
            ...

    - `spelling` names the fields that record *how* a value was written rather than *what* it is.
      `canonical` compares them away, so two nodes that spell the same value differently are the
      same program. Declarations accumulate down the hierarchy.
    - `unparsed` marks a node that stands for source text no parser understood. Such a node prints
      text that reads back as arbitrary other nodes, so it is excluded from `is_well_formed`.
    - `identity` names another node class this one is the same program as, for two classes that
      differ only in how the source spelled them — a here-string and a quoted string hold the same
      value. The two must carry the same value fields, since `canonical` then compares them
      field by field. Where an identification instead needs to look at the instance, because it
      holds only for some values, override `canonical_form` instead.

    Two further facts are per-instance rather than per-class and so are methods: `has_spelling`
    reports whether this node can be printed at all, and `canonical_form` reports the node this one
    is identified with when comparing programs.
    """
    offset: int = -1
    parent: Node | None = field(default=None, compare=False)
    leading_comments: list[str] = field(default_factory=list, compare=False)

    spelling_fields: typing.ClassVar[frozenset[str]] = frozenset()
    unparsed: typing.ClassVar[bool] = False
    canonical_type: typing.ClassVar[str] = 'Node'

    @classmethod
    def __init_subclass__(
        cls,
        spelling: str | typing.Iterable[str] = (),
        unparsed: bool = False,
        identity: type[Node] | None = None,
        **kwargs,
    ):
        super().__init_subclass__(**kwargs)
        if isinstance(spelling, str):
            spelling = (spelling,)
        inherited = frozenset()
        for base in cls.__bases__:
            inherited |= getattr(base, 'spelling_fields', frozenset())
        cls.spelling_fields = inherited | frozenset(spelling)
        cls.canonical_type = cls.__name__ if identity is None else identity.canonical_type
        if unparsed:
            cls.unparsed = True

    def __post_init__(self):
        for c in _compute_children(self):
            self._adopt(c)

    def has_spelling(self) -> bool:
        """
        Whether this node can be written as source at all. A node for which this is false has no
        spelling in the language, so a synthesizer cannot print it and a parser must never build
        it: `,` is not a PowerShell expression, and neither is a `do` loop with no condition. The
        synthesizer refuses such a node rather than printing something else, because printing an
        approximation of a node that cannot exist is the silent corruption this predicate exists to
        prevent.
        """
        return True

    def canonical_form(self) -> Node | None:
        """
        The node this one is identified with when comparing programs, or `None` when it stands for
        itself. Two shapes are identified: a *transparent wrapper* that spells nothing of its own,
        such as a parenthesis around an expression, and a *deliberate normalization* between two
        spellings of one value, such as a here-string and the quoted string holding the same text.

        `canonical` applies this repeatedly, so a form may itself have a form.
        """
        return None

    def children(self) -> tuple[Node, ...]:
        return _compute_children(self)

    def walk(self) -> Generator[Node, None, None]:
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(_compute_children(node))

    def walk_in_order(self) -> Generator[Node, None, None]:
        """
        Pre-order left-to-right traversal that preserves source order:
        The regular `Node.walk` method uses a LIFO stack which reverses child
        order; this variant pushes children in reverse so that the first child is popped first.
        """
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(_compute_children(node)))

    def is_descendant_of(self, ancestor: Node) -> bool:
        cursor = self.parent
        while cursor is not None:
            if cursor is ancestor:
                return True
            cursor = cursor.parent
        return False

    def _adopt(self, *nodes: Node | None):
        for node in nodes:
            if node is not None:
                node.parent = self

    def __repr__(self):
        name = type(self).__name__
        return F'{name}@{self.offset}'


class Expression(Node):
    """
    Abstract base for all expression nodes.
    """
    pass


class Statement(Node):
    """
    Abstract base for all statement nodes.
    """
    pass


@dataclass(repr=False, eq=False)
class Block(Node):
    """
    Ordered sequence of statements.
    """
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Script(Node):
    """
    Top-level node representing an entire script.
    """
    body: list[Statement] = field(default_factory=list)


class Visitor:
    """
    Dispatch-based tree walker. Subclasses define visit_ClassName methods;
    unhandled nodes fall through to generic_visit.
    """

    def __init__(self):
        self._dispatch: dict[type[Node], Callable[[Node], Node | None]] = {}

    def visit(self, node: Node) -> Node | None:
        t = type(node)
        try:
            handler = self._dispatch[t]
        except KeyError:
            handler = getattr(self, F'visit_{t.__name__}', self.generic_visit)
            self._dispatch[t] = handler
        return handler(node)

    def generic_visit(self, node: Node) -> Node | None:
        for child in node.children():
            self.visit(child)


class AnalysisCache(Protocol):
    """
    The minimal surface the transformer base needs from a per-run analysis cache: a hook to drop its
    memoized analyses when the tree changes. A concrete cache adds the model accessors its consumers
    use; see `refinery.lib.scripts.modelcache.ModelCacheBase` and its per-language subclasses.
    """
    def invalidate(self) -> None:
        ...


class Transformer(Visitor):
    """
    In-place tree rewriter. Each visit method may return a replacement node
    or `None` to keep the original. Tracks whether any transformation was applied
    via the `changed` flag.

    When a `models` cache is attached by the pipeline, setting `changed` truthy invalidates it, so a
    transform that mutates the tree never leaves a stale model behind for the next consumer.
    """

    self_converging: bool = False

    def __init__(self):
        super().__init__()
        self._changed = False
        self.models: AnalysisCache | None = None
        self.options: object | None = None

    @property
    def changed(self) -> bool:
        return self._changed

    @changed.setter
    def changed(self, value: bool):
        self._changed = value
        if value and self.models is not None:
            self.models.invalidate()

    def mark_changed(self):
        self.changed = True

    def generic_visit(self, node: Node):
        for field_name, kind in _classify_fields(type(node)):
            if kind == Kind.ChildNode:
                value = getattr(node, field_name)
                if isinstance(value, Node):
                    replacement = self.visit(value)
                    if replacement is not None:
                        set_child(node, field_name, replacement)
                        self.mark_changed()
            elif kind == Kind.ChildList:
                items = getattr(node, field_name)
                new_list = None
                for idx, item in enumerate(items):
                    if isinstance(item, Node):
                        replacement = self.visit(item)
                        if replacement is not None:
                            if new_list is None:
                                new_list = list(items[:idx])
                            new_list.append(replacement)
                            continue
                    if new_list is not None:
                        new_list.append(item)
                if new_list is not None:
                    set_child_list(node, field_name, new_list)
                    self.mark_changed()
            elif kind == Kind.TupleList:
                items = getattr(node, field_name)
                new_list = None
                for idx, item in enumerate(items):
                    new_tuple = []
                    tuple_changed = False
                    for elem in item:
                        if isinstance(elem, Node):
                            replacement = self.visit(elem)
                            if replacement is not None:
                                new_tuple.append(replacement)
                                tuple_changed = True
                            else:
                                new_tuple.append(elem)
                        else:
                            new_tuple.append(elem)
                    if tuple_changed:
                        if new_list is None:
                            new_list = list(items[:idx])
                        new_list.append(tuple(new_tuple))
                    elif new_list is not None:
                        new_list.append(item)
                if new_list is not None:
                    set_child_list(node, field_name, new_list)
                    self.mark_changed()
        return None


_tree_versions: WeakKeyDictionary[Node, int] = WeakKeyDictionary()


def tree_version(root: Node) -> int:
    """
    The AST-mutation counter for the tree rooted at *root*. Every mutation made through
    `_replace_in_parent`, `_remove_from_parent`, `set_child`, `set_child_list`, `set_value` or
    `BodyEdit` — and so through `Transformer.generic_visit`, which installs every `visit_X`
    replacement through `set_child` and `set_child_list` — advances the counter of the one tree it
    mutates, found by walking from the mutation site up to its topmost ancestor, and leaves every
    other tree untouched.
    `refinery.lib.scripts.modelcache.ModelCacheBase` records the value
    its own root stood at when its models were built and rebuilds once that root's counter moves,
    so a transform observes models consistent with the current tree even when an earlier mutation
    in the same pass has not yet been announced through `Transformer.changed`. Mutations to
    unrelated trees — parsed snippets or clones probed during analysis — never advance this root's
    counter and so never force a needless rebuild.
    """
    return _tree_versions.get(root, 0)


def tree_root(node: Node) -> Node:
    """
    The topmost ancestor of *node*, which is the tree it belongs to. Both the mutation counter and
    the analysis caches are keyed on this rather than on whatever node a caller happens to hold: a
    model built over a subtree answers questions about that subtree alone, and a whole-script fact
    derived from it — whether any statement anywhere runs opaque code — would come back wrong in
    the permissive direction for every node outside it.
    """
    while node.parent is not None:
        node = node.parent
    return node


def _bump_tree_version(site: Node) -> None:
    root = tree_root(site)
    _tree_versions[root] = _tree_versions.get(root, 0) + 1


def _replace_in_parent(old: Node, new: Node) -> bool:
    """
    Replace `old` with `new` in `old`'s parent node. Sets `new.parent` and handles direct fields,
    list items, and tuple-in-list items. Returns whether `old` was found and replaced, the same way
    `_remove_from_parent` reports whether it removed anything — a caller that turns tree edits into
    a `Transformer.changed` flag needs the answer, and reading `None` as "nothing moved" leaves the
    pipeline calling a pass stable while its edit has already advanced the mutation counter.

    `new.parent` is set only once a slot has been found, so that a failed replacement leaves `new`
    naming no holder rather than naming one that does not hold it — a caller that abandons the
    replacement then has nothing to undo.
    """
    parent = old.parent
    if parent is None:
        return False
    for attr_name in vars(parent):
        if attr_name in _SKIP_FIELDS:
            continue
        value = getattr(parent, attr_name)
        if value is old:
            new.parent = parent
            setattr(parent, attr_name, new)
            _bump_tree_version(parent)
            return True
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is old:
                    new.parent = parent
                    value[i] = new
                    _bump_tree_version(parent)
                    return True
                if isinstance(item, tuple):
                    lst = list(item)
                    for j, elem in enumerate(lst):
                        if elem is old:
                            new.parent = parent
                            lst[j] = new
                            value[i] = tuple(lst)
                            _bump_tree_version(parent)
                            return True
    return False


def _remove_from_parent(node: Node) -> bool:
    """
    Remove `node` from its parent's child list. Returns `True` if the node was found and removed.
    Uses identity comparison to avoid removing structurally equal but distinct nodes.
    """
    parent = node.parent
    if parent is None:
        return False
    for attr_name in vars(parent):
        if attr_name in _SKIP_FIELDS:
            continue
        value = getattr(parent, attr_name)
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is node:
                    del value[i]
                    _bump_tree_version(parent)
                    return True
    return False


def reattach(node: Node) -> None:
    """
    Restore every parent pointer inside the subtree at `node` to name its actual holder.

    Building a replacement node adopts the children handed to it — `Node.__post_init__` does this,
    and it is what keeps a freshly built subtree consistent — so a replacement built over parts of a
    statement that is then *not* installed leaves those parts still in the tree with their parent
    pointers aimed at a node that is not. Anything reading upward from inside such a subtree, and
    that includes every guard that asks what encloses a statement, then walks out of the tree. A
    pass that may abandon a replacement it has already built calls this on what it kept.
    """
    for parent in node.walk():
        parent._adopt(*_compute_children(parent))


def owning_list(node: Node) -> tuple[Node, str] | None:
    """
    The parent node and attribute name of the child list `node` sits in, or `None` when it sits in
    none. Every list attribute of the parent is searched, by identity, the same way
    `_remove_from_parent` searches for the node it removes — a caller that wants to edit the list
    around a node it found by a whole-tree walk needs the same answer that removal would reach.
    """
    parent = node.parent
    if parent is None:
        return None
    for name, value in vars(parent).items():
        if name in _SKIP_FIELDS or not isinstance(value, list):
            continue
        if any(item is node for item in value):
            return parent, name
    return None


def owning_field(node: Node) -> tuple[Node, str] | None:
    """
    The parent node and attribute name of the single-node field `node` sits in, or `None` when it
    sits in a list, in a tuple inside one, or nowhere. This is the counterpart of `owning_list` for
    the shape a whole-tree walk also reaches: the inner store of `($y = ($z = 1))` is a statement to
    every pass that finds it and a direct field to the parenthesis that holds it.
    """
    parent = node.parent
    if parent is None:
        return None
    for name, value in vars(parent).items():
        if name not in _SKIP_FIELDS and value is node:
            return parent, name
    return None


def set_child_list(parent: Node, attr: str, items: list) -> None:
    """
    Replace the contents of the child list at `parent.<attr>` with `items`, adopt every `Node` among
    them (including nodes nested one level inside tuple items, as in a
    `refinery.lib.scripts.ps1.model.Ps1IfStatement` `(condition, block)` clause), and advance the
    mutation counter of the tree `parent` belongs to.

    This is the in-place body/clause counterpart to `_replace_in_parent` and `_remove_from_parent`:
    a transform that rewrites a whole statement list splices it through here rather than mutating
    the list object directly, so an `AnalysisCache` over the tree rebuilds on next access instead of
    serving a model built before the edit. A raw `body[:] = ...` or `body.clear(); body.extend(...)`
    leaves the counter untouched and silently opts the tree out of that consistency check.

    The existing list object is spliced rather than replaced, so a caller iterating the list it was
    handed — as `refinery.lib.scripts.js.deobfuscation.helpers.BodyProcessingTransformer` hands one
    to `_process_body` — keeps observing the node's current children.
    """
    for item in items:
        if isinstance(item, Node):
            item.parent = parent
        elif isinstance(item, tuple):
            for elem in item:
                if isinstance(elem, Node):
                    elem.parent = parent
    existing = getattr(parent, attr, None)
    if isinstance(existing, list):
        existing[:] = items
    else:
        setattr(parent, attr, items)
    _bump_tree_version(parent)


def set_body(parent: Node, statements: list) -> None:
    """
    Replace `parent.body` with `statements` through `set_child_list` — the common case of splicing a
    statement body, used by transforms that rebuild a `refinery.lib.scripts.Block` or
    `refinery.lib.scripts.ps1.model.Ps1Code` body in place.
    """
    set_child_list(parent, 'body', statements)


def set_child(parent: Node, attr: str, child: Node | None) -> None:
    """
    Replace the single child node at `parent.<attr>`, adopt it, and advance the mutation counter of
    the tree `parent` belongs to. This is the direct-field counterpart to `set_child_list`; passing
    `None` clears the field, which is how a transform drops an optional sub-node such as a loop's
    condition or a `finally` block.
    """
    if child is not None:
        child.parent = parent
    setattr(parent, attr, child)
    _bump_tree_version(parent)


def set_value(parent: Node, attr: str, value) -> None:
    """
    Replace the value field at `parent.<attr>` — one holding a scalar rather than a child node, such
    as an operator string, a name, or a flag — and advance the mutation counter of the tree `parent`
    belongs to.

    A value field is as much part of the program a node spells as its children are: `canonical`
    compares them, the synthesizer prints them, and the analysis models read them — the block model
    reads a `refinery.lib.scripts.ps1.model.Ps1CommandInvocation`'s invocation operator to say what
    scope a body runs in, and the world model reads it as evidence that another script file runs. A
    pass that assigns such a field directly therefore changes the program without moving the counter
    every `AnalysisCache` over that tree watches, which is the same silent opt-out a raw
    `body[:] = ...` makes and is why `set_child_list` exists.
    """
    setattr(parent, attr, value)
    _bump_tree_version(parent)


class BodyEdit:
    """
    A batch of splices against one child list, applied as a single mutation.

    A transform that rewrites several entries of the same statement list registers each rewrite with
    `splice` and then calls `apply` once. The alternative — one `set_child_list` per entry, or worse
    a direct `list.remove` — advances the mutation counter once per entry, so every analysis cache
    over the tree rebuilds mid-pass and each rebuild observes a body that is half rewritten. Here
    the list the tree holds is untouched until `apply`, and the counter moves exactly once.

    Splices are keyed by node identity, so an entry that appears twice by equality is still
    rewritten only where it actually sits. An empty replacement list deletes the entry, which is the
    shape a removal takes; the class itself knows nothing about why an entry is being removed and
    enforces no policy about what may be.
    """

    def __init__(self, parent: Node, attr: str = 'body'):
        self.parent = parent
        self.attr = attr
        #: The spliced-out node is kept beside its replacement, and not only its `id`, so that it
        #: cannot be collected while the splice is pending: a recycled `id` would make the batch
        #: rewrite whatever object next took the address.
        self._splices: dict[int, tuple[Node, list]] = {}

    def splice(self, node: Node, items: list) -> None:
        """
        Register that `node` is to be replaced by `items` in the target list. An empty `items`
        deletes it. Registering the same node twice replaces the earlier splice.
        """
        self._splices[id(node)] = (node, items)

    def result(self) -> list:
        """
        The list `apply` would install, without installing it. Entries with no registered splice are
        carried over unchanged; a registered node that is not in the list at all is ignored, since a
        splice describes an edit to this list and nothing else.
        """
        current = getattr(self.parent, self.attr, None) or []
        if not self._splices:
            return list(current)
        result = []
        for item in current:
            try:
                _, items = self._splices[id(item)]
            except KeyError:
                result.append(item)
            else:
                result.extend(items)
        return result

    def apply(self) -> bool:
        """
        Install the spliced list and advance the mutation counter, returning whether anything moved.
        A batch whose splices all turn out to be no-ops leaves the tree and the counter alone.
        """
        if not self._splices:
            return False
        current = getattr(self.parent, self.attr, None) or []
        result = self.result()
        if len(result) == len(current) and all(a is b for a, b in zip(result, current)):
            return False
        set_child_list(self.parent, self.attr, result)
        return True


_N = TypeVar('_N', bound='Node')


def _clone_node(node: _N) -> _N:
    """
    Deep-clone a node tree downward without following parent pointers.
    """
    clone = copy.copy(node)
    clone.parent = None
    for field_name, kind in _classify_fields(type(node)):
        if kind == Kind.ChildNode:
            value = getattr(node, field_name)
            if isinstance(value, Node):
                child = _clone_node(value)
                child.parent = clone
                setattr(clone, field_name, child)
        elif kind == Kind.ChildList:
            items = getattr(node, field_name)
            cloned = []
            for item in items:
                if isinstance(item, Node):
                    child = _clone_node(item)
                    child.parent = clone
                    cloned.append(child)
                else:
                    cloned.append(item)
            setattr(clone, field_name, cloned)
        elif kind == Kind.TupleList:
            items = getattr(node, field_name)
            cloned = []
            for tup in items:
                new_tup = []
                for elem in tup:
                    if isinstance(elem, Node):
                        child = _clone_node(elem)
                        child.parent = clone
                        new_tup.append(child)
                    else:
                        new_tup.append(elem)
                cloned.append(tuple(new_tup))
            setattr(clone, field_name, cloned)
    return clone


class UnspellableNode(LookupError):
    """
    Raised when a synthesizer is handed a node the model says has no spelling. See
    `Node.has_spelling`.
    """
    def __init__(self, node: Node):
        super().__init__(F'{type(node).__name__} has no spelling')
        self.node = node


class Synthesizer(Visitor):
    """
    Base class for AST-to-source synthesizers. Provides indentation-aware output buffering shared
    by all language-specific synthesizers.
    """

    def visit(self, node: Node) -> Node | None:
        """
        Refuse a node the model declares unspellable rather than printing an approximation of it.
        A shape that cannot be written is one no parser may produce — the parsers build an error
        node holding the source instead — so reaching one here means a transform assembled it, and
        the alternative to failing is emitting a script that quietly means something else.
        """
        if not node.has_spelling():
            raise UnspellableNode(node)
        return super().visit(node)

    def __init__(self, indent: str = '  ', line_length: int = 140):
        super().__init__()
        self._indent = indent
        self._line_length = line_length
        self._depth = 0
        self._parts = io.StringIO()
        self._col = 0

    def convert(self, node: Node) -> str:
        self._parts.seek(0)
        self._parts.truncate(0)
        self._depth = 0
        self._col = 0
        self.visit(node)
        return self._parts.getvalue()

    def _write(self, text: str):
        self._parts.write(text)
        nc = len(text)
        self._col = (nc - br - 1) if (br := text.rfind('\n')) >= 0 else (self._col + nc)

    def _newline(self):
        self._parts.write('\n')
        indent = self._indent * self._depth
        self._parts.write(indent)
        self._col = len(indent)

    def generic_visit(self, node: Node):
        raise LookupError(F'no synthesizer visit method for {type(node).__name__}')
