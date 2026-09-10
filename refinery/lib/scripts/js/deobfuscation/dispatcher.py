"""
The dispatcher obfuscation wraps function bodies into a central routing function that uses a string
keyed lookup table and a global payload array for argument passing. This transformer detects the
pattern structurally (no reliance on variable names), extracts the original functions, rewrites all
call sites, and removes the dispatcher scaffolding.
"""
from __future__ import annotations

from dataclasses import dataclass

from refinery.lib.scripts import (
    Node,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import enclosing_operator
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    access_key,
    binding_has_references,
    make_undefined_expression,
    property_key,
    remove_declarator,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsObjectExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
    is_async_function,
    is_generator_function,
    strip_parens,
    wraps_return,
)


class _Unreadable:
    """
    What a dispatch argument this pass cannot read as a fixed string is reported as, kept apart from
    the `None` an absent argument gives: an argument that is not there is one the dispatcher sees as
    `undefined` and compares unequal to every flag, while one that is there and unreadable may be
    any of them and may run something on the way.
    """


_UNREADABLE = _Unreadable()


def _flag_argument(
    call: JsCallExpression | JsNewExpression,
    index: int,
) -> str | None | _Unreadable:
    """
    The string the argument of *call* at *index* certainly evaluates to, `None` where the call has
    no such argument, and `_UNREADABLE` where it has one this pass cannot read as a fixed string.
    """
    if len(call.arguments) <= index:
        return None
    argument = strip_parens(call.arguments[index])
    if isinstance(argument, JsStringLiteral) and argument.value is not None:
        return argument.value
    return _UNREADABLE


def _reads_the_payload(fn: JsFunctionExpression, payload_id: str) -> bool:
    """
    Whether the table entry *fn* takes its arguments out of the payload, so what the payload holds
    when it is reached decides what it computes.
    """
    return _extract_params(fn, payload_id) != []


@dataclass
class _DispatcherInfo:
    """
    All structurally-extracted metadata about a single dispatcher function.

    The three flag strings are carried beside the things they select, because what a dispatch means
    is decided by the arguments after the key and not by the key alone. *init_flag* is the value of
    the second parameter that empties the payload, so a dispatch passing it reaches its callee with
    no arguments however the payload was filled. *create_flag* is the value that makes the
    dispatcher hand back the table entry instead of calling it, so a dispatch passing it names a
    function where every other one names a result. *wrap_flag* is the value of the third parameter
    that wraps the result in an object under `wrap_key`, so a dispatch passing it denotes that
    object and only the access on that key denotes the result.
    """
    decl: JsFunctionDeclaration
    dispatcher_id: str
    fns_map: dict[str, JsFunctionExpression]
    fns_declarator: JsVariableDeclarator
    payload_id: str
    init_flag: str
    wrap_key: str | None
    wrap_flag: str | None
    cache_id: str | None
    create_flag: str | None


@dataclass
class _DispatchSite:
    """
    One dispatch this pass can read: the expression it is written as, the identifier naming the
    dispatcher within it, the name of the function it selects, and the arguments that function is
    reached with. *arguments* is `None` where the site names the function rather than calling it,
    which the wrapped-reference form does.

    *reference* is the one occurrence of the dispatcher name this site consumes, and it is what the
    coverage question is asked over. Asking it over the site's whole subtree instead would count a
    dispatch this pass cannot read as covered merely for standing inside one it can, and a payload
    argument is carried into the replacement rather than discarded with the rest of it.
    """
    node: Node
    reference: JsIdentifier
    key: str
    arguments: list | None

    def replacement(self) -> Node:
        if self.arguments is None:
            return JsIdentifier(name=self.key)
        return JsCallExpression(
            callee=JsIdentifier(name=self.key),
            arguments=self.arguments,
        )


def _extract_fns_table(
    body: list,
) -> tuple[JsVariableDeclarator, dict[str, JsFunctionExpression]] | None:
    """
    Finds a declaration of the form

        var fns = { ... }

    where every property value is a zero-parameter
    `refinery.lib.scripts.js.model.JsFunctionExpression`. Returns the declarator node and a map from
    string key to function.
    """
    for stmt in body:
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        for decl in stmt.declarations:
            if not isinstance(decl, JsVariableDeclarator):
                continue
            if not isinstance(decl.init, JsObjectExpression):
                continue
            obj = decl.init
            if not obj.properties:
                continue
            fns: dict[str, JsFunctionExpression] = {}
            ok = True
            for prop in obj.properties:
                if not isinstance(prop, JsProperty):
                    ok = False
                    break
                key = property_key(prop)
                if key is None:
                    ok = False
                    break
                if not isinstance(prop.value, JsFunctionExpression):
                    ok = False
                    break
                if prop.value.params:
                    ok = False
                    break
                fns[key] = prop.value
            if ok and fns:
                return decl, fns
    return None


def _guarded_flag(stmt: Node, param: str) -> str | None:
    """
    The string *stmt*'s guard compares *param* to, or `None` where *stmt* is not an `if` guarded
    that way. Every branch this pass reads out of a dispatcher body is selected by one such
    comparison, and the value compared against is what a dispatch has to spell to take the branch —
    so the same read serves finding the branch and deciding whether a call site enters it.
    """
    if not isinstance(stmt, JsIfStatement):
        return None
    test = stmt.test
    if not isinstance(test, JsBinaryExpression) or test.operator != '===':
        return None
    if not isinstance(test.left, JsIdentifier) or test.left.name != param:
        return None
    if not isinstance(test.right, JsStringLiteral):
        return None
    return test.right.value


def _find_payload_id(body: list, second_param: str) -> tuple[str, str] | None:
    """
    Find the payload-init guard:

        if (p1 === "...") { payload = []; }

    and return the payload identifier name together with the flag that empties it. The guard
    compares the function's second parameter to a string literal and assigns an empty array to the
    payload variable.
    """
    for stmt in body:
        flag = _guarded_flag(stmt, second_param)
        if flag is None:
            continue
        assert isinstance(stmt, JsIfStatement)
        cons = stmt.consequent
        if isinstance(cons, JsBlockStatement) and len(cons.body) == 1:
            cons = cons.body[0]
        if not isinstance(cons, JsExpressionStatement):
            continue
        expr = cons.expression
        if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
            continue
        if isinstance(expr.left, JsIdentifier) and isinstance(expr.right, JsArrayExpression):
            if not expr.right.elements:
                return expr.left.name, flag
    return None


def _find_wrap_key(body: list, third_param: str) -> tuple[str, str] | None:
    """
    Find the return-type wrapper:

        if (p2 === "...") { return { "wrapKey": output }; }

    and return the wrapper property name together with the flag that asks for it.
    """
    for stmt in body:
        flag = _guarded_flag(stmt, third_param)
        if flag is None:
            continue
        assert isinstance(stmt, JsIfStatement)
        cons = stmt.consequent
        if isinstance(cons, JsBlockStatement) and len(cons.body) == 1:
            inner = cons.body[0]
        else:
            inner = cons
        if not isinstance(inner, JsReturnStatement):
            continue
        ret_val = inner.argument
        if not isinstance(ret_val, JsObjectExpression):
            continue
        if len(ret_val.properties) != 1:
            continue
        prop = ret_val.properties[0]
        if isinstance(prop, JsProperty):
            key = property_key(prop)
            if key is not None:
                return key, flag
    return None


def _find_cache_id(body: list, first_param: str, second_param: str) -> tuple[str, str] | None:
    """
    Find the cache variable from the create-flag branch. Looks for an `if` guarded on the second
    parameter whose body contains a logical-or assignment like

        cache[p0] || (cache[p0] = ...)

    Returns the cache identifier together with the flag that reaches that branch. The guard is read
    rather than skipped past, because the branch does not call the entry it looks up: a dispatch
    that spells this flag names the function, and one that does not names what calling it returned.
    """
    for stmt in body:
        flag = _guarded_flag(stmt, second_param)
        if flag is None:
            continue
        for node in stmt.walk():
            if not isinstance(node, JsMemberExpression):
                continue
            if (
                isinstance(node.object, JsIdentifier)
                and isinstance(node.property, JsIdentifier)
                and node.property.name == first_param
                and node.computed
            ):
                parent = node.parent
                if isinstance(parent, JsLogicalExpression) and parent.operator == '||':
                    return node.object.name, flag
    return None


def _detect_dispatcher(func: JsFunctionDeclaration) -> _DispatcherInfo | None:
    if wraps_return(func):
        return None
    if not isinstance(func.id, JsIdentifier):
        return None
    if not isinstance(func.body, JsBlockStatement):
        return None
    if len(func.params) < 3:
        return None
    p0 = func.params[0]
    p1 = func.params[1]
    p2 = func.params[2]
    if (
        not isinstance(p0, JsIdentifier)
        or not isinstance(p1, JsIdentifier)
        or not isinstance(p2, JsIdentifier)
    ):
        return None
    first_param: str = p0.name
    second_param: str = p1.name
    third_param: str = p2.name
    body = func.body.body
    result = _extract_fns_table(body)
    if result is None:
        return None
    fns_declarator, fns_map = result
    payload = _find_payload_id(body, second_param)
    if payload is None:
        return None
    payload_id, init_flag = payload
    wrap = _find_wrap_key(body, third_param)
    cache = _find_cache_id(body, first_param, second_param)
    return _DispatcherInfo(
        decl=func,
        dispatcher_id=func.id.name,
        fns_map=fns_map,
        fns_declarator=fns_declarator,
        payload_id=payload_id,
        init_flag=init_flag,
        wrap_key=None if wrap is None else wrap[0],
        wrap_flag=None if wrap is None else wrap[1],
        cache_id=None if cache is None else cache[0],
        create_flag=None if cache is None else cache[1],
    )


def _extract_params(
    fn: JsFunctionExpression,
    payload_id: str,
) -> list[JsIdentifier] | None:
    """
    Extract parameter names from the leading payload destructuring statement:

        var [a, b] = payload;

    Returns the parameter identifiers or `None` if the pattern is not found.
    """
    if not isinstance(fn.body, JsBlockStatement) or not fn.body.body:
        return []
    first = fn.body.body[0]
    if not isinstance(first, JsVariableDeclaration):
        return []
    for decl in first.declarations:
        if not isinstance(decl, JsVariableDeclarator):
            continue
        if not isinstance(decl.id, JsArrayPattern):
            continue
        if not isinstance(decl.init, JsIdentifier):
            continue
        if decl.init.name != payload_id:
            continue
        params: list[JsIdentifier] = []
        for elem in decl.id.elements:
            if not isinstance(elem, JsIdentifier):
                return None
            params.append(JsIdentifier(name=elem.name))
        return params
    return []


def _build_extracted_function(
    key: str,
    fn: JsFunctionExpression,
    payload_id: str,
) -> JsFunctionDeclaration | None:
    """
    Convert a dispatcher function-table entry into a standalone
    `refinery.lib.scripts.js.model.JsFunctionDeclaration` of the same kind. Extracts parameters from
    the payload destructuring and removes that statement.

    The kind is carried rather than defaulted: an entry that was `async` returns a promise and one
    that was a generator returns an iterator, and a declaration that dropped either would compute a
    different value — a `yield` left in a body no longer marked `*` does not even parse.

    The body is cloned before anything is taken out of it, so that building a declaration leaves
    the entry it was built from exactly as it stood. Reading the statements out of the entry itself
    would make extraction destructive, and extraction is attempted for every entry of a table
    before any of them is installed: a later entry this pass cannot read would then abandon the
    unwrap over a table whose earlier entries had already had their payload destructuring taken
    away, which is a dispatcher whose callees name parameters nothing declares.
    """
    params = _extract_params(fn, payload_id)
    if params is None:
        return None
    if not isinstance(fn.body, JsBlockStatement):
        return None
    body = _clone_node(fn.body)
    new_body_stmts = list(body.body)
    if new_body_stmts and params:
        first = new_body_stmts[0]
        if isinstance(first, JsVariableDeclaration):
            remaining = [
                d for d in first.declarations
                if not (
                    isinstance(d, JsVariableDeclarator)
                    and isinstance(d.id, JsArrayPattern)
                    and isinstance(d.init, JsIdentifier)
                    and d.init.name == payload_id
                )
            ]
            if not remaining:
                new_body_stmts = new_body_stmts[1:]
            else:
                first.declarations = remaining
    new_body = JsBlockStatement(body=new_body_stmts)
    decl = JsFunctionDeclaration(
        id=JsIdentifier(name=key),
        params=list(params),
        body=new_body,
        generator=is_generator_function(fn),
        is_async=is_async_function(fn),
    )
    return decl


def _is_object_create_null(node: Node) -> bool:
    """
    Check if *node* is `Object.create(null)`.
    """
    if not isinstance(node, JsCallExpression):
        return False
    if len(node.arguments) != 1 or not isinstance(node.arguments[0], JsNullLiteral):
        return False
    callee = node.callee
    if not isinstance(callee, JsMemberExpression):
        return False
    if not isinstance(callee.object, JsIdentifier) or callee.object.name != 'Object':
        return False
    prop = callee.property
    if isinstance(prop, JsStringLiteral):
        return prop.value == 'create'
    if isinstance(prop, JsIdentifier) and not callee.computed:
        return prop.name == 'create'
    return False


class JsDispatcherUnwrapper(ScopeProcessingTransformer):
    """
    Detect and unwrap a dispatcher pattern. For each dispatcher found, extract the wrapped
    functions, rewrite call sites, and remove the dispatcher scaffolding.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        for func in list(body):
            if not isinstance(func, JsFunctionDeclaration):
                continue
            info = _detect_dispatcher(func)
            if info is None:
                continue
            self._unwrap_dispatcher(scope, body, info)

    def _unwrap_dispatcher(
        self,
        scope: Node,
        body: list,
        info: _DispatcherInfo,
    ) -> None:
        plan = self._plan_call_sites(scope, info)
        if not self._plan_covers_every_reference(info, plan):
            return
        extracted: dict[str, JsFunctionDeclaration] = {}
        for key, fn in info.fns_map.items():
            decl = _build_extracted_function(key, fn, info.payload_id)
            if decl is None:
                return
            extracted[key] = decl
        for site in plan:
            _replace_in_parent(site.node, site.replacement())
        insert_idx = body.index(info.decl)
        body.remove(info.decl)
        for i, (key, decl) in enumerate(extracted.items()):
            decl.parent = scope
            body.insert(insert_idx + i, decl)
        self.mark_changed()
        self._remove_boilerplate(scope, body, info)

    def _plan_call_sites(
        self,
        scope: Node,
        info: _DispatcherInfo,
    ) -> list[_DispatchSite]:
        """
        Every dispatch through *info* that this pass can read, with nothing replaced yet. Whether
        the dispatcher may be removed at all is a question about the whole set, so the set has to
        exist before the first replacement does.

        A site nested inside another is kept rather than dropped, because the outer replacement does
        not always take the inner one with it: the direct-call form carries the payload elements
        into the call it builds, so a dispatch written into a payload survives the rewrite of the
        dispatch it is an argument of. The order the walk yields is what makes both replaceable —
        an ancestor comes first, and building its replacement adopts the arguments it reuses, so the
        inner node is still reachable from its new holder when its own turn comes.
        """
        planned: list[_DispatchSite] = []
        for node in list(scope.walk()):
            if isinstance(node, JsSequenceExpression):
                site = self._read_direct_call(node, info)
            elif isinstance(node, JsMemberExpression):
                site = self._read_wrapped_ref(node, info)
            elif isinstance(node, JsCallExpression):
                site = self._read_bare_call(node, info)
            else:
                continue
            if site is not None:
                planned.append(site)
        return planned

    def _plan_covers_every_reference(
        self,
        info: _DispatcherInfo,
        plan: list[_DispatchSite],
    ) -> bool:
        """
        Whether *plan* replaces every reference to the dispatcher, so that removing its declaration
        leaves nothing naming it. A dispatch this pass cannot read is one it is right to leave
        alone, and what it leaves alone still calls the function it is leaving, so removing the
        declaration anyway hands back a file that throws a `ReferenceError` where the original ran.

        The whole unwrap is refused rather than the removal alone, because a dispatcher left
        standing beside the extracted functions would still have to route through its own table,
        and the payload the surviving dispatch writes is read by no extracted body.

        What each site accounts for is the one occurrence of the name it consumes, not everything
        standing inside it. A dispatch this pass cannot read is often written *within* one it can,
        a payload argument being the ordinary place for a call, and the replacement carries such an
        argument over rather than discarding it, so counting a subtree as covered would clear the
        very reference that survives.

        The dispatcher's own body is excluded rather than counted, since it goes with the
        declaration. Everything else is asked of the model, so a same-named binding in another
        scope is not mistaken for a use of this one.
        """
        assert self._root is not None
        if not isinstance(info.decl.id, JsIdentifier):
            return False
        model = model_cache(self, self._root).model
        binding = model.binding_of(info.decl.id)
        return not binding_has_references(
            model,
            binding,
            exclude=info.decl,
            exclude_ids={id(site.reference) for site in plan},
        )

    def _read_direct_call(
        self,
        seq: JsSequenceExpression,
        info: _DispatcherInfo,
    ) -> _DispatchSite | None:
        """
        The sequence expression dispatch call *seq* is:

            (payload = [args], dispatcher("key"))  ->  key(args)

        Also reads the wrapped variant where the return value is unwrapped via a member access
        on the wrap key:

            (payload = [args], dispatcher("key", s, wrapFlag)["wk"])

        A `new` dispatch is read only in that wrapped variant. `new` hands back the object the
        dispatcher returned only where it returned one, and the wrapper is the one branch that
        does: everywhere else `new` yields the fresh instance and the result the call computed is
        thrown away, which the call this would build hands back instead.
        """
        if len(seq.expressions) != 2:
            return None
        assign, second = seq.expressions
        if not isinstance(assign, JsAssignmentExpression):
            return None
        if assign.operator != '=':
            return None
        if not isinstance(assign.left, JsIdentifier) or assign.left.name != info.payload_id:
            return None
        if not isinstance(assign.right, JsArrayExpression):
            return None
        read = self._unwrap_dispatch_call(second, info)
        if read is None:
            return None
        dispatch_call, through_the_wrap_key = read
        if isinstance(dispatch_call, JsNewExpression) and not through_the_wrap_key:
            return None
        if not dispatch_call.arguments:
            return None
        key_arg = dispatch_call.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return None
        if key_arg.value not in info.fns_map:
            return None
        if not self._flags_agree_with_the_reading(
            dispatch_call,
            info,
            unwrapped=through_the_wrap_key,
            selects_without_calling=False,
            carries_the_payload=True,
        ):
            return None
        elements = assign.right.elements
        if any(element is None for element in elements) and not self._a_hole_reads_undefined():
            return None
        args = [
            make_undefined_expression() if e is None else e
            for e in elements
        ]
        assert isinstance(dispatch_call.callee, JsIdentifier)
        return _DispatchSite(seq, dispatch_call.callee, key_arg.value, args)

    def _a_hole_reads_undefined(self) -> bool:
        """
        Whether a payload position written with no element in it reads `undefined`, which is what
        spelling it out as `undefined` at the call site claims. A hole is not an element whose value
        is `undefined`: the callee reaches it by reading that index off the payload array, so what
        it finds is whatever `Array.prototype` answers there, and a file that wrote that prototype
        answers something else.
        """
        assert self._root is not None
        return model_cache(self, self._root).effects.chain_roots_unwritten(list)

    def _flags_agree_with_the_reading(
        self,
        call: JsCallExpression | JsNewExpression,
        info: _DispatcherInfo,
        *,
        unwrapped: bool,
        selects_without_calling: bool,
        carries_the_payload: bool,
    ) -> bool:
        """
        Whether the arguments after the key say the dispatch is the one the site reading it built.
        The key alone selects the table entry; which of the dispatcher's branches runs, and what the
        expression standing at the site therefore denotes, is decided by the two flags behind it.

        Three readings can disagree with the flags, and each is a value the replacement would get
        wrong rather than a shape it cannot spell. A dispatch spelling the wrap flag denotes the
        wrapper object, so the access on the wrap key belongs to it and a reading without one hands
        back the result the wrapper held. A dispatch spelling the create flag is handed the table
        entry rather than what calling it returned, which is the wrapped-reference form's whole
        premise and the ruin of every other one. And a dispatch spelling the init flag reaches its
        callee with the payload emptied, so a reading that carries the payload elements into a call
        passes arguments the original threw away.

        Every argument beyond the third is dropped by the replacement, so it has to be one nothing
        can miss. An argument this pass cannot read as a fixed string is refused outright in the
        two flag positions, since such an argument may be any flag and may run something on the way
        to being one.
        """
        assert self._root is not None
        flag = _flag_argument(call, 1)
        rtype = _flag_argument(call, 2)
        if isinstance(flag, _Unreadable) or isinstance(rtype, _Unreadable):
            return False
        if (info.wrap_flag is not None and rtype == info.wrap_flag) is not unwrapped:
            return False
        selects = info.create_flag is not None and flag == info.create_flag
        if selects is not selects_without_calling:
            return False
        if carries_the_payload and flag == info.init_flag:
            return False
        cache = model_cache(self, self._root)
        return all(
            cache.effects.is_side_effect_free(
                argument,
                discarded=True,
                reads_may_throw=True,
                read_established=cache.read_established,
            )
            for argument in call.arguments[3:]
        )

    @staticmethod
    def _unwrap_dispatch_call(
        node: Node,
        info: _DispatcherInfo,
    ) -> tuple[JsCallExpression | JsNewExpression, bool] | None:
        """
        Extract a dispatcher call from *node*, which may be a bare call or a member access of
        the form:

            dispatcher(...)["wrapKey"]

        Returns the call node together with whether the wrap-key access was read off it, or `None`.
        The second half is what the caller checks the dispatch's own return-type flag against: the
        access and the flag asking for the object it reads from are one fact written twice, and a
        site holding one without the other denotes something else entirely.
        """
        call = strip_parens(node)
        through_the_wrap_key = False
        if isinstance(call, JsMemberExpression) and info.wrap_key is not None:
            if access_key(call) == info.wrap_key:
                call = strip_parens(call.object)
                through_the_wrap_key = True
        if not isinstance(call, (JsCallExpression, JsNewExpression)):
            return None
        if not isinstance(call.callee, JsIdentifier):
            return None
        if call.callee.name != info.dispatcher_id:
            return None
        return call, through_the_wrap_key

    def _read_wrapped_ref(
        self,
        member: JsMemberExpression,
        info: _DispatcherInfo,
    ) -> _DispatchSite | None:
        """
        The new-expression dispatch with wrap key access *member* is, which names the function it
        selects rather than calling it:

            new dispatcher("key", createFlag, wrapFlag)["wrapKey"]  ->  key

        Both flags are what make it that. The create flag is what has the dispatcher hand the table
        entry back instead of calling it, so without it this member denotes a *result*, and the wrap
        flag is what puts that entry under the key being read.
        """
        if info.wrap_key is None:
            return None
        if access_key(member) != info.wrap_key:
            return None
        new_expr = strip_parens(member.object)
        if not isinstance(new_expr, JsNewExpression):
            return None
        if not isinstance(new_expr.callee, JsIdentifier):
            return None
        if new_expr.callee.name != info.dispatcher_id:
            return None
        if not new_expr.arguments:
            return None
        key_arg = new_expr.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return None
        if key_arg.value not in info.fns_map:
            return None
        if not self._flags_agree_with_the_reading(
            new_expr,
            info,
            unwrapped=True,
            selects_without_calling=True,
            carries_the_payload=False,
        ):
            return None
        return _DispatchSite(member, new_expr.callee, key_arg.value, None)

    def _read_bare_call(
        self,
        call: JsCallExpression,
        info: _DispatcherInfo,
    ) -> _DispatchSite | None:
        """
        The bare `dispatcher("key")` call *call* is. These occur without a preceding payload
        assignment, when the dispatched function takes no arguments.

        A call standing second in a sequence expression is not one of them however it reads here:
        the assignment in front of it is what fills the payload its callee takes its arguments from,
        so rewriting it alone would call that callee with none. It belongs to `_read_direct_call`,
        which reads the pair, and is left for that one to plan or to refuse whole. The parent is
        read through any parentheses around the call, since a file that writes the grouping means
        the same dispatch by it.

        A call whose result is unwrapped on the wrap key is not one of them either: what that
        member expression denotes is the callee's return value, so replacing the call alone leaves
        the unwrap standing over a value that carries no such key. This pass has no reading of that
        form, and an unread dispatch is what `_plan_covers_every_reference` refuses the unwrap on.

        The zero arguments this reading gives its callee are a claim about the payload, not about
        the site: the callee reads its arguments off the payload array, which a dispatch that does
        not spell the init flag leaves holding whatever the last one put there. So an entry that
        reads the payload at all is planned here only behind that flag, and an entry that reads
        none is planned whatever the payload holds.
        """
        parent = enclosing_operator(call)
        if isinstance(parent, JsSequenceExpression):
            return None
        if (
            info.wrap_key is not None
            and isinstance(parent, JsMemberExpression)
            and strip_parens(parent.object) is call
            and access_key(parent) == info.wrap_key
        ):
            return None
        if not isinstance(call.callee, JsIdentifier):
            return None
        if call.callee.name != info.dispatcher_id:
            return None
        if not call.arguments:
            return None
        key_arg = call.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return None
        if key_arg.value not in info.fns_map:
            return None
        if not self._flags_agree_with_the_reading(
            call,
            info,
            unwrapped=False,
            selects_without_calling=False,
            carries_the_payload=False,
        ):
            return None
        if (
            _flag_argument(call, 1) != info.init_flag
            and _reads_the_payload(info.fns_map[key_arg.value], info.payload_id)
        ):
            return None
        return _DispatchSite(call, call.callee, key_arg.value, [])

    def _remove_boilerplate(self, scope: Node, body: list, info: _DispatcherInfo) -> None:
        assert self._root is not None
        model = model_cache(self, self._root).model
        to_remove = []
        for stmt in list(body):
            if isinstance(stmt, JsVariableDeclaration):
                for decl in stmt.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    if decl.id.name == info.payload_id and decl.init is None:
                        remove_declarator(decl)
                        break
                    if info.cache_id and decl.id.name == info.cache_id:
                        if decl.init is not None and _is_object_create_null(decl.init):
                            remove_declarator(decl)
                            break
            elif isinstance(stmt, JsFunctionDeclaration):
                if (
                    isinstance(stmt.id, JsIdentifier)
                    and isinstance(stmt.body, JsBlockStatement)
                    and not stmt.body.body
                    and not stmt.params
                ):
                    binding = model.binding_of(stmt.id)
                    if not binding_has_references(model, binding, exclude=stmt):
                        to_remove.append(stmt)
        for stmt in to_remove:
            _remove_from_parent(stmt)
