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
    _replace_in_parent,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    property_key,
    remove_declarator,
    string_value,
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
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsObjectExpression,
    JsProperty,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
)


@dataclass
class _DispatcherInfo:
    """
    All structurally-extracted metadata about a single dispatcher function.
    """
    decl: JsFunctionDeclaration
    dispatcher_id: str
    fns_map: dict[str, JsFunctionExpression]
    fns_declarator: JsVariableDeclarator
    payload_id: str
    wrap_key: str | None
    cache_id: str | None


def _extract_fns_table(
    body: list,
) -> tuple[JsVariableDeclarator, dict[str, JsFunctionExpression]] | None:
    """
    Finds a declaration of the form

        var fns = { ... }

    where every property value is a zero-parameter `JsFunctionExpression`. Returns the declarator
    node and a map from string key to function.
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


def _find_payload_id(body: list, second_param: str) -> str | None:
    """
    Find the payload-init guard:

        if (p1 === "...") { payload = []; }

    and return the payload identifier name. The guard compares the function's second parameter to a
    string literal and assigns an empty array to the payload variable.
    """
    for stmt in body:
        if not isinstance(stmt, JsIfStatement):
            continue
        test = stmt.test
        if not isinstance(test, JsBinaryExpression) or test.operator != '===':
            continue
        if not (
            isinstance(test.left, JsIdentifier)
            and test.left.name == second_param
            and isinstance(test.right, JsStringLiteral)
        ):
            continue
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
                return expr.left.name
    return None


def _find_wrap_key(body: list, third_param: str) -> str | None:
    """
    Find the return-type wrapper:

        if (p2 === "...") { return { "wrapKey": output }; }

    and return the wrapper property name.
    """
    for stmt in body:
        if not isinstance(stmt, JsIfStatement):
            continue
        test = stmt.test
        if not isinstance(test, JsBinaryExpression) or test.operator != '===':
            continue
        if not (
            isinstance(test.left, JsIdentifier)
            and test.left.name == third_param
            and isinstance(test.right, JsStringLiteral)
        ):
            continue
        cons = stmt.consequent
        if isinstance(cons, JsBlockStatement) and len(cons.body) == 1:
            inner = cons.body[0]
        else:
            inner = cons
        from refinery.lib.scripts.js.model import JsReturnStatement
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
                return key
    return None


def _find_cache_id(body: list, first_param: str) -> str | None:
    """
    Find the cache variable from the create-flag branch. Looks for an `if` whose body contains a
    logical-or assignment like

        cache[p0] || (cache[p0] = ...)

    Returns the cache identifier.
    """
    for stmt in body:
        if not isinstance(stmt, JsIfStatement):
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
                from refinery.lib.scripts.js.model import JsLogicalExpression
                if isinstance(parent, JsLogicalExpression) and parent.operator == '||':
                    return node.object.name
    return None


def _detect_dispatcher(func: JsFunctionDeclaration) -> _DispatcherInfo | None:
    """
    Structurally detect whether `func` is a dispatcher function. Returns the extracted metadata or
    `None` if the function does not match the pattern.
    """
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
    payload_id = _find_payload_id(body, second_param)
    if payload_id is None:
        return None
    wrap_key = _find_wrap_key(body, third_param)
    cache_id = _find_cache_id(body, first_param)
    return _DispatcherInfo(
        decl=func,
        dispatcher_id=func.id.name,
        fns_map=fns_map,
        fns_declarator=fns_declarator,
        payload_id=payload_id,
        wrap_key=wrap_key,
        cache_id=cache_id,
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
    Convert a dispatcher function-table entry into a standalone `JsFunctionDeclaration`. Extracts
    parameters from the payload destructuring and removes that statement.
    """
    params = _extract_params(fn, payload_id)
    if params is None:
        return None
    body = fn.body
    if not isinstance(body, JsBlockStatement):
        return None
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

    def _process_scope(self, scope: Node) -> None:
        if isinstance(scope, JsScript):
            body = scope.body
        elif isinstance(scope, JsBlockStatement):
            body = scope.body
        else:
            return
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
        extracted: dict[str, JsFunctionDeclaration] = {}
        for key, fn in info.fns_map.items():
            decl = _build_extracted_function(key, fn, info.payload_id)
            if decl is None:
                return
            extracted[key] = decl
        self._rewrite_call_sites(scope, info, extracted)
        insert_idx = body.index(info.decl)
        body.remove(info.decl)
        for i, (key, decl) in enumerate(extracted.items()):
            decl.parent = scope
            body.insert(insert_idx + i, decl)
        self._remove_boilerplate(body, info)
        self.mark_changed()

    def _rewrite_call_sites(
        self,
        scope: Node,
        info: _DispatcherInfo,
        extracted: dict[str, JsFunctionDeclaration],
    ) -> None:
        for node in list(scope.walk()):
            if isinstance(node, JsSequenceExpression):
                self._try_rewrite_direct_call(node, info, extracted)
            elif isinstance(node, JsMemberExpression):
                self._try_rewrite_wrapped_ref(node, info, extracted)
            elif isinstance(node, JsCallExpression):
                self._try_rewrite_bare_call(node, info, extracted)

    def _try_rewrite_direct_call(
        self,
        seq: JsSequenceExpression,
        info: _DispatcherInfo,
        extracted: dict[str, JsFunctionDeclaration],
    ) -> None:
        """
        Rewrite `(payload = [args], dispatcher("key"))` to `key(args)`.
        Also handles the wrapped variant `(payload = [args], dispatcher("key", s, wrapFlag)["wk"])`
        where the return value is unwrapped via a member access on the wrap key.
        """
        if len(seq.expressions) != 2:
            return
        assign, second = seq.expressions
        if not isinstance(assign, JsAssignmentExpression):
            return
        if assign.operator != '=':
            return
        if not isinstance(assign.left, JsIdentifier) or assign.left.name != info.payload_id:
            return
        if not isinstance(assign.right, JsArrayExpression):
            return
        dispatch_call = self._unwrap_dispatch_call(second, info)
        if dispatch_call is None:
            return
        if not dispatch_call.arguments:
            return
        key_arg = dispatch_call.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return
        key = key_arg.value
        if key not in extracted:
            return
        args = [
            JsIdentifier(name='undefined') if e is None else e
            for e in assign.right.elements
        ]
        replacement = JsCallExpression(
            callee=JsIdentifier(name=key),
            arguments=args,
        )
        _replace_in_parent(seq, replacement)

    @staticmethod
    def _unwrap_dispatch_call(
        node: Node,
        info: _DispatcherInfo,
    ) -> JsCallExpression | JsNewExpression | None:
        """
        Extract a dispatcher call from *node*, which may be a bare `dispatcher(...)` call or
        a `dispatcher(...)["wrapKey"]` member access. Returns the call node or `None`.
        """
        call = node
        if isinstance(node, JsMemberExpression) and info.wrap_key is not None:
            prop_name = string_value(node.property) if node.computed else (
                node.property.name if isinstance(node.property, JsIdentifier) else None
            )
            if prop_name == info.wrap_key:
                call = node.object
        if not isinstance(call, (JsCallExpression, JsNewExpression)):
            return None
        if not isinstance(call.callee, JsIdentifier):
            return None
        if call.callee.name != info.dispatcher_id:
            return None
        return call

    def _try_rewrite_wrapped_ref(
        self,
        member: JsMemberExpression,
        info: _DispatcherInfo,
        extracted: dict[str, JsFunctionDeclaration],
    ) -> None:
        """
        Rewrite `new dispatcher("key", s2, s3)["wrapKey"]` to `key`.
        """
        if info.wrap_key is None:
            return
        prop_name = string_value(member.property) if member.computed else (
            member.property.name if isinstance(member.property, JsIdentifier) else None
        )
        if prop_name != info.wrap_key:
            return
        new_expr = member.object
        if not isinstance(new_expr, JsNewExpression):
            return
        if not isinstance(new_expr.callee, JsIdentifier):
            return
        if new_expr.callee.name != info.dispatcher_id:
            return
        if not new_expr.arguments:
            return
        key_arg = new_expr.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return
        key = key_arg.value
        if key not in extracted:
            return
        _replace_in_parent(member, JsIdentifier(name=key))

    def _try_rewrite_bare_call(
        self,
        call: JsCallExpression,
        info: _DispatcherInfo,
        extracted: dict[str, JsFunctionDeclaration],
    ) -> None:
        """
        Rewrite bare `dispatcher("key")` calls (without a preceding payload assignment) to
        `key()`. These occur when the dispatched function takes no arguments.
        """
        if not isinstance(call.callee, JsIdentifier):
            return
        if call.callee.name != info.dispatcher_id:
            return
        if not call.arguments:
            return
        key_arg = call.arguments[0]
        if not isinstance(key_arg, JsStringLiteral):
            return
        key = key_arg.value
        if key not in extracted:
            return
        if isinstance(call.parent, JsSequenceExpression):
            return
        replacement = JsCallExpression(
            callee=JsIdentifier(name=key),
            arguments=[],
        )
        _replace_in_parent(call, replacement)

    @staticmethod
    def _remove_boilerplate(body: list, info: _DispatcherInfo) -> None:
        """
        Remove dispatcher-related boilerplate declarations from the scope body.
        """
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
                    if not _has_references(body, stmt.id.name, stmt):
                        to_remove.append(stmt)
        for stmt in to_remove:
            body.remove(stmt)


def _has_references(body: list, name: str, exclude: Node) -> bool:
    """
    Check if *name* is referenced anywhere in *body* outside of *exclude*.
    """
    for stmt in body:
        if stmt is exclude:
            continue
        for node in stmt.walk():
            if isinstance(node, JsIdentifier) and node.name == name:
                return True
    return False
