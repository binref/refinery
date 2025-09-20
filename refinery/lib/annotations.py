"""
This module exposes a method for backwards-compatible evaluation of modern type annotations.
Starting with Python 3.10, this module only forwards standard library functions, but in earlier
versions, annotations are converted to backwards-compatible expressions before evaluation. For
example, consider the following modern type annotation:

    list[list[int] | str | bool | float] | dict[str, int]

While this is valid as a type annotation with a `__future__` import, it does not evaluate as a
Python expression at runtime before 3.10. Therefore, it would be transformed into the following
anntoation before evaluation:

    Union[List[Union[List[int], str, bool, float]], Dict[str, int]]

This backwards compatibility layer can be removed as soon as refinery has raised its minimum
Python version requirement to Python 3.10 or higher.
"""
from __future__ import annotations

import sys
import typing

__pdoc__ = {
    'evaluate': (
        'The same as `eval` on Python 3.10 and beyond, otherwise a backwards-compatibility layer '
        'that converts modern type hints back to compatible expressions.'
    ),
    'get_type_hints': (
        'Implements the same functionality as `typing.get_type_hints` but uses `evaluate` rather '
        'than `eval` when the Python version is below 3.10.'
    ),
}

__all__ = ['get_type_hints', 'evaluate']

if sys.version_info >= (3, 10):
    get_type_hints = typing.get_type_hints
    evaluate = eval
else:
    import ast

    if sys.version_info >= (3, 9):
        def _index(n):
            return n
    elif typing.TYPE_CHECKING:
        def _index(n: _T) -> _T:
            return typing.cast(_T, ast.Index(value=n))
        _T = typing.TypeVar('_T', bound=ast.expr)
    else:
        def _index(n):
            return ast.Index(value=n)

    _TYPING_LOOKUP = {}
    _TYPING_MODULE = '_imp_typing'

    def _into_typing(name: str):
        try:
            alias = _TYPING_LOOKUP[(name := name.casefold())]
        except KeyError:
            for t in dir(typing):
                if t.casefold() == name:
                    _TYPING_LOOKUP[name] = alias = t
                    break
            else:
                _TYPING_LOOKUP[name] = alias = None
        return alias

    def get_type_hints(obj):
        if getattr(obj, '__no_type_check__', None):
            return {}
        if isinstance(obj, type):
            hints = {}
            for base in reversed(obj.__mro__):
                gns: dict = sys.modules[base.__module__].__dict__
                ann: dict = base.__dict__.get('__annotations__', {})
                for name, value in ann.items():
                    hints[name] = evaluate(value, gns)
            return hints
        root = obj
        while hasattr(root, '__wrapped__'):
            root = root.__wrapped__
        globalns = getattr(root, '__globals__', {})
        hints = getattr(obj, '__annotations__', None)
        if hints is None:
            return {}
        if not isinstance(hints, dict):
            hints = dict(hints)
        for name, value in hints.items():
            hints[name] = evaluate(value, globalns)
        return hints

    def evaluate(annotation: str | None, globalns: dict | None = None, localns: dict | None = None):
        if annotation is None:
            return type(None)

        if not isinstance(annotation, str):
            return annotation

        def _types(attr: str):
            return ast.Attribute(
                ctx=ast.Load(),
                value=ast.Name(id=_TYPING_MODULE, ctx=ast.Load()),
                attr=attr
            )

        class T(ast.NodeTransformer):

            def visit_Subscript(self, node):
                node.value = self.visit(node.value)
                node.slice = self.visit(node.slice)
                if isinstance(node.value, ast.Name):
                    if downgrade := _into_typing(node.value.id):
                        node.value = _types(downgrade)
                return node

            def visit_Call(self, node: ast.Call):
                # do not descend into calls
                return node

            def visit_BinOp(self, node):
                def collect(n: ast.expr):
                    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
                        yield from collect(n.left)
                        yield from collect(n.right)
                    else:
                        yield self.visit(n)
                if not isinstance(node.op, ast.BitOr):
                    return self.generic_visit(node)
                return ast.Subscript(
                    value=_types('Union'),
                    slice=_index(
                        ast.Tuple(elts=list(collect(node)), ctx=ast.Load())),
                    ctx=ast.Load()
                )

        if annotation.startswith('Param['):
            if not globalns or 'Param' not in globalns:
                raise LookupError
        try:
            tree = ast.parse(annotation, mode='eval')
            body = T().visit(tree.body)
            ast.fix_missing_locations(body)
            code = compile(ast.Expression(body=body), '[annotation]', 'eval')
            globalns = globalns or {}
            globalns[_TYPING_MODULE] = typing
            return eval(code, globalns, localns)
        except Exception:
            raise
