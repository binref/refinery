"""
A selection of refinery-specific decorators.
"""
from __future__ import annotations

import codecs
import copy
import itertools
import re

from functools import WRAPPER_ASSIGNMENTS, wraps
from typing import TYPE_CHECKING, Any, Callable, TypeVar, cast, overload

if TYPE_CHECKING:
    from refinery.units import Chunk, Unit


_F = TypeVar('_F', bound=Callable)


def wraps_without_annotations(method: Callable) -> Callable[[_F], _F]:
    """
    This decorator works simila to `wraps` from `functools` but does not update the
    type annotations of the wrapped function. This is used in the other decorators
    in this module because they change the function signature.
    """
    assignments: set[str] = set(WRAPPER_ASSIGNMENTS)
    assignments.discard('__annotations__')
    wrap = wraps(method, assigned=assignments)
    if TYPE_CHECKING:
        wrap = cast('Callable[[_F], _F]', wrap)
    return wrap


@overload
def unicoded(method: Callable[[Any, str], str]) -> Callable[[Any, Chunk], bytes]:
    ...


@overload
def unicoded(method: Callable[[Any, str], str | None]) -> Callable[[Any, Chunk], bytes | None]:
    ...


def unicoded(method: Callable[[Any, str], str | None]) -> Callable[[Any, Chunk], bytes | None]:
    """
    Can be used to decorate a `refinery.units.Unit.process` routine that takes a
    string argument and also returns one. The resulting routine takes a binary buffer
    as input and attempts to decode it as unicode text. If certain characters cannot
    be decoded, then these ranges are skipped and the decorated routine is called
    once for each string patch that was successfully decoded.
    """
    @wraps_without_annotations(method)
    def method_wrapper(self: Unit, data: Chunk) -> bytes | None:
        input_codec = self.codec if any(data[::2]) else 'UTF-16LE'
        partial = re.split(R'([\uDC80-\uDCFF]+)',  # surrogate escape range
            codecs.decode(data, input_codec, errors='surrogateescape'))
        partial[::2] = (method(self, p) or '' if p else '' for p in itertools.islice(iter(partial), 0, None, 2))
        nones = sum(1 for p in partial if p is None)
        if nones == len(partial):
            return None
        if nones >= 1:
            for k, p in enumerate(partial):
                if p is None:
                    partial[k] = ''
        return codecs.encode(''.join(partial), self.codec, errors='surrogateescape')
    return method_wrapper


def masked(mask: int, mod: bool = False):
    """
    Convert arithmetic operations that occur within the decorated function body in such a way that
    the result is reduced with the given bit mask. All additions, subtractions, multiplications,
    left shifts, and taking powers are augmented by introducing a binary AND. If the mod parameter
    is enabled, a modulo operation is introduced instead.
    """
    import ast
    import inspect

    if mod:
        op = ast.Mod
    else:
        op = ast.BitAnd

    def decorator(function):
        code = inspect.getsource(function)
        code = inspect.cleandoc(code)
        tree = ast.parse(code)

        class Postprocessor(ast.NodeTransformer):
            name = None

            def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
                self.generic_visit(node)
                if not isinstance(node.op, (ast.USub, ast.Invert)):
                    return node
                return ast.BinOp(node, op(), ast.Constant(mask))

            def visit_AugAssign(self, node: ast.AugAssign) -> Any:
                self.generic_visit(node)
                if not isinstance(node.op, (ast.Add, ast.Mult, ast.Sub, ast.LShift, ast.Pow)):
                    return node
                target_load = copy.deepcopy(node.target)
                target_load.ctx = ast.Load()
                computation = ast.BinOp(left=target_load, op=node.op, right=node.value)
                reduced = ast.BinOp(left=computation, op=op(), right=ast.Constant(mask))
                return ast.Assign(targets=[node.target], value=reduced)

            def visit_BinOp(self, node: ast.BinOp):
                self.generic_visit(node)
                if not isinstance(node.op, (ast.Add, ast.Mult, ast.Sub, ast.LShift, ast.Pow)):
                    return node
                return ast.BinOp(node, op(), ast.Constant(mask))

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.generic_visit(node)
                if self.name is None:
                    node.name = self.name = F'__wrapped_{node.name}'
                    for k in range(len(node.decorator_list)):
                        if not isinstance(decorator := node.decorator_list[k], ast.Call):
                            continue
                        if not isinstance(decorator := decorator.func, ast.Name):
                            continue
                        if decorator.id == masked.__name__:
                            del node.decorator_list[:k + 1]
                            break
                return node

        pp = Postprocessor()
        fixed = ast.fix_missing_locations(pp.visit(tree))
        if (name := pp.name) is None:
            raise RuntimeError

        import types

        freevars = function.__code__.co_freevars
        closure = function.__closure__
        namespace = {**function.__globals__}

        if freevars and closure:
            # Wrap the rewritten function definition inside a factory function that takes the free
            # variables as parameters, recreating the closure binding. The factory is needed so
            # that the inner function has the correct co_freevars, allowing us to reconstruct it
            # with the original closure cells to preserve late binding.
            factory_name = '__closure_factory'
            factory_args = ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=v) for v in freevars],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            )
            factory_body: list[ast.stmt] = fixed.body + [
                ast.Return(value=ast.Name(id=name, ctx=ast.Load()))]
            no_decorators: list[ast.expr] = []
            factory_def = ast.FunctionDef(
                name=factory_name,
                args=factory_args,
                body=factory_body,
                decorator_list=no_decorators,
                returns=None,
                type_comment=None,
                type_params=[],
            )
            fixed = ast.Module(body=[factory_def], type_ignores=[])
            fixed = ast.fix_missing_locations(fixed)
            exec(compile(fixed, function.__code__.co_filename, 'exec'), namespace)
            # We can't call the factory directly because the closure cells may not
            # have been assigned yet (late binding). Instead, we extract the inner
            # function's code object from the factory and reconstruct the function
            # with the original closure cells and the real globals dict.
            factory_fn = namespace[factory_name]
            inner_code = None
            for const in factory_fn.__code__.co_consts:
                if isinstance(const, types.CodeType) and const.co_name == name:
                    inner_code = const
                    break
            if inner_code is None:
                raise RuntimeError(F'Could not find inner code object {name!r} in factory')
            result = types.FunctionType(inner_code, function.__globals__, name, closure=closure)
        else:
            exec(compile(fixed, function.__code__.co_filename, 'exec'), namespace)
            result = types.FunctionType(
                namespace[name].__code__, function.__globals__, name)

        return wraps(function)(result)

    return decorator
