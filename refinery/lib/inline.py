"""
Implements programmatic inlining, specifically for the units in `refinery.units.blockwise`.
"""
from __future__ import annotations

import ast
import inspect

from ast import (
    Assign,
    BinOp,
    BitAnd,
    Call,
    Constant,
    Expr,
    For,
    FunctionDef,
    GeneratorExp,
    Load,
    Name,
    NodeTransformer,
    Return,
    Store,
    Yield,
    arg,
    comprehension,
)
from typing import Any, Callable, Generator, TypeVar

_R = TypeVar('_R')


class PassAsConstant:
    """
    This simple wrapper can be used to mark an argument as a constant when passing it as an inline
    argument to `refinery.lib.inline.iterspread`.
    """
    def __init__(self, value):
        self.value = value


def getsource(f):
    """
    Retrieve the source code of a given object and remove any common indentation from all lines.
    This function is used by `refinery.lib.inline.iterspread` to obtain the source code for the
    input method, which is then parsed and reshaped to provide the optimized callable.
    """
    return inspect.cleandoc(F'\n{inspect.getsource(f)}')


class ArgumentCountMismatch(ValueError):
    """
    Raised by `refinery.lib.inline.iterspread` if the input method expects a different number of
    arguments than provided by the arguments to `refinery.lib.inline.iterspread`.
    """


class NoFunctionDefinitionFound(ValueError):
    """
    When `refinery.lib.inline.iterspread` fails to find a function definition when parsing the
    source code that belongs to the input method, this error is raised.
    """


def iterspread(
    method: Callable[..., _R],
    iterator,
    *inline_args,
    mask: int | None = None
) -> Callable[..., Generator[_R]]:
    """
    This function receives an arbitrary callable `method`, a primary iterator called `iterator`,
    and an arbitrary number of additional arguments, collected in the `inline_args` variable. The
    function will essentially turn this:

        def method(self, a, b):
            return a + b

    into this:

        def iterspread_method(self):
            for _var_a in _arg_a:
                _var_b = next(_arg_b)
                yield _var_a + _var_b

    where `_arg_a` and `_arg_b` are closure variables that are bound to the primary iterator and
    the single element of `inline_args`, respectively. If one of the elements in `inline_args` is
    a constant, then this constant will instead be set initially in front of the loop, as shown
    below. An argument is identified as a constant if it is of type `str`, `int`, `bytes`, or
    explicitly wrapped in a `refinery.lib.inline.PassAsConstant`.

        def iterspread_method(self):
            _var_b = 5
            for _var_a in _arg_a:
                yield _var_a + _var_b

    Spreading the application of `method` like this provides a high performance increase over
    making a function call to `method` in each step of the iteration.
    """

    code = ast.parse(getsource(method))
    closure_vars = inspect.getclosurevars(method)
    context = closure_vars.nonlocals
    reserved_names = set(context)
    reserved_names.update(closure_vars.globals)
    reserved_names.update(closure_vars.builtins)

    try:
        function_head = next(node for node in ast.walk(code) if isinstance(node, FunctionDef))
    except StopIteration:
        raise NoFunctionDefinitionFound

    function_name = None

    def as_arg(name: str):
        return F'_arg_{name}'

    def as_var(name: str):
        return F'_var_{name}'

    def as_tmp(name: str):
        return F'_tmp_{name}'

    def apply_node_transformation(cls: type[NodeTransformer]):
        nonlocal code
        code = ast.fix_missing_locations(cls().visit(code))

    def constant(value):
        return Constant(value=value)

    @apply_node_transformation
    class _(NodeTransformer):
        def visit_Name(self, node: Name) -> Any:
            if node.id in reserved_names:
                return node
            node.id = as_var(node.id)
            return node

    @apply_node_transformation
    class _(NodeTransformer):
        def visit_FunctionDef(self, node: FunctionDef):
            nonlocal function_name
            if node is not function_head:
                return node
            function_body = []
            function_name = node.name
            function_args = [arg.arg for arg in node.args.args]
            inlined_start = 1

            if inspect.ismethod(method):
                inlined_start += 1

            iterator_name = function_args[inlined_start - 1]
            function_args[:inlined_start] = []
            arity = len(function_args)

            try:
                vararg = as_arg(node.args.vararg.arg)
            except Exception:
                if arity != len(inline_args):
                    raise ArgumentCountMismatch
            else:
                context[vararg] = inline_args[arity:]

            for name, value in zip(function_args, inline_args):
                targets = [Name(id=as_var(name), ctx=Store())]
                if isinstance(value, PassAsConstant):
                    context[as_var(name)] = value.value
                    continue
                if isinstance(value, (int, str, bytes)):
                    context[as_var(name)] = value
                    continue
                context[as_arg(name)] = value
                function_body.append(Assign(
                    targets=targets,
                    value=Call(
                        func=Name(id='next', ctx=Load()),
                        args=[Name(id=as_arg(name), ctx=Load())],
                        keywords=[]
                    )))

            if node.args.vararg:
                name = node.args.vararg.arg
                function_body.append(Assign(
                    targets=[
                        Name(id=as_var(name), ctx=Store())
                    ],
                    value=Call(
                        func=Name(id='tuple', ctx=Load()),
                        args=[GeneratorExp(
                            elt=Call(
                                func=Name(id='next', ctx=Load()),
                                args=[Name(id=as_tmp(name), ctx=Load())],
                                keywords=[]
                            ),
                            generators=[comprehension(
                                is_async=0,
                                target=Name(id=as_tmp(name), ctx=Store()),
                                iter=Name(id=as_arg(name), ctx=Load()),
                                ifs=[]
                            )]
                        )],
                        keywords=[]
                    )
                ))

            function_body.extend(node.body)
            context[as_arg(iterator_name)] = iterator
            function_body = [For(
                target=Name(id=as_var(iterator_name), ctx=Store()),
                iter=Name(id=as_arg(iterator_name), ctx=Load()),
                body=function_body,
                orelse=[]
            )]

            node.body = function_body
            node.args.args = [arg(arg=as_var('self'))]
            node.args.vararg = None
            node.decorator_list = []
            return node

    @apply_node_transformation
    class _(NodeTransformer):
        def visit_Return(self, node: Return) -> Any:
            value = node.value
            if mask is not None:
                value = BinOp(left=value, op=BitAnd(), right=constant(mask))
            return Expr(value=Yield(value=value))

    bin = compile(code, '<inlined>', 'exec', optimize=2)
    exec(bin, context, context)
    return context[function_name]
