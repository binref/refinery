#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements programmatic inlining, specifically for the units in `refinery.units.blockwise`.
"""
from __future__ import annotations
from typing import Any, Callable, Generator, Optional, Type, TypeVar, Union

import ast
import inspect
import functools
import sys

from ast import (
    Assign,
    BinOp,
    BitAnd,
    Bytes,
    Call,
    Constant,
    Expr,
    For,
    FunctionDef,
    GeneratorExp,
    Load,
    Name,
    NodeTransformer,
    Num,
    Return,
    Store,
    Str,
    Yield,
    arg,
    comprehension,
)

_R = TypeVar('_R')


class inline(Callable[..., _R]):
    def __init__(self, function: Callable[..., _R]):
        self._function = function
        functools.update_wrapper(self, function)

    def __call__(self, *args, **kwargs):
        return self._function(*args, **kwargs)


class PassAsConstant:
    def __init__(self, value):
        self.value = value


def getsource(f):
    return inspect.cleandoc(F'\n{inspect.getsource(f)}')


class ArgumentCountMismatch(ValueError):
    pass


class NoFunctionDefinitionFound(ValueError):
    pass


def iterspread(
    method: Callable[..., _R],
    iterator,
    *inline_args,
    mask: Optional[int] = None
) -> Callable[..., Generator[_R, None, None]]:
    """
    This function receives an arbitrary callable `method`, a primary iterator called `iterator`, and
    an arbitrary number of additional arguments, collected in the `inline_args` variable. The function
    will essentially turn this:

        def method(self, a, b):
            return a + b

    into this:

        def iterspread_method(self):
            for _var_a in _arg_a:
                _var_b = next(_arg_b)
                yield _var_a + _var_b

    where `_arg_a` and `_arg_b` are closure variables that are bound to the primary iterator, and the
    single element of `inline_args`, respectively. If one of the elements in `inline_args` is a constant,
    then this constant will instead be set initially in front of the loop:

        def iterspread_method(self):
            _var_b = 5
            for _var_a in _arg_a:
                yield _var_a + _var_b

    Spreading the application of `method` like this provides a high performance increase over making a
    function call to `method` in each step of the iteration.
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

    def as_arg(name: str): return F'_arg_{name}'
    def as_var(name: str): return F'_var_{name}'
    def as_tmp(name: str): return F'_tmp_{name}'

    def apply_node_transformation(cls: Type[NodeTransformer]):
        nonlocal code
        code = ast.fix_missing_locations(cls().visit(code))

    if sys.version_info >= (3, 8):
        def constant(value):
            return Constant(value=value)
    else:
        @functools.singledispatch
        def constant(value: Union[int, str, bytes]):
            raise NotImplementedError(F'The type {type(value).__name__} is not supported for inlining')
        @constant.register # noqa
        def _(value: bytes): return Bytes(s=value)
        @constant.register
        def _(value: int): return Num(n=value)
        @constant.register
        def _(value: str): return Str(s=value)

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
            nonlocal function_name, context
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
