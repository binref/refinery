"""
Implements programmatic inlining, specifically for the units in `refinery.units.blockwise`.
"""
from __future__ import annotations

import ast
import inspect
import symtable

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
from typing import Any, Callable, Generator, Iterable, TypeVar

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


class FunctionRefersToItself(ValueError):
    """
    Raised by `refinery.lib.inline.iterspread` if the body of the input method uses the name of
    the method as a global name: The inlined function is a different function under the same name.
    """


def _uses_global_name(source: str, function: str, name: str) -> bool:
    """
    Whether the given function, defined in the given source code, uses the given name as a global
    name in its body or in a scope nested in it. A parameter or local variable of that name is not
    a global name.
    """
    module = symtable.symtable(source, '<inlined>', 'exec')
    pending = [table for table in module.get_children() if table.get_name() == function]
    while pending:
        table = pending.pop()
        try:
            symbol = table.lookup(name)
        except KeyError:
            pass
        else:
            if symbol.is_global() and symbol.is_referenced():
                return True
        pending.extend(table.get_children())
    return False


def _as_arg(name: str):
    return F'_arg_{name}'


def _as_var(name: str):
    return F'_var_{name}'


def _as_tmp(name: str):
    return F'_tmp_{name}'


class _RenameVariables(NodeTransformer):
    """
    Renames every variable of the inlined function, except for the given reserved names.
    """
    def __init__(self, reserved_names: set[str]):
        self.reserved_names = reserved_names

    def visit_Name(self, node: Name) -> Any:
        if node.id in self.reserved_names:
            return node
        node.id = _as_var(node.id)
        return node


class _SpreadLoop(NodeTransformer):
    """
    Turns the body of the inlined function into a loop over its primary iterator. Constant inline
    arguments are placed in the given context, the other ones are read once in each step of the
    loop.
    """
    def __init__(
        self,
        function_head: FunctionDef,
        is_method: bool,
        inline_args: tuple,
        iterator: Iterable,
        context: dict[str, Any],
    ):
        self.function_head = function_head
        self.is_method = is_method
        self.inline_args = inline_args
        self.iterator = iterator
        self.context = context

    def visit_FunctionDef(self, node: FunctionDef):
        context = self.context
        inline_args = self.inline_args
        if node is not self.function_head:
            return node
        function_body = []
        function_args = [arg.arg for arg in node.args.args]
        inlined_start = 1

        if self.is_method:
            inlined_start += 1

        iterator_name = function_args[inlined_start - 1]
        function_args[:inlined_start] = []
        arity = len(function_args)

        try:
            vararg = _as_arg(node.args.vararg.arg)
        except Exception:
            if arity != len(inline_args):
                raise ArgumentCountMismatch
        else:
            context[vararg] = inline_args[arity:]

        for name, value in zip(function_args, inline_args):
            targets = [Name(id=_as_var(name), ctx=Store())]
            if isinstance(value, PassAsConstant):
                context[_as_var(name)] = value.value
                continue
            if isinstance(value, (int, str, bytes)):
                context[_as_var(name)] = value
                continue
            context[_as_arg(name)] = value
            function_body.append(Assign(
                targets=targets,
                value=Call(
                    func=Name(id='next', ctx=Load()),
                    args=[Name(id=_as_arg(name), ctx=Load())],
                    keywords=[]
                )))

        if node.args.vararg:
            name = node.args.vararg.arg
            function_body.append(Assign(
                targets=[
                    Name(id=_as_var(name), ctx=Store())
                ],
                value=Call(
                    func=Name(id='tuple', ctx=Load()),
                    args=[GeneratorExp(
                        elt=Call(
                            func=Name(id='next', ctx=Load()),
                            args=[Name(id=_as_tmp(name), ctx=Load())],
                            keywords=[]
                        ),
                        generators=[comprehension(
                            is_async=0,
                            target=Name(id=_as_tmp(name), ctx=Store()),
                            iter=Name(id=_as_arg(name), ctx=Load()),
                            ifs=[]
                        )]
                    )],
                    keywords=[]
                )
            ))

        function_body.extend(node.body)
        context[_as_arg(iterator_name)] = self.iterator
        function_body = [For(
            target=Name(id=_as_var(iterator_name), ctx=Store()),
            iter=Name(id=_as_arg(iterator_name), ctx=Load()),
            body=function_body,
            orelse=[]
        )]

        node.body = function_body
        node.args.args = [arg(arg=_as_var('self'))]
        node.args.vararg = None
        node.decorator_list = []
        return node


class _YieldMasked(NodeTransformer):
    """
    Turns each return statement of the inlined function into a yield, and reduces the value with the
    given mask.
    """
    def __init__(self, mask: int | None):
        self.mask = mask

    def visit_Return(self, node: Return) -> Any:
        value = node.value
        if (mask := self.mask) is not None:
            value = BinOp(left=value, op=BitAnd(), right=Constant(value=mask))
        return Expr(value=Yield(value=value))


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

    source = getsource(method)
    code = ast.parse(source)
    closure_vars = inspect.getclosurevars(method)
    context = dict(closure_vars.nonlocals)
    reserved_names = set(context)
    reserved_names.update(closure_vars.globals)
    reserved_names.update(closure_vars.builtins)

    try:
        function_head = next(node for node in ast.walk(code) if isinstance(node, FunctionDef))
    except StopIteration:
        raise NoFunctionDefinitionFound

    if _uses_global_name(source, function_head.name, function_head.name):
        raise FunctionRefersToItself(F'The function {function_head.name} refers to itself and cannot be inlined.')

    for transformer in (
        _RenameVariables(reserved_names),
        _SpreadLoop(function_head, inspect.ismethod(method), inline_args, iterator, context),
        _YieldMasked(mask),
    ):
        code = ast.fix_missing_locations(transformer.visit(code))

    bin = compile(code, '<inlined>', 'exec', optimize=2)
    exec(bin, context, context)
    return context.pop(function_head.name)
