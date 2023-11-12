#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
## Multibin Syntax

Many refinery units receive arguments which represent binary data, and usually these arguments can
be given in **multibin** format, which is a special syntax which allows to preprocess data with a
number of **handlers**. For example, the multibin expression `md5:password` preprocesses the
argument `password` (which is understood as its UTF8 encoding by default) using the `md5` handler,
which returns the MD5 hash of the input data. Consequently, the output of

    emit md5:password | hex -R

would be the string `5F4DCC3B5AA765D61D8327DEB882CF99`. The most important basic handlers to know
are:

- `s:string` disables all further preprocessing and interprets `string` as an UTF8 encoded string
- `u:string` same, but as an UTF16-LE encoded string
- `h:string` assumes that `string` is a hexadecimal string and returns the decoded byte sequence.
- any unit's name can be prefixed to the string, i.e. `esc:\\n` corresponds to the line break character.

If a multibin argument does not use any handler, refinery first interprets the string as the path
of an existing file on disk and attempts to return the contents of this file. If this fails, the
UTF8 encoding of the string is returned.

The handlers `copy` and `cut` as well as their shortcuts `c` and `x` are **final** handlers like
the above example `s`, i.e. the string that follows `copy:` will not be interpreted as a multibin
expression. Indeed, `copy` and `cut` expect the remaining string to be in Python slice syntax. The
expression `copy:0:1` would, for example, represent the first byte of the input data. With `copy`,
this data is copied out of the input and used for the argument. With `cut`, this data is removed
from the input data and used for the argument. All `cut` operations are performed in the order in
which the arguments are specified on the command line. For example:
```
emit 1234 | cca x::1 x::1
```
will output the string `3412`.

The modifiers `s`, `u`, `h`, `copy` (or `c`), and `cut` (or `x`) along with using unit modifiers
should cover most use cases. To learn about other existing modifiers, refer to the rest of this
documentation.

## Arguments For Handlers

Neither `refinery.lib.argformats.DelayedArgument.s`, `refinery.lib.argformats.DelayedArgument.u`,
nor `refinery.lib.argformats.DelayedArgument.h` require any additional arguments except for the
input string that they are applied to. However, if a refinery unit is used as a handler, there is
an option to add arguments to the handler that will be passed to the unit as command-line
arguments. For example, the following will output the hexadecimal text representation of the MD5
hash of the string "password":

    emit md5[-t]:password

Inside the square brackets that follow the handler name, arguments are separated by commas. This
also means that arguments passed to handlers in this way cannot contain any commas. There is no
escape sequence, but it is possible to use nested multibin expressions to work around this. For
example, the multibin expression `q:1%2c2%2c3` corresponds to the string `1,2,3` and the output
of the following command will be `2,4,5`:

    emit repl[q:1%2c2%2c3,2]:1,2,3,4,5

The first argument to the `refinery.repl` unit is the multibin argument `q:1%2c2%2c3`, which uses
the `refinery.lib.argformats.DelayedArgument.q` handler to return `1,2,3`. The second argument to
this unit-based handler is `2`, separated from the previous one by a comma. Hence, `refinery.repl`
will replace all occurrences of `1,2,3` in the input with just `2`.

Some of the more complex non-unit handlers also have optional arguments.

## Technical Details

This module implements all argument parser types for the binary refinery. Notable classes for the
command line use are the following:

- `refinery.lib.argformats.DelayedBinaryArgument` (used almost everywhere)
- `refinery.lib.argformats.DelayedNumSeqArgument` (used by children of `refinery.units.blockwise.ArithmeticUnit`)
- `refinery.lib.argformats.DelayedRegexpArgument` (used by `refinery.rex`, `refinery.resub`)

All of the above classes inherit from `refinery.lib.argformats.DelayedArgument`. The following
mainly applies to `refinery.lib.argformats.DelayedBinaryArgument`, but the other two parsers work
similar. The classes implement the various modifiers which are available to multibin expressions.

The reason why these parsers have **"delayed"** in their name is that they allow the implementation
of handlers which require input data to be present, like the handlers `copy` and `cut`, which are
implemented in `refinery.lib.argformats.DelayedBinaryArgument.copy` and
`refinery.lib.argformats.DelayedBinaryArgument.cut`, respectively. These expressions can not be
evaluated immediately after the command line is parsed, but only as soon as input data becomes
available for processing.

As explained above, each refinery unit defines a (non-final) modifier. The expression `b64:Zm9v`,
for example, corresponds to the binary string `foo` - the unit `refinery.b64` is used to decode the
string `Zm9v` to `foo`. Arguments can be passed to units in square brackets and separated by commas,
but there is no support for escaping comma characters (see the previous section for more details).

## Examples

1. The multibin expression `xor[0xAA]:b64:2c/J2M/e` will return the binary string `secret`; the
   string `2c/J2M/e` is base64-decoded using `refinery.b64` and then each byte is xor'ed with the
   key `0xAA` by the unit `refinery.xor`.
2. The expression `hex[-R]:sha256:read:foobar.txt` is the hexadecimal representation of the SHA256
   hash of the contents of the file `foobar.txt` on disk.
"""
from __future__ import annotations

import ast
import builtins
import itertools
import inspect
import sys

from abc import ABC, abstractmethod
from pathlib import Path
from argparse import ArgumentTypeError
from contextlib import suppress
from functools import update_wrapper, reduce, lru_cache
from typing import TYPE_CHECKING, get_type_hints
from typing import AnyStr, Deque, Optional, Tuple, Union, Mapping, Any, List, TypeVar, Iterable, ByteString, Callable

from refinery.lib.frame import Chunk
from refinery.lib.tools import isbuffer, infinitize, one, normalize_to_identifier
from refinery.lib.meta import is_valid_variable_name, metavars

if TYPE_CHECKING:
    from refinery import Unit

FinalType = TypeVar('FinalType')
DelayedType = Callable[[ByteString], FinalType]
MaybeDelayedType = Union[DelayedType[FinalType], FinalType]

_DEFAULT_BITS = 64


class ParserError(ArgumentTypeError): pass
class ParserVariableMissing(ParserError): pass


class RepeatedInteger(int):
    """
    This class serves as a dual-purpose result for `refinery.lib.argformats.numseq`
    types. It is an integer, but can be infinitely iterated.
    """
    def __iter__(self): return self
    def __next__(self): return self


class LazyEvaluation:
    """
    Empty parent class for any unit that throws `refinery.lib.argformats.TooLazy`.
    """
    pass


class PythonExpression:
    """
    Implements a parser for any Python expression with a prescribed set of variable
    names permitted to occur in the expression. The resulting object is a callable
    which can be given the string representation of such an expression. In turn, the
    result of this operation is either the value of the expression if no variables
    were present, or a callable which expects keyword arguments corresponding to the
    permitted variable names.
    """
    def __init__(self, definition: AnyStr, *variables, constants=None, all_variables_allowed=False):
        self.definition = definition = definition.strip()
        if not isinstance(definition, str):
            definition = definition.decode('utf8')
        constants = constants or {}
        variables = set(variables) | set(constants)
        try:
            expression = ast.parse(definition, mode='eval')
        except Exception:
            raise ParserError(F'The provided expression could not be parsed: {definition!s}')

        class StringToBytes(ast.NodeTransformer):
            if sys.version_info >= (3, 8):
                def visit_Constant(self, node: ast.Constant):
                    if not isinstance(node.value, str):
                        return node
                    return ast.Constant(value=node.value.encode('utf8'))
            else:
                def visit_Str(self, node: ast.Str):
                    return ast.Bytes(s=node.s.encode('utf8'))

            def visit_MatMult(self, node: ast.MatMult) -> Any:
                return ast.BitXor()

        expression = ast.fix_missing_locations(StringToBytes().visit(expression))
        nodes = ast.walk(expression)

        try:
            if type(next(nodes)) != ast.Expression:
                raise ParserError(F'Unknown error parsing the expression: {definition!s}')
        except StopIteration:
            raise ParserError('The input string is not a Python expression.')

        names = {node.id for node in nodes if isinstance(node, ast.Name)}
        names.difference_update(dir(builtins))
        names.difference_update(globals())
        if not all_variables_allowed and not names <= variables:
            raise ParserVariableMissing(
                'the following variable names are unknown: {}'.format(', '.join(names - variables)))

        self.variables = names
        self.constants = constants
        self.expression = compile(expression, '<string>', 'eval')

    def __str__(self):
        return self.definition

    def __call__(self, mapping: dict = None, **values):
        if mapping is not None:
            values, tmp = mapping, values
            values.update(tmp)
        variables = dict(values)
        for v in self.variables.difference(variables):
            try:
                variables[v] = values[v]
            except KeyError:
                raise ParserVariableMissing(v)
        variables.update(self.constants)
        return eval(self.expression, None, variables)

    @classmethod
    def evaluate(cls, definition, values):
        expression = cls(definition, all_variables_allowed=True)
        for name in expression.variables:
            if name not in values:
                raise ParserVariableMissing(name)
        return expression(values)


class SliceAgain(LazyEvaluation):
    """
    Raised by `refinery.lib.argformats.sliceobj` to indicate that meta variables
    are required to compue this slice.
    """
    def __init__(self, expr: Union[DelayedBinaryArgument, str]):
        self.expr = expr

    def __call__(self, data):
        expression = self.expr
        if pending(expression):
            expression = expression(data).decode('utf8')
        return sliceobj(expression, data)


def percent(expression: str):
    """
    Allows specification of percentages.
    """
    if expression.endswith('%'):
        return float(expression[:-1].strip()) / 100
    return float(expression)


def sliceobj(expression: Union[int, str, slice], data: Optional[Chunk] = None, range=False, final=False) -> Union[slice, SliceAgain]:
    """
    Uses `refinery.lib.argformats.PythonExpression` to parse slice expressions
    where the bounds can be given as arithmetic expressions. For example, this
    argument format type will process the string `0x11:0x11+4*0x34` as the slice
    object `slice(17, 225, None)`.
    """
    if isinstance(expression, slice):
        return expression
    if isinstance(expression, int):
        return slice(expression, expression + 1)
    if isinstance(expression, (bytes, bytearray)):
        expression = expression.decode('utf8')

    if data is None:
        variables = {}
    else:
        variables = metavars(data)
        if is_valid_variable_name(expression):
            try:
                return sliceobj(variables[expression], data, final=True)
            except Exception:
                pass

    sliced = expression and expression.split(':') or ['', '']

    if not sliced or len(sliced) > 3:
        raise ArgumentTypeError(F'the expression "{expression}" is not a valid slice.')
    try:
        sliced = [None if not t else PythonExpression.evaluate(t, variables) for t in sliced]
    except ParserVariableMissing:
        if final:
            raise
        elif data is not None:
            parser = DelayedNumSeqArgument(expression)
            return sliceobj(parser(data), data, range, final=True)
        else:
            return SliceAgain(expression)
    if len(sliced) == 1:
        k = sliced[0]
        if not range:
            return slice(k, k + 1) if k + 1 else slice(k, None, None)
        return slice(0, k)
    for k, item in enumerate(sliced):
        if item is None or isinstance(item, int):
            continue
        if isbuffer(item) and len(item) in (1, 2, 4, 8, 16):
            sliced[k] = int.from_bytes(item, 'little')
            continue
        raise TypeError(F'The value {item!r} of type {type(item).__name__} cannot be used as a slice index.')
    return slice(*sliced)


def utf8(x: str):
    """
    Returns the UTF8 encoding of the given string.
    """
    return x.encode('UTF8')


class IncompatibleHandler(ArgumentTypeError):
    """
    This exception is generated when `refinery.lib.argformats.DelayedArgument` handlers
    are chained in an incompatible way.
    """
    def __init__(self, type_expected, type_observed, modifier):
        self.type_expected = type_expected
        self.type_observed = type_observed
        self.modifier = modifier
        modifier_name = F'handler {modifier}' if modifier else 'default handler'
        super().__init__('{} received {} but expected {}'.format(
            modifier_name,
            type_observed.__name__,
            type_expected.__name__
        ))


class TooLazy(Exception):
    """
    Exception which indicates that an argument parser requires input data before it can be
    evaluated.
    """
    pass


class VariableMissing(ArgumentTypeError):
    def __init__(self, name):
        super().__init__(F'The variable {name} is not defined.')
        self.name = name


class DelayedArgumentDispatch:
    """
    This class is used as a decorator for the default handler of classes that inherit from
    `refinery.lib.argformats.DelayedArgument`. After decorating the routine `handler` with
    `refinery.lib.argformats.DelayedArgumentDispatch`, `handler.register` can be used to
    register additional handlers.
    """
    class Wrapper:
        def can_handle(self, *a): return self.ego.can_handle(*a)
        def terminates(self, *a): return self.ego.terminates(*a)

        def __init__(self, ego, arg):
            self.ego = ego
            self.arg = arg

        def __call__(self, *args, **kwargs):
            return self.ego(self.arg, *args, **kwargs)

        def __getattr__(self, key):
            return getattr(self.ego, key)

    @classmethod
    def Inherit(cls, parent: DelayedArgument):
        def wrap(method):
            dispatcher = cls(method)
            parent_dispatcher = parent.handler
            dispatcher.handlers.update(parent_dispatcher.handlers)
            dispatcher.final.update(parent_dispatcher.final)
            dispatcher.units = parent_dispatcher.units
            return dispatcher
        return wrap

    def __init__(self, method):
        update_wrapper(self, method)
        self.default = method
        self.handlers = {}
        self.final = {}
        self.units = {}

    def _get_unit(self, name: str, *args) -> Unit:
        name = normalize_to_identifier(name)
        uhash = hash((name,) + args)
        if uhash in self.units:
            return self.units[uhash]
        from refinery import load
        unit = load(name)
        unit = unit and unit.assemble(*args).log_detach()
        self.units[uhash] = unit
        return unit

    def __get__(self, instance, t=None):
        return self.Wrapper(self, instance)

    def __call__(self, instance, data, modifier=None, *args):
        try:
            handler = self.default if modifier is None else self.handlers[modifier]
            name = next(itertools.islice(inspect.signature(handler).parameters.values(), 1, None)).name
            hint = get_type_hints(handler).get(name, None)
            if hint == Iterable[type(data)]:
                data = (data,)
            if hint == str and isbuffer(data):
                data = data.decode('utf8')
            return handler(instance, data, *args)
        except KeyError:
            unit = self._get_unit(modifier, *args)
            if not unit:
                raise ArgumentTypeError(F'failed to build unit {modifier}')
            result = unit.act(data)
            return result if isbuffer(result) else B''.join(result)

    def can_handle(self, modifier, *args):
        return modifier in self.handlers or bool(self._get_unit(modifier, *args))

    def terminates(self, modifier):
        """
        Indicates whether the given registered modifier is final.
        """
        return self.final.get(modifier, False)

    def register(self, *modifiers, final=False):
        """
        Registers a new modifier handler.
        """
        def _register(method):
            for modifier in modifiers:
                self.handlers[modifier] = method
                self.final[modifier] = final
            return method
        return _register


def LazyPythonExpression(expression: str) -> MaybeDelayedType[Any]:
    import re
    match = re.fullmatch(
        R'(?i)(?P<digits>[1-9][0-9]*|0)(?P<unit>[KMGTPE]B?)',
        expression.strip())
    if match is not None:
        unit = match['unit'].upper()
        for k, symbol in enumerate('KMGTPE', 1):
            if unit.startswith(symbol):
                expression = match['digits'] + (k * 3 * '0')
                break
    parser = PythonExpression(expression, all_variables_allowed=True)
    if parser.variables:
        def evaluate(data: Chunk):
            try:
                return parser(metavars(data))
            except ParserVariableMissing:
                # It is possible that a byte string can accidentally look like a valid Python
                # expression, e.g.: B0fGtH*9/HKlwT:
                definition = parser.definition
                if isinstance(definition, str):
                    definition = definition.encode('utf8')
                return definition
        return evaluate
    else:
        return parser()


class DelayedArgument(LazyEvaluation):
    """
    This base class for delayed argument parsers implements parsing expressions into supported modifiers.
    When `reverse` is set to `True`, the multibin expression is expected to have suffixes for handlers
    rather than prefixes. If the `seed` value is specified, the expression is expected to only contain
    a chain of handlers, and the given seed will be used as the initial value to be passed to them.
    """
    _ARG_BEGIN_TOKEN = '['
    _ARG_CLOSE_TOKEN = ']'
    _ARG_SPLIT_TOKEN = ','
    _CMD_SPLIT_TOKEN = ':'

    def __init__(self, expression: str, reverse: bool = False, seed=None):
        self.expression = expression
        self.modifiers = []
        self.finalized = False
        if seed is not None:
            if reverse:
                if not expression.startswith(':'):
                    expression = F':{expression}'
            else:
                if not expression.endswith(':'):
                    expression = F'{expression}:'
        while not self.finalized:
            name, arguments, newexpr = self._split_modifier(expression, reverse)
            if not name or not self.handler.can_handle(name, *arguments):
                break
            self.modifiers.append((name, arguments))
            expression = newexpr
            if self.handler.terminates(name):
                self.finalized = True
        if seed is not None:
            if expression:
                rt = 'reverse ' if reverse else ''
                raise ValueError(F'{rt}expression {self.expression} with seed {seed} was not fully parsed.')
            self.seed = seed
        else:
            self.seed = expression
        self.modifiers.reverse()

    def _split_expression(self, expression: str, reverse: bool = False) -> Tuple[str, Optional[str]]:
        argument_list_visited = False
        brackets = 0
        inc = self._ARG_BEGIN_TOKEN
        dec = self._ARG_CLOSE_TOKEN
        itx = enumerate(expression)
        if reverse:
            inc, dec = dec, inc
            itx = reversed(list(itx))
        for k, character in itx:
            if character == inc:
                if not brackets:
                    if argument_list_visited:
                        # This is the second time we encounter what appears to be an
                        # argument list, before the modifier has ended. This is not
                        # possible, and we decide to assume that no modifier was used.
                        break
                    argument_list_visited = True
                brackets += 1
                continue
            if character == dec:
                if not brackets:
                    break
                brackets -= 1
                continue
            if not brackets and character == self._CMD_SPLIT_TOKEN:
                head = expression[:k]
                tail = expression[k + 1:]
                return (head, tail) if reverse else (tail, head)
        return expression, None

    def _split_modifier(self, expression: str, reverse: bool = False) -> Tuple[Optional[str], Tuple[str], str]:
        brackets = 0
        name = None
        argoffset = 0
        arguments = ()

        rest, expression = self._split_expression(expression, reverse)
        if expression is None:
            return name, arguments, rest
        name = expression

        for k, character in enumerate(expression):
            if character == self._ARG_BEGIN_TOKEN:
                if not brackets:
                    if argoffset:
                        raise ArgumentTypeError(F'Unexpected error parsing "{expression}": Double argument list.')
                    name = expression[:k]
                    argoffset = k + 1
                brackets += 1
                continue
            if character == self._ARG_CLOSE_TOKEN:
                if brackets == 1:
                    arguments += expression[argoffset:k],
                elif not brackets:
                    if argoffset:
                        raise ArgumentTypeError(F'Unable to parse "{expression}": Too many closing brackets.')
                    else:
                        break
                brackets -= 1
                continue
            if character == self._ARG_SPLIT_TOKEN:
                if brackets == 1:
                    arguments += expression[argoffset:k],
                    argoffset = k + 1
            if character == self._CMD_SPLIT_TOKEN and not brackets:
                raise ArgumentTypeError(F'Unexpected error parsing "{expression}".')
        return name, arguments, rest

    def __call__(self, data: Optional[ByteString] = None) -> bytes:
        arg = self.seed
        mod = iter(self.modifiers)
        if not self.finalized:
            mod = itertools.chain(((None, ()),), mod)
        for name, arguments in mod:
            if isbuffer(arg):
                arg = Chunk(arg)
                with suppress(AttributeError):
                    arg.meta.update(data.meta)
            try:
                arg = self.handler(arg, name, *arguments)
            except VariableMissing as v:
                if data is not None:
                    raise
                raise TooLazy from v
            except AttributeError as AE:
                raise ArgumentTypeError(F'failed to apply modifier {name} to incoming data: {AE}') from AE
            if callable(arg):
                if data is None:
                    raise TooLazy
                arg = arg(data)
        return arg

    def __eq__(self, other):
        if isinstance(other, DelayedArgument):
            return other.expression == self.expression
        try:
            # Try to realize on a completely empty chunk of data. If the result equals the
            # other object, we are likely identical and we were too cautious when delaying.
            value = self(B'')
        except Exception:
            return False
        else:
            return value == other

    def default_handler(self, expression: str) -> bytes:
        try:
            return open(expression, 'rb').read()
        except Exception:
            pass
        try:
            return utf8(expression)
        except Exception:
            return expression

    @DelayedArgumentDispatch
    def handler(self, expression) -> bytes:
        return self.default_handler(expression)

    @handler.register('s', 'S', final=True)
    def s(self, string: str) -> bytes:
        """
        The final modifier `s:string` returns the UTF-8 encoded representation of `string`.
        """
        return string.encode('UTF8')

    @handler.register('u', 'U', final=True)
    def u(self, string: str) -> bytes:
        """
        The final modifier `u:string` returns the UTF16 (little endian without BOM) encoded
        representation of `string`.
        """
        return string.encode('UTF-16LE')

    @handler.register('a', 'A', final=True)
    def a(self, string: str) -> bytes:
        """
        The final modifier `a:string` returns the latin-1 encoded representation of `string`.
        """
        return string.encode('LATIN-1')

    @handler.register('h!', 'H!')
    def hexencode(self, string: bytes) -> bytes:
        """
        The modifier `h!` (or `H!`) encodes the input as hexadecimal.
        """
        import base64
        return base64.b16encode(string)

    @handler.register('h', 'H', final=True)
    def h(self, string: str) -> bytes:
        """
        The final modifier `h:string` (or `H:string`) returns the hex decoding of `string`.
        """
        import base64
        return base64.b16decode(string, casefold=True)

    @handler.register('n')
    def n(self, string: bytes) -> bytes:
        """
        The final modifier `n:string` returns the un-escaped version of a string containing
        backslash escape sequences.
        """
        from refinery.units.encoding.esc import esc
        return esc().process(string)

    @handler.register('q', 'Q', final=True)
    def q(self, string: str) -> bytes:
        """
        The final modifier `q:string` (or `Q:string`) returns the url-quote decoding of `string`.
        """
        import urllib.parse
        return urllib.parse.unquote_to_bytes(string)

    @handler.register('read', final=True)
    def read(self, path: str, region: str = None) -> bytes:
        """
        Returns the contents of the file located at the given path. This path may contain
        wildcard characters, but this pattern has to match a single file. It is also possible
        to use the handler as `read[offset]` or as `read[offset:count]` to read `count` many
        bytes from the file at the given offset.
        """
        return self._file(path, region)

    @handler.register('readfrom')
    def readfrom(self, path: bytes, region: str = None) -> bytes:
        """
        A non-final variant of the `refinery.lib.argformats.DelayedArgument.read` handler. This
        handler should only be used to read from path names that were the result of a previous
        handler. Using `readfrom:sample.bin` will cause an error: Since `readfrom` is not final,
        the default handler will be applied to `sample.bin`, feeding the binary contents of the
        file into `readfrom`, but the handler is expecting a path name.
        """
        try:
            path = path.decode('utf8')
        except UnicodeDecodeError:
            raise ArgumentTypeError(
                'The input for the readfrom handler was not a path. Consider using the read '
                'handler instead, which is final.')
        else:
            return self._file(path, region)

    def _file(self, pattern: str, region: str) -> Optional[bytes]:
        def read(data: Optional[Chunk] = None):
            if not region:
                bounds = slice(0, None)
            else:
                bounds = sliceobj(region, data, range=True)
            if bounds.step:
                raise ValueError('Step size is not supported for file slices.')
            with open(path, 'rb') as stream:
                stream.seek(bounds.start or 0)
                return stream.read(bounds.stop)
        try:
            path: Path = one(Path.cwd().glob(pattern))
        except (NotImplementedError, LookupError):
            path: Path = Path(pattern)
        try:
            return read()
        except FileNotFoundError:
            raise ArgumentTypeError(F'File not found: {pattern}')
        except Exception:
            return read

    @handler.register('range', final=True)
    def range(self, region: str) -> bytes:
        """
        Implements the final modifier `range:bounds` to generate a sequence of bytes, where
        `bounds` is parsed as a `refinery.lib.argformats.sliceobj` with one exception: If
        `bounds` is just a single integer, it is interpreted as the upper bound for a sequence
        of bytes starting at zero.
        """
        def compute_range(data: Optional[Chunk] = None):
            try:
                bounds = sliceobj(region, data, range=True)
            except ParserVariableMissing:
                raise TooLazy
            if pending(bounds):
                raise TooLazy
            start = bounds.start or 0
            stop = bounds.stop
            step = bounds.step or 1
            if stop is None:
                return itertools.islice(itertools.count(), start, None, step)
            result = range(start, stop, step)
            if 0 <= start and stop <= 0x100:
                result = bytearray(result)
            return result
        try:
            return compute_range()
        except TooLazy:
            return compute_range

    @handler.register('env', final=True)
    def env(self, name: str) -> bytes:
        """
        The final modifier `env:name` returns the UTF8-encoded value of the environment variable
        with the given name.
        """
        import os
        return os.environ[name]

    @handler.register('pos')
    def pos(self, regex: ByteString, occurrence: int = 0) -> int:
        """
        The handler pos[k=0]:[regex] returns the position of the k-th occurrence of the regular
        expression [regex]. The value `k` can be set to `-1` to return the position of the last
        match. If `k` is a negative value, then the handler returns the offset at the end of the
        match rather than the one at the beginning. If no match is found, the handler returns
        the value `-1`.
        """
        if isinstance(occurrence, str):
            occurrence = int(occurrence, 0)

        def _pos(data: bytearray) -> int:
            import re
            it: Iterable[re.Match] = re.finditer(bytes(regex), data, flags=re.DOTALL)

            if occurrence < 0:
                from collections import deque
                matches: Deque[re.Match] = deque()
                while len(matches) < -occurrence:
                    try:
                        matches.append(next(it))
                    except StopIteration:
                        return -1
                for match in it:
                    matches.append(match)
                    matches.popleft()
                return matches[0].end()
            else:
                for k, match in enumerate(it):
                    if k == occurrence:
                        return match.start()
                else:
                    return -1

        return _pos

    @handler.register('rx')
    def rx(self, str: bytes) -> bytes:
        """
        The handler `rx:str` returns a regular expression which matches the exact string
        sequence given by `str`, with special regular expression control characters escaped.
        """
        import re
        return re.escape(str)

    @handler.register('c', 'copy', final=True)
    def copy(self, region: str) -> bytes:
        """
        Implements the final modifier `c:region` or `copy:region`, where `region` is parsed
        as a `refinery.lib.argformats.sliceobj`. The result contains the corresponding slice
        of the input data.
        """
        return lambda d: d[sliceobj(region, d)]

    @handler.register('x', 'cut', final=True)
    def cut(self, region: str) -> bytes:
        """
        `x:region` and `cut:region` work like `refinery.lib.argformats.DelayedBinaryArgument.copy`,
        but the corresponding bytes are also removed from the input data.
        """
        def extract(data: Union[bytearray, Chunk]):
            bounds = sliceobj(region, data)
            result = bytearray(data[bounds])
            data[bounds] = []
            return result
        return extract

    def _interpret_variable(self, name: str, obj: Any):
        if isbuffer(obj) or isinstance(obj, int) or obj is None:
            return obj
        if isinstance(obj, str):
            return utf8(obj)
        if isinstance(obj, (tuple, set, frozenset)):
            obj = list(obj)
        if isinstance(obj, list):
            return obj
        raise ArgumentTypeError(F'The meta variable {name} is of type {type(obj).__name__} and no conversion is known.')

    @handler.register('var', final=True)
    def var(self, name: str) -> bytes:
        """
        The final handler `var:name` contains the value of the meta variable `name`.
        The variable remains attached to the chunk.
        """
        def extract(data: Chunk):
            meta = metavars(data)
            try:
                result = meta[name]
            except KeyError:
                raise VariableMissing(name)
            return self._interpret_variable(name, result)
        return extract

    @handler.register('eat', final=True)
    def eat(self, name: str) -> bytes:
        """
        The final handler `eat:name` contains the value of the meta variable `name`.
        The variable is removed from the chunk and no longer available to subsequent
        units.
        """
        def extract(data: Chunk):
            try:
                result = data.meta.pop(name)
            except KeyError as K:
                raise VariableMissing(name) from K
            return self._interpret_variable(name, result)
        return extract

    @handler.register('e', 'E', 'eval')
    def eval(self, expression) -> Any:
        """
        Final modifier `e:expression` or `eval:expression`; uses a `refinery.lib.argformats.PythonExpression`
        parser to process expressions. The expression can contain any meta variable that is attached to the
        chunk. The `refinery.cm` unit can be used to attach information such as chunk size and the chunk
        index within the current frame (see `refinery.lib.frame`).
        """
        if isbuffer(expression):
            expression = expression.decode('utf8')
        if not isinstance(expression, str):
            return expression
        return LazyPythonExpression(expression)

    @handler.register('btoi')
    def btoi(self, binary: ByteString, size=None, step=None) -> Iterable[int]:
        """
        The modifier `btoi[size=0,step=0]:data` uses `refinery.lib.chunks.unpack` to convert a
        sequence of bytes into a sequence of integers.

        The optional parameter `size` has to be an integer expression whose absolute value gives
        the size of each encoded number in bytes. Its default value is `0`, which corresponds to
        choosing the size automatically in the following manner: If the length of the buffer is
        uneven, the value 1 is chosen. If the length modulo 4 is nonzero, the value 2 is chosen. If
        the length is divisible by 4, then 4 is chosen. To unpack as big endian as opposed to the
        default little endian, a negative value for `size` has to be specified. The absolute value
        of `size` will be used.

        By default, integers are parsed from the input buffer at offsets that are integer multiples
        of the block size. The optional parameter `step` can be used to override this behavior. For
        example, `btoi[2,1]` can be used to read 16-bit values at each byte offset.
        """
        from refinery.lib import chunks
        size = int(size, 0) if size else 0
        step = int(step, 0) if step else 0
        bigE = size < 0
        size = abs(size)
        if not size:
            n = len(binary)
            if n % 2:
                size = 1
            elif n % 4:
                size = 2
            else:
                size = 4
        return list(chunks.unpack(binary, size, bigE, step))

    @handler.register('itob')
    def itob(self, integers: Iterable[int], size=None) -> ByteString:
        """
        The modifier `itob[size=0]:integers` is the inverse of `btoi` and works in the same way,
        except that the case `size=0` is handled in the following way: The handler inspects all
        integers in the input and determines the minimum block size required to pack all of them.
        """
        from refinery.lib import chunks
        size = int(size, 0) if size else 0
        bigE = size < 0
        size = abs(size)
        if not size:
            def byte_length(n: int):
                width, overflow = divmod(n.bit_length(), 8)
                if overflow: width += 1
                return width
            if not isinstance(integers, list):
                integers = list(integers)
            size = max((byte_length(n) for n in integers), default=1)
            size = max(size, 1)
        else:
            mask = (1 << (size * 8)) - 1
            integers = (integer & mask for integer in integers)
        return chunks.pack(integers, size, bigE)

    @handler.register('inc')
    def inc(self, it: Iterable[int], precision=None) -> Iterable[int]:
        """
        The modifier `inc:it` or `inc[N=64]:it` expects a sequence `it` of integers (a binary
        string is interpreted as the sequence of its byte values), iterates it cyclically and
        perpetually adds an increasing counter to the result. If the number `N` is nonzero, then
        the counter is limited to `N` bits.
        """
        precision = precision and int(precision, 0) or _DEFAULT_BITS
        it = infinitize(it)
        if precision:
            def delay(_):
                mask = (1 << precision) - 1
                for a, b in zip(it, itertools.cycle(range(mask + 1))):
                    yield a + b & mask
        else:
            def delay(_):
                for a, b in zip(it, itertools.count()):
                    yield a + b
        return delay

    @handler.register('dec')
    def dec(self, it: Iterable[int], precision=None) -> Iterable[int]:
        """
        Identical to `refinery.lib.argformats.DelayedNumSeqArgument.inc`, but decreasing the counter
        rather than increasing it.
        """
        precision = precision and int(precision, 0) or _DEFAULT_BITS
        it = infinitize(it)
        if precision:
            def delay(_):
                mask = (1 << precision) - 1
                for a, b in zip(it, itertools.cycle(range(mask + 1))):
                    yield a - b & mask
        else:
            def delay(_):
                for a, b in zip(it, itertools.count()):
                    yield a - b
        return delay

    @handler.register('take')
    def take(self, it: Iterable[int], bounds: Optional[str] = None):
        """
        The handler `take[start:stop:step]` expects an integer sequence as input and applies a slice
        to it. Slices are given in Python syntax, so `take[::2]` will extract every second item from
        the incoming data. The default sequence is `1:`, i.e. skipping the first element.
        """
        def sliced(bounds):
            try:
                return it[bounds]
            except TypeError:
                subsequence = itertools.islice(it, bounds.start, bounds.stop, bounds.step)
                if bounds.stop is not None:
                    subsequence = list(subsequence)
                    if all(t in range(0x100) for t in subsequence):
                        subsequence = bytearray(subsequence)
                return subsequence
        bounds = bounds and sliceobj(bounds) or slice(1, None)
        if isinstance(bounds, slice):
            return sliced(bounds)
        return lambda d: sliced(bounds(d))

    @handler.register('cycle')
    def cycle(self, it: Iterable[int]) -> Iterable[int]:
        """
        The `cycle` handler turns a finite integer sequence into an infinitely repeating integer sequence.
        """
        if isinstance(it, itertools.cycle):
            return it
        return itertools.cycle(it)

    @handler.register('accu', final=True)
    def accu(
        self,
        spec: str,
        seed: Optional[str] = None,
        skip: Optional[str] = None,
        precision: Optional[str] = None
    ) -> Iterable[int]:
        """
        The final handler

            accu[seed=0,skip=1,precision=64]:update[#feed]

        expects `seed`, `skip`, `update`, and `feed` to be Python expressions. It generates an infinite integer
        sequence maintaining an internal state `A`: The initial value for `A` is `seed`. Each subsequent state is
        the result of evaluating the `update` expression, which can use the variable `A` to access the current
        state. The next integer value to be generated is the result of evaluating the expression `feed`, which
        may again use the variable `A` to access the internal state. If the `feed` expression is omitted, the
        complete state `A` is emitted in each step. The value of `skip` specifies the number of elements from the
        beginning of the sequence that should be skipped. The value of `precision` specifies the number of bits
        that are used by the internal state variable `A`. You can specify `precision` to be zero if you want the
        result to be an unbounded big integer.

        Instead of a Python expression, the  variable `update` can also be one of the following values, which
        are pre-defined update routines based on popular generators:

        - `@libc`: `A * 0x041C64E6D + 0x003039`
        - `@ansi`: `A * 0x041C64E6D + 0x003039 # (A >> 0x10)`
        - `@msvc`: `A * 0x0000343FD + 0x269EC3 # (A >> 0x10)`
        - `@msvb`: `A * 0x043FD43FD + 0xC39EC3`
        - `@java`: `A * 0x5DEECE66D + 0x00000B`
        - `@mmix`: `A * 6364136223846793005 + 1442695040888963407`
        """
        if spec.startswith('@'):
            try:
                spec = {
                    '@libc': 'A * 0x041C64E6D + 0x003039',
                    '@ansi': 'A * 0x041C64E6D + 0x003039 # (A >> 0x10)',
                    '@msvc': 'A * 0x0000343FD + 0x269EC3 # (A >> 0x10)',
                    '@msvb': 'A * 0x043FD43FD + 0xC39EC3',
                    '@java': 'A * 0x5DEECE66D + 0x00000B',
                    '@mmix': 'A * 6364136223846793005 + 1442695040888963407'
                }[spec]
            except KeyError:
                raise ArgumentTypeError(F'The generator type {spec} is unknown.')
        update, _, feed = spec.partition('#')
        update = PythonExpression(update, all_variables_allowed=True)
        seed = seed or '0'
        seed = PythonExpression(seed, all_variables_allowed=True)
        feed = feed and PythonExpression(feed, all_variables_allowed=True)
        skip = 1 if skip is None else int(skip, 0)
        precision = precision and int(precision, 0) or _DEFAULT_BITS
        mask = precision and (1 << precision) - 1

        def finalize(data: Optional[Chunk] = None):
            @lru_cache(maxsize=512, typed=False)
            def accumulate(A):
                return update(meta, A=A)
            meta = dict(metavars(data))
            A = seed and seed(meta) or 0
            F = feed(meta, A=A) if feed else A
            S = skip
            while True:
                if not S:
                    yield F
                else:
                    S = S - 1
                A = accumulate(A)
                if mask:
                    A &= mask
                F = feed(meta, A=A) if feed else A
        try:
            update(A=seed())
        except ParserVariableMissing:
            return finalize
        else:
            return finalize()

    @handler.register('be')
    def be(self, arg: Union[int, ByteString]) -> int:
        """
        Convert a binary input into the integer that it encodes in big endian format, and vice versa.
        """
        if isinstance(arg, int):
            size, remainder = divmod(arg.bit_length(), 8)
            if remainder: size += 1
            return arg.to_bytes(size, 'big')
        else:
            return int.from_bytes(arg, 'big')

    @handler.register('le')
    def le(self, arg: Union[int, ByteString]) -> int:
        """
        Convert a binary input into the integer that it encodes in little endian format, and vice versa.
        """
        if isinstance(arg, int):
            size, remainder = divmod(arg.bit_length(), 8)
            if remainder: size += 1
            return arg.to_bytes(size, 'little')
        else:
            return int.from_bytes(arg, 'little')

    @handler.register('reduce')
    def reduce(self, it: Iterable[int], reduction: str, seed: Optional[str] = None) -> int:
        """
        The handler `reduce[reduction, seed=0]` has two parameters. The string `reduction` is a
        Python expression that involves the two special variables `S` (the state) and `B`
        (the current block value). This expression is evaluated for every `B` in the incoming
        integer sequence and assigned back to `S`. The starting value of `S` is given by `seed`,
        which has a default value of `0` and must also be given as a Python expression.
        """
        seed = seed and PythonExpression(seed, all_variables_allowed=True)
        reduction = PythonExpression(reduction, all_variables_allowed=True)

        def finalize(data: Optional[Chunk] = None):
            def _reduction(S, B):
                v = reduction(args, S=S, B=B)
                return v
            args = dict(metavars(data))
            return reduce(_reduction, it, seed and seed(args) or 0)

        try:
            return finalize()
        except ParserVariableMissing:
            return finalize


class DelayedBinaryArgument(DelayedArgument):
    """
    A parser for binary arguments. It does not implement any handlers beyond the default handlers that
    are implemented in `refinery.lib.argformats.DelayedArgument`.
    """

    def __call__(self, data: Optional[ByteString] = None) -> bytes:
        value = super().__call__(data=data)
        if not isbuffer(value):
            if isinstance(value, str):
                return value.encode('utf8')
            if not value:
                return B''
            raise ArgumentTypeError(
                F'The expression {self.expression} returned a value of type {type(value).__name__}, '
                R'which could not be converted to a byte string.'
            )
        return value


class DelayedNumSeqArgument(DelayedArgument):
    """
    A parser for sequences of numeric arguments. It does not implement any handlers beyond the default
    handlers that are implemented in `refinery.lib.argformats.DelayedArgument`, but the default handler
    attempts to evalue the input as a Python expression.
    """

    def __init__(self, expression: str, reverse=False, seed=None, typecheck=True, additional_types=None):
        super().__init__(expression, reverse, seed)
        self.typecheck = typecheck
        self.additional_types = additional_types or []

    def default_handler(self, expression: str) -> Iterable[int]:
        """
        Attempts to parse the input expression as a sequence of integers. If this fails, the handler defaults
        to the parent `refinery.lib.argformats.DelayedArgument.default_handler`.
        """
        try:
            with open(expression, 'rb') as stream:
                return stream.read()
        except Exception:
            pass
        try:
            return LazyPythonExpression(expression)
        except Exception:
            if isinstance(expression, str):
                return super().default_handler(expression)
            return expression

    def __call__(self, data: Optional[Union[ByteString, Chunk]] = None) -> Iterable[int]:
        value = super().__call__(data)
        if isbuffer(value):
            return value
        if hasattr(value, '__iter__'):
            try:
                if len(value) == 1:
                    return RepeatedInteger(next(iter(value)))
            except TypeError:
                def rewind():
                    yield top
                    yield from it
                it = iter(value)
                top = next(it)
                if not isinstance(top, int):
                    raise ArgumentTypeError(
                        F'The first item {top!r} of the iterable computed from {self.expression} was not an integer.')
                return rewind()
            else:
                return value
        if isinstance(value, float):
            tmp = int(value)
            if float(tmp) == value:
                value = tmp
        if isinstance(value, int):
            return RepeatedInteger(value)
        if not self.typecheck:
            return value
        if self.additional_types:
            typecheck = self.additional_types
            try:
                typecheck = tuple(typecheck)
            except Exception:
                pass
            try:
                if isinstance(value, typecheck):
                    return value
            except Exception:
                pass
        raise ArgumentTypeError(
            F'The value computed from {self.expression} is of type {type(value).__name__} but the unit requested an '
            R'integer or a sequence of integers.'
        )


class DelayedRegexpArgument(DelayedArgument):
    """
    A parser for regular expressions arguments. It implements two additional handlers beyond the ones
    inherited from `refinery.lib.argformats.DelayedArgument`.
    """

    @DelayedArgumentDispatch.Inherit(DelayedArgument)
    def handler(self, expression: str) -> bytes:
        """
        The default handler encodes the input expression as latin-1 to return a binary
        string regular expression.
        Furthermore, the use of named patterns from `refinery.lib.patterns.formats` and
        `refinery.lib.patterns.indicators` is possible by means of the extension format
        `(??name)`. For example, the pattern `e:((??url)\\x00){4}` will match a sequence
        of four URL strings which are all terminated with a null character.
        """
        if '(??' in expression:
            import re
            from refinery.lib.patterns import formats, indicators

            def replace(match):
                name = match[1]
                return '(?:{})'.format(formats.get(
                    name, indicators.get(name, match[0])))

            expression = re.sub(
                R'\(\?\?({}|{})\)'.format(
                    '|'.join(p.name for p in formats),
                    '|'.join(p.name for p in indicators)
                ),
                replace,
                expression
            )

        return expression.encode('latin-1')

    @handler.register('yara', 'Y')
    def yara(self, pattern: bytes) -> bytes:
        """
        The handler `yara:pattern` or `Y:pattern` converts YARA syntax wildcard hexadecimal
        expressions into standard regular expressions. For example, the string `D?` is
        translated to `[\\xD0-\\xDF]`, the expression `[2-6]` becomes `.{2,6}`, and `?D`
        becomes the following substring:
        ```
        [\\x0D\\x1D\\x2D\\x3D\\x4D\\x5D\\x6D\\x7D\\x8D\\x9D\\xAD\\xBD\\xCD\\xDD\\xED\\xFD]
        ```
        Only two-letter hexadecimal sequences with optional `?` wildcards and wildcard
        ranges such as `[2-6]` are substituted, all other characters in the pattern are
        left unchanged.
        """
        import re

        def y2r(match):
            expr = match[0]
            if expr == B'??':
                return B'.'
            if B'?' not in expr:
                return BR'\x%s' % expr
            if expr.endswith(B'?'):
                return BR'[\x%c0-\x%cF]' % (expr[0], expr[0])
            return BR'[%s]' % BR''.join(
                BR'\x%x%c' % (k, expr[1]) for k in range(0x10)
            )

        def yara_range(rng):
            return B'.{%s}' % B','.join(t.strip() for t in rng[1:-1].split(B'-'))

        pattern = re.split(BR'(\[\s*\d+(?:\s*-\s*\d+)?\s*\])', pattern)
        pattern[0::2] = [re.sub(BR'[A-Fa-f0-9?]{2}', y2r, c) for c in pattern[::2]]
        pattern[1::2] = [yara_range(b) for b in pattern[1::2]]
        return B''.join(pattern)


class DelayedNumberArgument(DelayedArgument):
    """
    A parser for numeric arguments. Implements no handlers beyond the ones inherited from its parent
    `refinery.lib.argformats.DelayedArgument`. The final handler output is expected to be an integer.
    The class can be initialized with numerical bounds and checks the validity of the input after
    having evaluated all handlers.
    """
    def __init__(self, expression: str, min: int, max: int):
        self.min = min
        self.max = max
        super().__init__(expression)

    def __call__(self, data: Union[ByteString, Chunk, None] = None) -> int:
        value = super().__call__(data)
        if not isinstance(value, int):
            tv = type(value).__name__
            raise ArgumentTypeError(F'The value computed from {self.expression} is of type {tv}, it should be an integer.')
        if self.min is not None and value < self.min or self.max is not None and value > self.max:
            a = '-∞' if self.min is None else self.min
            b = '∞' if self.max is None else self.max
            raise ArgumentTypeError(F'value {value} is out of bounds [{a}, {b}]')
        return value

    def default_handler(self, expression: str) -> int:
        """
        The default handler: Attempts to parse the input expression as an integer.
        """
        return LazyPythonExpression(expression)


class number:
    __name__ = 'number'

    def __init__(self, min=None, max=None):
        self.min = min
        self.max = max

    def __getitem__(self, bounds):
        return self.__class__(bounds.start, bounds.stop)

    def __call__(self, value):
        if isinstance(value, int):
            return value
        try:
            delay = DelayedNumberArgument(value, self.min, self.max)
            try:
                return delay()
            except TooLazy:
                return delay
        except ParserError:
            import re
            match = re.fullmatch('(?:0x)?([A-F0-9]+)H?', value, flags=re.IGNORECASE)
            if not match:
                raise
            return number(F'0x{match[1]}')


number = number()
"""
The singleton instance of a class that uses `refinery.lib.argformats.PythonExpression`
to parse expressions with integer value. This singleton can be slice accessed to
create new number parsers, e.g. `number[0:]` will refuse to parse negative integer
expressions.
"""


def numseq(expression: Union[int, str], reverse=False, seed=None, typecheck=True) -> Union[Iterable[int], DelayedNumSeqArgument]:
    """
    This is the argument parser type that uses `refinery.lib.argformats.DelayedNumSeqArgument`.
    """
    if isinstance(expression, int):
        return RepeatedInteger(expression)
    arg = DelayedNumSeqArgument(expression, reverse=reverse, seed=seed, typecheck=typecheck)
    with suppress(TooLazy):
        return arg()
    return arg


def multibin(expression: Union[str, bytes, bytearray], reverse=False, seed=None) -> Union[bytes, DelayedArgument]:
    """
    This is the argument parser type that uses `refinery.lib.argformats.DelayedBinaryArgument`.
    """
    if not isinstance(expression, str):
        return bytes(expression)
    arg = DelayedBinaryArgument(expression, reverse, seed)
    with suppress(TooLazy):
        return arg()
    return arg


def regexp(expression: str) -> Union[int, bytes, DelayedRegexpArgument]:
    """
    This is the argument parser type that uses `refinery.lib.argformats.DelayedRegexpArgument`.
    """
    arg = DelayedRegexpArgument(expression)
    with suppress(TooLazy):
        return arg()
    return arg


class Option(ABC):
    name: str
    mode: Any

    @abstractmethod
    def __init__(self, name: str):
        raise NotImplementedError

    def __eq__(self, other):
        return str(other) == self.name

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    @property
    def value(self):
        return self.mode


def OptionFactory(options: Mapping[str, Any], ignorecase: bool = False):
    """
    The factory produces an argument parser type that accepts the keys of `options`
    as possible values and causes the parsed argument to contain the corresponding
    value from the `options` dictionary.
    """
    class _Option(Option):
        def __init__(self, name: str):
            if ignorecase and name not in options:
                needle = name.upper()
                for key in options:
                    if needle == key.upper():
                        name = key
                        break
            if name not in options:
                raise ValueError('The option %s is not one of these: %s' % (name, list(options)))
            self.mode = options[name]
            self.name = name

    return _Option


def extract_options(symbols, prefix: str, *exceptions: str):
    """
    A helper function to extract all numeric constants from modules that have a certain
    prefix. `refinery.units.crypto.cipher.StandardCipherUnit` uses this to extract the
    block cipher modes of operation from block cipher modules of the `pycryptodome` library.
    """
    candidates = {
        k[len(prefix):]: getattr(symbols, k, None)
        for k in dir(symbols) if k.startswith(prefix) and all(
            e not in k for e in exceptions
        )
    }
    return {k: v for k, v in candidates.items() if isinstance(v, int)}


def pending(argument: Union[Any, Iterable[Any]]) -> bool:
    """
    This function returns a boolean value which indicates whether the given
    argument is a `refinery.lib.argformats.LazyEvaluation`.
    """
    if isinstance(argument, (list, tuple)):
        return any(pending(x) for x in argument)
    return isinstance(argument, LazyEvaluation)


def manifest(argument: Union[Any, List[Any]], data: bytearray) -> Union[Any, List[Any]]:
    """
    Returns the manifestation of a `refinery.lib.argformats.LazyEvaluation`
    on the given data. This function can change the data.
    """
    if isinstance(argument, (list, tuple)):
        return [manifest(x, data) for x in argument]
    return argument(data) if isinstance(argument, LazyEvaluation) else argument
