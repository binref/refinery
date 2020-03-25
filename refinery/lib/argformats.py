#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# Multibin Syntax

## Introduction

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
- `h:string` assumes that `string` is a hexadecimal string of even length and returns the decoded byte sequence.
- any unit's name can be prefixed to the string, i.e. `esc:\n` corresponds to the line break character.

If a multibin argument does not use any handler, refinery first interprets the string as the path
of an existing file on disk and attempts to return the contents of this file. If this fails, the
UTF8 encoding of the string is returned.

The handlers `copy` and `cut` as well as their shortcuts `c` and `x` are **final** handlers like
the above example `s`, i.e. the string that follows `copy:` will not be interpreted as a multibin
expression. Indeed, `copy` and `cut` expect the remaining string to be in Python slice syntax. The
expression `copy:0:1` would, for example, represent the first byte of the input data. With `copy`,
this data is copied out of the input and used for the argument. With `cut`, this data is removed
from the input data and used for the argument. All `cut` operations are performed in the order in
which the arguments are specified on the command line. For example, `emit Test | cca x::1 x::1`
will output `stTe`.

The modifiers `s`, `u`, `h`, `copy` (or `c`), and `cut` (or `x`) along with using unit modifiers
should cover most use cases. To learn about other existing modifiers, refer to the rest of this
documentation.

## The Details

This module implements all argument parser types for the binary refinery. Notable classes for the
command line use are the following:

- `refinery.lib.argformats.DelayedBinaryArgument` (used almost everywhere)
- `refinery.lib.argformats.DelayedNumbinArgument` (used by children of `refinery.units.blockwise.ArithmeticUnit`)
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

In addition to the handlers which are implemented here, each refinery unit defines a (non-final)
modifier. For example, the expression `b64:Zm9v` corresponds to the binary string `foo`: The unit
`refinery.b64` is used to decode the string `Zm9v` here. Arguments can be passed to units in square
brackets and separated by commas, but there is no support for escaping comma characters. For
example, the multibin expression `xor[0xAA]:b64:2c/J2M/e` will return the binary string `secret` as
the final expression `2c/J2M/e` is base64-decoded and each byte xor'ed with the key `0xAA`. As a
second example, the expression

    hex[-R]:sha256:file:foobar.txt

will be parsed as the hexadecimal representation of the SHA256 hash of the file `foobar.txt`.
"""
import ast

from itertools import cycle, count, chain
from argparse import ArgumentTypeError
from contextlib import suppress
from functools import update_wrapper
from typing import Optional, Tuple, Union, Mapping, Any, List, Iterable

from ..lib.loader import resolve, EntryNotFound


class PythonExpression:
    """
    Implements a parser for any Python expression with a prescribed set of variable
    names permitted to occur in the expression. The resulting object is a callable
    which can be given the string representation of such an expression. In turn, the
    result of this operation is either the value of the expression if no variables
    were present, or a callable which expects keyword arguments corresponding to the
    permitted variable names.
    """

    _ALLOWED_NODE_TYPES = {
        ast.Add,
        ast.BinOp,
        ast.BitAnd,
        ast.BitAnd,
        ast.BitOr,
        ast.BitXor,
        ast.BoolOp,
        ast.Compare,
        ast.Constant,
        ast.Div,
        ast.Eq,
        ast.FloorDiv,
        ast.Gt,
        ast.GtE,
        ast.IfExp,
        ast.Index,
        ast.Invert,
        ast.Is,
        ast.IsNot,
        ast.Load,
        ast.LShift,
        ast.Lt,
        ast.LtE,
        ast.List,
        ast.MatMult,
        ast.Mod,
        ast.Mult,
        ast.Name,
        ast.Not,
        ast.NotEq,
        ast.Num,
        ast.Or,
        ast.Pow,
        ast.RShift,
        ast.Slice,
        ast.Sub,
        ast.Subscript,
        ast.Tuple,
        ast.UAdd,
        ast.UnaryOp,
        ast.USub
    }

    def __init__(self, *variables):
        self.variables = set(variables)

    def __call__(self, definition):
        try:
            expression = ast.parse(definition)
            nodes = ast.walk(expression)
        except Exception:
            raise ArgumentTypeError(F'The provided expression could not be parsed: {definition!s}')

        if type(next(nodes)) != ast.Module:
            raise ArgumentTypeError('unknown error parsing the expression')

        if type(next(nodes)) != ast.Expr:
            raise ArgumentTypeError('operation string is not a valid Python expression')

        nodes = list(nodes)
        types = set(type(node) for node in nodes)
        names = set(node.id for node in nodes if type(node) == ast.Name)

        if not types <= self._ALLOWED_NODE_TYPES:
            raise ArgumentTypeError(
                'the following operations are not allowed: {}'.format(
                    ', '.join(t.__name__ for t in types - self._ALLOWED_NODE_TYPES))
            )

        if not names <= self.variables:
            raise ArgumentTypeError(
                'the following variable names are unknown: {}'.format(
                    ', '.join(names - self.variables))
            )

        if not self.variables:
            return eval(definition)
        else:
            def evaluator(**kw): return eval(definition, None, kw)
            return evaluator


_PYTHON_EXPRESSION = PythonExpression()


def sliceobj(expression: Union[int, str]) -> slice:
    """
    Uses `refinery.lib.argformats.PythonExpression` to parse slice expressions
    where the bounds can be given as arithmetic expressions. For example, this
    argument format type will process the string `0x11:0x11+4*0x34` as the slice
    object `slice(17, 225, None)`.
    """
    if isinstance(expression, int):
        sliced = (expression,)
    else:
        sliced = expression.split(':')
        if not sliced or len(sliced) > 3:
            raise ArgumentTypeError(F'the expression {expression} is not a valid slice.')
        sliced = [None if not t else _PYTHON_EXPRESSION(t) for t in sliced]
    if len(sliced) == 1:
        k = sliced[0]
        return slice(k, k + 1) if k + 1 else slice(k, None, None)
    return slice(*sliced)


class virtualaddr:
    """
    Represents a virtual address; used by `refinery.peslice` and
    `refinery.elfslice` to reference offsets in executable file
    formats as they would appear in memory.
    """
    def __init__(self, address='0'):
        try:
            self.section, address = address.split(':')
        except ValueError:
            self.section = None
        else:
            if not address:
                self.address = 0
                return
        try:
            address = address.upper()
            if address.endswith('H'):
                address = '0x' + address[:-1]
            self.address = number[0:](address)
        except ValueError:
            pass
        try:
            self.address = int(address, 0x10)
        except ValueError:
            raise ArgumentTypeError(F'could not parse {address} as hexadecimal integer')


def utf8(x):
    """
    Returns the UTF8 encoding of the given string.
    """
    return x.encode('UTF8')


class number:
    __name__ = 'number'

    def __init__(self, min=None, max=None):
        self.min = min
        self.max = max

    def __getitem__(self, bounds):
        return self.__class__(bounds.start, bounds.stop)

    def __call__(self, value):
        if not isinstance(value, int):
            try:
                value = _PYTHON_EXPRESSION(value)
            except Exception:
                raise ValueError('unable to parse expression')
            if not isinstance(value, int):
                raise ArgumentTypeError('the expression with value {} is not an integer'.format(value))
        if self.min is not None and value < self.min or self.max is not None and value > self.max:
            raise ValueError('value {} is out of bounds [{}, {}]'.format(value, self.min, self.max))
        return value


number = number()
"""
The singleton instance of a class that uses `refinery.lib.argformats.PythonExpression`
to parse expressions with integer value. This singleton can be slice accessed to
create new number parsers, e.g. `number[0:]` will refuse to parse negative integer
expressions.
"""


class IncompatibleHandler(ValueError):
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


class LazyEvaluation:
    """
    Empty parent class for any unit that throws `refinery.lib.argformats.TooLazy`.
    """
    pass


class DelayedArgumentDispatch:
    """
    This class is used as a decorator for the default handler of classes that inherit from
    `refinery.lib.argformats.DelayedArgument`. After decorating the routine `handler` with
    `refinery.lib.argformats.DelayedArgumentDispatch`, `handler.register` can be used to
    register additional handlers.
    """
    def __init__(self, method):
        update_wrapper(self, method)
        self.default = method
        self.handlers = {}
        self.final = {}
        self.units = {}

    def _get_unit(self, name, *args):
        name = name.replace('-', '_')
        uhash = hash((name,) + args)
        if uhash in self.units:
            return self.units[uhash]
        try:
            unit = resolve(name)
        except EntryNotFound:
            return None
        else:
            unit = unit and unit.assemble(*args)
            self.units[uhash] = unit
            return unit

    def __get__(self, instance, instancetype):
        # We do not know the class whose methods we are decorating.
        self.instance = instance
        return self

    def __call__(self, data, modifier=None, *args):
        try:
            handler = self.default if modifier is None else self.handlers[modifier]
            return handler(self.instance, data, *args)
        except KeyError:
            import io
            unit = self._get_unit(modifier, *args)
            if not unit:
                raise ArgumentTypeError(F'failed to build unit {modifier}')
            with io.BytesIO(data) as stream:
                return B''.join(stream | unit)

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


class DelayedArgument(LazyEvaluation):
    """
    This base class for delayed argument parsers implements parsing
    expressions into supported modifiers.
    """
    _ARG_BEGIN_TOKEN = '['
    _ARG_CLOSE_TOKEN = ']'
    _ARG_SPLIT_TOKEN = ','

    def __init__(self, expression: str):
        self.modifiers = []
        self.finalized = False
        if not isinstance(self.handler, DelayedArgumentDispatch):
            raise NotImplementedError(
                'The default handler is required to be a '
                'DelayedArgumentDispatch instance.'
            )
        while not self.finalized:
            name, arguments, newexpr = self._split_modifier(expression)
            if not name or not self.handler.can_handle(name, *arguments):
                break
            self.modifiers.append((name, arguments))
            expression = newexpr
            if self.handler.terminates(name):
                self.finalized = True
        self.seed = expression
        self.modifiers.reverse()

    def _split_modifier(self, expression: str) -> Tuple[Optional[str], Tuple[str], str]:
        brackets = 0
        name = None
        argoffset = 0
        arguments = ()
        for k, character in enumerate(expression):
            if character == self._ARG_BEGIN_TOKEN:
                if not brackets:
                    if argoffset:
                        # This is the second time we encounter what appears to be an
                        # argument list, before the modifier has ended. This is not
                        # possible, and we decide to assume that no modifier was used.
                        break
                    name = expression[:k]
                    argoffset = k + 1
                brackets += 1
                continue
            if character == self._ARG_CLOSE_TOKEN:
                if brackets == 1:
                    arguments += expression[argoffset:k],
                elif not brackets:
                    if argoffset:
                        raise ArgumentTypeError(
                            F'Unable to parse {expression}, too many closing brackets.'
                        )
                    else:
                        break
                brackets -= 1
                continue
            if character == self._ARG_SPLIT_TOKEN:
                if brackets == 1:
                    arguments += expression[argoffset:k],
                    argoffset = k + 1
            if character == ':' and not brackets:
                if name is None:
                    name = expression[:k]
                return name, arguments, expression[k + 1:]
        return None, (), expression

    def __call__(self, data: Optional[bytearray] = None) -> bytes:
        arg = self.seed
        mod = iter(self.modifiers)
        if not self.finalized:
            mod = chain(((None, ()),), mod)
        for name, arguments in mod:
            try:
                arg = self.handler(arg, name, *arguments)
            except Exception as E:
                raise ArgumentTypeError(F'failed to apply modifier {name} to incoming data: {E}') from E
            if callable(arg):
                if data is None:
                    raise TooLazy
                arg = arg(data)
        return arg

    def handler(self, expression: str):
        """
        This method is overwritten by children of `refinery.lib.argformats.DelayedArgument`
        to implement the default handler.
        """
        raise NotImplementedError


class DelayedBinaryArgument(DelayedArgument):

    @DelayedArgumentDispatch
    def handler(self, expr: str) -> bytes:
        try:
            return open(expr, 'rb').read()
        except Exception:
            pass
        return utf8(expr)

    @handler.register('s', final=True)
    def s(self, string: str) -> bytes:
        """
        The final modifier `s:string` returns the UTF-8 encoded representation of `string`.
        """
        return string.encode('UTF8')

    @handler.register('u', final=True)
    def u(self, string: str) -> bytes:
        """
        The final modifier `u:string` returns the UTF16 (little endian without BOM) encoded
        representation of `string`.
        """
        return string.encode('UTF-16LE')

    @handler.register('a', final=True)
    def a(self, string: str) -> bytes:
        """
        The final modifier `a:string` returns the latin-1 encoded representation of `string`.
        """
        return string.encode('LATIN-1')

    @handler.register('H', 'h', final=True)
    def h(self, string: str) -> bytes:
        """
        The final modifier `h:string` (or `H:string`) returns the hex decoding of `string`.
        """
        import base64
        return base64.b16decode(string, casefold=True)

    @handler.register('f', 'file', final=True)
    def file(self, path: str) -> bytes:
        """
        The final modifier `f:path` or `file:path` returns the contents of the file located
        at the given path.
        """
        return open(path, 'rb').read()

    @handler.register('range', final=True)
    def range(self, region: str) -> bytes:
        """
        Implements the final modifier `range:bounds` to generate a sequence of bytes, where
        `bounds` is parsed as a `refinery.lib.argformats.sliceobj` with one exception: If
        `bounds` is just a single integer, it is interpreted as the upper bound for a sequence
        of bytes starting at zero.
        """
        try:
            bounds = number(region)
            return bytearray(range(bounds))
        except ValueError:
            pass
        bounds = sliceobj(region)
        if bounds.stop is None:
            raise ArgumentTypeError('cannot generate unbounded byte sequence.')
        return bytearray(range(bounds.start or 0, bounds.stop, bounds.step or 1))

    @handler.register('c', 'copy', final=True)
    def copy(self, region: str) -> bytes:
        """
        Implements the final modifier `c:region` or `copy:region`, where `region` is parsed
        as a `refinery.lib.argformats.sliceobj`. The result contains the corresponding slice
        of the input data.
        """
        bounds = sliceobj(region)
        return lambda d: d[bounds]

    @handler.register('x', 'cut', final=True)
    def cut(self, region: str) -> bytes:
        """
        `x:region` and `cut:region` work like `refinery.lib.argformats.DelayedBinaryArgument.copy`,
        but the corresponding bytes are also removed from the input data.
        """
        def extract(data: bytearray):
            result = data[bounds]
            data[bounds] = []
            return result
        bounds = sliceobj(region)
        return extract


def multibin(expression: Union[str, bytes, bytearray]) -> Union[bytes, DelayedBinaryArgument]:
    """
    This is the argument parser type that uses `refinery.lib.argformats.DelayedBinaryArgument`.
    """
    if not isinstance(expression, str):
        return bytes(expression)
    arg = DelayedBinaryArgument(expression)
    with suppress(TooLazy):
        return arg()
    return arg


class DelayedNumbinArgument(DelayedArgument):
    """
    A parser for sequences of numeric arguments. As `refinery.lib.argformats.DelayedNumbinArgument.handler`
    uses `refinery.lib.argformats.multibin`, it is possible to use any handler specified in
    `refinery.lib.argformats.DelayedBinaryArgument` as long as these handlers precede any of the handlers
    defined here.
    """

    _EV_PARSER = PythonExpression('N')

    def _mbin(self, expr: str) -> bytes:
        binary = multibin(expr)
        if not binary:
            raise ArgumentTypeError('received empty binary argument')
        return binary

    def _iter(self, unknown):
        if hasattr(unknown, '__iter__'):
            it = list(unknown)
            if all(isinstance(t, int) for t in it):
                return it
        if isinstance(unknown, int):
            return (unknown,)
        raise ArgumentTypeError(
            F'numbin parser encountered {unknown} of type {type(unknown).__name__}, '
            F'but only integers are supported.'
        )

    @DelayedArgumentDispatch
    def handler(self, expression: str) -> Iterable[int]:
        """
        The default handler: Attempts to parse the input expression as an integer and uses
        `refinery.lib.argformats.multibin` to parse it if that fails.
        """
        try:
            return (int(expression, 0),)
        except ValueError:
            return self._mbin(expression)

    @handler.register('ev', final=True)
    def ev(self, expression: str) -> Iterable[int]:
        """
        Final modifier `ev:expression`; uses a `refinery.lib.argformats.PythonExpression`
        parser to process expressions that may contain the variable `N` whose value will be
        the size of the input data.
        """
        ev = self._EV_PARSER(expression)
        try:
            return self._iter(ev())
        except Exception:
            return lambda d: self._iter(ev(N=len(d)))

    @handler.register('unpack', final=True)
    def unpack(self, expression: str) -> Iterable[int]:
        """
        Final modifier `unpack:[#]size:expression`; uses `refinery.lib.chunks.unpack` to
        convert a sequence of bytes into a sequence of numbers by unpacking them. The `expression`
        parameter is parsed with `refinery.lib.argformats.multibin` yielding this byte string.
        The `size` has to be an integer expression specifying the size of each encoded number in
        bytes. The optional hash tag modifier preceding the size indicates that the parser
        should use big endian rather than the default, little endian.
        """
        from .chunks import unpack
        size, expression = expression.split(':', 1)
        bigendian = False
        if size.startswith('#'):
            bigendian = True
            size = size[1:]
        try:
            size = int(size, 0)
        except ValueError as E:
            raise ArgumentTypeError(
                'the syntax is unpack:[!]size:bytes where size is an integer '
                'and bytes a multibin expression. You can specify the exclamation '
                'mark to use network (big endian) byte order.'
            ) from E
        mbin = self._mbin(expression)
        if not callable(mbin):
            return list(unpack(mbin, size, bigendian))
        return lambda d: list(unpack(mbin(d), size, bigendian))

    @handler.register('inc')
    def inc(self, it: Iterable[int], wrap=None) -> Iterable[int]:
        """
        The modifier `inc:it` or `inc(wrap):it` expects a sequence `it` of integers
        (a binary string is interpreted as the sequence of its byte values), iterates it
        cyclically and perpetually adds an increasing counter to the result. If `wrap`
        is specified, then the counter is reduced modulo this number.
        """
        def delay(_):
            k = cycle(range(number(wrap))) if wrap else count()
            for item in cycle(it):
                yield item + next(k)
        return delay

    @handler.register('dec')
    def dec(self, it: Iterable[int], wrap=None) -> Iterable[int]:
        """
        Identical to `refinery.lib.argformats.DelayedNumbinArgument.inc`, but the counter
        is subtracted from `it`.
        """
        def delay(_):
            k = cycle(range(number(wrap))) if wrap else count()
            for item in cycle(it):
                yield item - next(k)
        return delay


class DelayedRegexpArgument(DelayedArgument):
    """
    A parser for regular expressions arguments.
    """

    @DelayedArgumentDispatch
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
            from .patterns import formats, indicators

            def replace(match):
                name = match.group(1)
                return '(?:{})'.format(formats.get(
                    name, indicators.get(name, match.group(0))))

            expression = re.sub(
                R'\(\?\?({}|{})\)'.format(
                    '|'.join(p.name for p in formats),
                    '|'.join(p.name for p in indicators)
                ),
                replace,
                expression
            )

        return expression.encode('latin-1')

    @handler.register('yara')
    def yara(self, pattern: bytes) -> bytes:
        """
        The handler `yara:pattern` converts YARA syntax wildcard hexadecimal expressions
        into regular expressions. For example, `D?` is translated to `[\\xD0-\\xDF]`, the
        expression `[2-6]` becomes `.{2,6}`, and `?D` becomes the following substring:
        ```
        [\\x0D\\x1D\\x2D\\x3D\\x4D\\x5D\\x6D\\x7D\\x8D\\x9D\\xAD\\xBD\\xCD\\xDD\\xED\\xFD]
        ```
        Only two-letter hexadecimal sequences with optional `?` wildcards and wildcard
        ranges such as `[2-6]` are substituted, all other characters in the pattern are
        left unchanged.
        """
        import re

        def y2r(match):
            expr = match.group(0)
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
        pattern[0::2] = [re.sub(BR'[A-F0-9?]{2}', y2r, c) for c in pattern[::2]]
        pattern[1::2] = [yara_range(b) for b in pattern[1::2]]
        return B''.join(pattern)

    @handler.register('escape')
    def escape(self, str: bytes) -> bytes:
        """
        The handler `escape:str` returns a regular expression which matches the exact
        string sequence given by `str`, with special regular expression control characters
        escaped.
        """
        import re
        return re.escape(str)


def numbin(expression: Union[int, str]) -> Union[Iterable[int], DelayedNumbinArgument]:
    """
    This is the argument parser type that uses `refinery.lib.argformats.DelayedNumbinArgument`.
    """
    if isinstance(expression, int):
        return (expression,)
    arg = DelayedNumbinArgument(expression)
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


def OptionFactory(options: Mapping[str, Any]):
    """
    The factory produces an argument parser type that accepts the keys of `options`
    as possible values and causes the parsed argument to contain the corresponding
    value from the `options` dictionary.
    """

    class Option():
        def __init__(self, name: str):
            if name not in options:
                raise ValueError(
                    'the option %s is not one of these: %s' % (name, list(options)))
            self.mode = options[name]
            self.name = name

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

    return Option


def extract_options(symbols, prefix='MODE_', *exceptions):
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
