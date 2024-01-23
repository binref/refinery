#!/usr/bin/env python3
# -*- coding: utf-8 -*-
R"""
Inside a frame (see `refinery.lib.frame`), all chunks that are processed by refinery units have a
dictionary of metadata attached to them. This dictionary implements chunk-local variables which can
be accessed in various ways by the refinery argument parser (see `refinery.lib.argformats`).

### Storing Meta Variables

There are several units that are specifically designed to store meta variables:

- The `refinery.put` unit can store any multibin expression into a variable.
- The `refinery.push` and `refinery.pop` units can be used to store the result of a more complex
  sub-pipeline inside a meta variable; more on this later.
- The `refinery.cm` unit is a catch-all helper to generate common metadata such as size, frame
  index, hashes, entropy, etcetera.
- The unit `refinery.rmv` (short for "remove variable") can be used to clear local variables.
- By default, variables exist only throughout the `refinery.lib.frame` that they are defined in.
  The unit `refinery.mvg` (short for "make variable global") can be used to propagate variables
  to parent frames.
- The `refinery.struct` parses structured data from the beginning of a chunk into meta variables.
- You can use named capture groups in regular expressions when using the `refinery.rex` unit, and
  these matches will be stored under their name as a meta variable in each output chunk.
- There are units that extract data from archive-like formats. Some examples are `refinery.xtzip`,
  `refinery.xtmail`, `refinery.winreg`, and `refinery.perc`. These units will enrich their output
  chunks with a metadata variable indicating the (virtual) path of the extracted item.

### Variable Reference Handlers

There are a number of ways in which meta variables can be used. The most straightforward way is to
use the `refinery.lib.argformats.DelayedArgument.var` handler to read the contents of a variable
and use it as part of a multibin expression. The `refinery.lib.argformats.DelayedArgument.eat`
handler works in the same way, except that the variable is removed from the meta dictionary after
it has been used. Example:

    $ emit FOO [| put x BAR | cca var:x ]]
    FOOBAR

We attach a variable named `x` with value `BAR` to the chunk containing the string `FOO` and then
use `refinery.cca` to append the contents of the variable to the chunk, giving us `FOOBAR`. Had we
used `refinery.ccp`, the result would have been `BARFOO`.

### Integer and Slice Expressions

Whenever a multibin argument supports Python expressions, be it integers, sequences of integers,
or slice expressions (see also the `refinery.lib.argformats.DelayedArgument.eval` handler), then
meta variables can freely be used in that expression. Examples:

    $ emit BAR-FOO [| put i 4 | snip i: ]]
    FOO
    $ emit range:4 [| put t a | add t ]]
    abcd

### Format String Expressions

The units `refinery.cfmt`, `refinery.dump`, and `refinery.couple` support format string expressions
that can contain meta variables. For example, the following command will print a recursive listing
of the current directory with human-readable file sizes, entropy in percent, and the md5 hash of
each file:

    ef ** [| cfmt {size!r} {entropy!r} {md5} {path} ]]

Another example would be the following command, which dumps the base64 encoded buffer of length at
least 200 from the input to incrementally numbered files:

    emit sample | carve --min=200 b64 [| dump buffer{index}.b64 ]

### Magic Meta Variables

As alluded to in the previous section, there are several meta variables that are available on every
chunk, such as `size`, `entropy`, and `md5`. These values are computed as soon as they are accessed.
Some of them are formatted differently when using the `r`-transformation; for example, the `size`
variable will be printed as a human-readable expression when formatted as `{size!r}`, but it will be
a decimal string when formatted as `{size}` or `{size!s}`.

- `index`: The index of the chunk in the current frame (see `refinery.lib.frame`).
- `magic`: Human-readable file magic string.
- `mime`: MIME type of the chunk according to file magic information.
- `ext`: A guessed file extension based on file magic information.
- `size`: The number of bytes in this chunk of data. The default formatting of this value is a
   decimal integer, but its r-format is a human-readable size expression.
- `entropy`: Information entropy value of the data. Its computation can be expensive for large
   chunks. The r-format of this value is a percentage.
- `ic`: The index of coincidence of the data. Its computation can be expensive for large chunks.
   The r-format of this value is a percentage.
- `crc32`: The hexadecimal representation of the CRC32-hash of the data.
- `sha1`: The hexadecimal representation of the SHA1-hash of the data.
- `sha256`: The hexadecimal representation of the SHA256-hash of the data.
- `sha512`: The hexadecimal representation of the SHA512-hash of the data.
- `md5`: The hexadecimal representation of the MD5-hash of the data.

### Using Push And Pop

The `refinery.push` and `refinery.pop` units can be used to extract sub-pipelines as variables. For
example, the following command extracts the files from a password-protected attachment of an email
message by first extracting the password from the email message body:

    $ emit phish.eml [                      |
    >     push [                            |
    >         xtmail body.txt               |
    >         rex -I password:\s*(\w+) {1}  |
    >         pop password ]                |
    >       xt *.zip                        |
    >       xt *.exe -p var:password        |
    >       dump extracted/{path} ]

The `refinery.push` unit emits two copies of the input data, and the second copy has been moved out
of scope (it is not visible). The first `refinery.xtmail` unit extracts the `body.txt` part and we
obtain the password using `refinery.rex`. The `refinery.pop` unit consumes the first input and will
populate the meta variable dictionaries of all subsequent chunks with a variable named `password`
which contains the data from that first chunk. Note that `refinery.pop` can also be used in other
ways to merge down the metadata from chunks inside sub-pipelines.
"""
from __future__ import annotations

import abc
import contextlib
import string
import codecs
import itertools
import os

from io import StringIO
from urllib.parse import quote_from_bytes, unquote_to_bytes
from typing import Callable, Dict, List, Tuple, Any, Iterable, Optional, ByteString, Union, TYPE_CHECKING

from refinery.lib.structures import MemoryFile
from refinery.lib.tools import isbuffer, entropy, typename, index_of_coincidence
from refinery.lib.environment import environment


if TYPE_CHECKING:
    from typing import Protocol
    from refinery.lib.frame import Chunk

    class _Derivation(Protocol):
        costly: bool
        name: str
        wrap: type

        def __call__(self, object: LazyMetaOracle) -> Union[str, int, float]:
            ...


class CustomStringRepresentation(abc.ABC):
    """
    This abstract class defines an interface for wrapper classes used in `refinery.lib.meta.LazyMetaOracleFactory`.
    These classes have to implement a `str` and `repr` typecast that can be used for the conversion part of a
    format string expression.
    """

    @abc.abstractmethod
    def __str__(self): ...

    @abc.abstractmethod
    def __repr__(self): ...


_PRINT_SAFE = set(string.printable.encode('latin1')) - set(b'|<>&\t\n\r\x0B\x0B')
if os.name == 'nt':
    _PRINT_SAFE -= set(b'^"')
else:
    _PRINT_SAFE -= set(b'*?\'"')
_PRINT_SAFE = bytes(_PRINT_SAFE)
_IS_PRINT_SAFE = bytearray(256)
for p in _PRINT_SAFE:
    _IS_PRINT_SAFE[p] = 1


def is_print_safe(string: str):
    if not string.isprintable():
        return False
    for letter in string:
        code = ord(letter)
        if code < len(_IS_PRINT_SAFE) and not _IS_PRINT_SAFE[code]:
            return False
    return True


class ByteStringWrapper(bytearray, CustomStringRepresentation):
    """
    Represents a binary string and a preferred codec in case it is printable. Casting this wrapper class
    will decode the string using the given codec, using backslash escape sequences to handle decoding
    errors. The `repr` case returns a hexadecimal representation of the binary data. Finally, the object
    proxies attribute access to the wrapped binary string.
    """
    _CODECS = {
        codecs.lookup(c).name: p
        for c, p in [('utf8', 's'), ('latin1', 'a'), ('utf-16le', 'u')]
    }

    def __init__(self, string: Union[str, ByteString], codec: Optional[str] = None):
        if isinstance(string, str):
            self._string = string
            self._buffer = False
            codec = codec or 'utf8'
            string = string.encode(codec)
        elif isbuffer(string):
            self._string = None
            self._buffer = True
        else:
            raise TypeError(F'The argument {string!r} is not a buffer or string.')

        super().__init__(string)

        if codec is not None:
            nc = codecs.lookup(codec).name
            if nc not in self._CODECS:
                raise ValueError(F'The codec {nc} is not a supported codec.')
            codec = nc

        self.codec = codec

    def __fspath__(self):
        return self.string

    def requires_prefix(self, string) -> bool:
        try:
            from refinery.lib.argformats import DelayedArgument
            return bool(DelayedArgument(string).modifiers)
        except Exception:
            return True

    @property
    def string(self):
        value = self._string
        if value is None:
            _codec = self.codec
            _error = None
            codecs = self._CODECS if _codec is None else [_codec, 'latin1']
            for codec in codecs:
                try:
                    value = self.decode(codec)
                except UnicodeError as e:
                    _error = _error or e
                else:
                    self.codec = codec
                    break
            else:
                raise AttributeError(F'Codec unknown: {_error!s}')
        return value

    def __eq__(self, other):
        if isinstance(other, str):
            return self.string == other
        return super().__eq__(other)

    def __hash__(self):
        return hash(self.string)

    def __repr__(self):
        try:
            return self._representation
        except AttributeError:
            pass
        try:
            if not self or any(self[1::2]):
                prefix = None
            else:
                try:
                    representation = self.decode('utf-16le')
                    prefix = 'u'
                except UnicodeDecodeError:
                    prefix = None
            if prefix is None:
                representation = self.string
                prefix = self._CODECS[self.codec]
        except AttributeError:
            representation = None
        else:
            if not is_print_safe(representation):
                representation = None
            elif prefix != 's' or self.requires_prefix(representation):
                representation = F'{prefix}:{representation}'
        if representation is None:
            representation = F'h:{self.hex()}'
        self._representation = representation
        return representation

    def __str__(self):
        return self.string

    def __format__(self, spec):
        return self.string.__format__(spec)


def is_valid_variable_name(name: str) -> bool:
    """
    All single-letter, uppercase variable names are reserved.
    """
    try:
        check_variable_name(name, allow_derivations=True)
    except ValueError:
        return False
    return True


def check_variable_name(name: Optional[str], allow_derivations=False) -> None:
    """
    All single-letter, uppercase variable names are reserved. Additionally, derived
    property names should not be overwritten.
    """
    error = None
    if name is None:
        return None
    elif len(name) == 1 and name.upper() == name:
        error = 'a capitalzed single letter, which are reserved for state machines.'
    elif not name.isidentifier():
        error = 'not an identifier.'
    elif not allow_derivations:
        if name == 'index' or name in LazyMetaOracle.derivations:
            error = 'reserved for a derived property.'
    if error:
        raise ValueError(F'The variable name "{name}" is invalid; it is {error}')
    return name


class SizeInt(int, CustomStringRepresentation):
    """
    The string representation of this int class is a a human-readable expression of size, using
    common units such as kB and MB.
    """
    width = 9
    align = True

    def __str__(self):
        return str(int(self))

    if environment.disable_size_format.value:
        __repr__ = __str__
    else:
        def __repr__(self):
            step = 1000.0
            unit = None
            result = self
            for unit in [None, 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
                if unit and result / step <= 0.1:
                    break
                result /= step
            if unit is None:
                width = 3 if self.align else 1
                return F'{result:{width}} BYTES'
            else:
                width = 6 if self.align else 1
                comma = 3 if self.align else 1
                return F'{result:0{width}.{comma}f} {unit}'


class TerseSizeInt(SizeInt):
    """
    Similar to `refinery.lib.meta.SizeInt`, but the representation does not pad with zeros to
    ensure having the same width for every input.
    """
    align = False


class Percentage(float, CustomStringRepresentation):
    """
    The string representation of this floating point class is a a human-readable expression of a
    percentage. The string representation is a common decimal with 4 digits precision, but casting
    the object using `repr` will yield a percentage.
    """
    def __str__(self):
        return F'{self:.4f}'

    def __repr__(self):
        return F'{self * 100:05.2f}%'


class _NoDerivationAvailable(Exception):
    pass


class _LazyMetaMeta(type):
    def __new__(cls, name: str, bases, namespace: dict):
        derivations: dict = namespace['derivations']
        for obj in namespace.values():
            try:
                obj: _Derivation
                derivations[obj.name] = obj
            except AttributeError:
                pass
        return type.__new__(cls, name, bases, namespace)


def _derivation(name, costly: bool = False, wrap: type = ByteStringWrapper) -> Callable[[_Derivation], _Derivation]:
    def decorator(method: _Derivation) -> _Derivation:
        method.name = name
        method.costly = costly
        method.wrap = wrap
        return method
    return decorator


class LazyMetaOracle(metaclass=_LazyMetaMeta):
    """
    A dictionary that can be queried lazily for all potential options of the common meta variable
    unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed at the
    key `'sha256'`.
    """

    derivations: Dict[str, _Derivation] = {}
    """
    A dictionary mapping the names of common properties to anonymous functions that compute their
    corresponding value on a chunk of binary input data.
    """

    ghost: bool
    chunk: ByteString
    cache: Dict[str, Union[str, int, float]]

    history: Dict[str, List[Tuple[bool, Any]]]
    current: Dict[str, Any]
    updated: Dict[str, bool]

    def __init__(self, chunk: ByteString, scope: Optional[int] = 1, seed: Optional[Dict[str, List[Tuple[bool, Any]]]] = None):
        self.ghost = False
        self.chunk = chunk
        self.cache = {}
        self.scope = scope
        self.tempval = {}
        self.current = {}
        self.updated = {}
        self.rescope = {}
        if seed is not None:
            for key, stack in seed.items():
                if not isinstance(stack, list):
                    raise TypeError(F'Encountered history item of type {typename(stack)}, this should be a list.')
                if len(stack) != scope:
                    raise ValueError(F'History item had length {len(stack)}, but scope was specified as {scope}.')
                for k, v in enumerate(stack):
                    stack[k] = tuple(v)
                for is_link, value in reversed(stack):
                    while is_link:
                        is_link, value = stack[value]
                    if value is not None:
                        self.current[key] = self.autowrap(key, value)
                        self.updated[key] = False
                    break
                else:
                    raise ValueError(R'History item was all None.')
            self.history = seed
        else:
            self.history = {}

    def update(self, other: Union[dict, LazyMetaOracle]):
        if isinstance(other, LazyMetaOracle):
            self.current.update(other.current)
            self.updated.update(other.updated)
            self.tempval.update(other.tempval)
            self.rescope.update(other.rescope)
            self.history = other.history
            return
        for key, value in other.items():
            self[key] = value

    def update_index(self, index: int):
        self['index'] = index

    def inherit(self, parent: LazyMetaOracle):
        """
        This method is called to inherit variables from a parent meta variable dictionary.
        """
        if not self.history:
            self.history = parent.history
        elif self.history is not parent.history:
            for key in parent.current.keys():
                if key not in self.current:
                    self.current[key] = parent.current[key]
                    self.history[key] = parent.history[key]
        self.scope = parent.scope
        for key in parent.keys():
            try:
                derivation = self.derivations[key]
            except KeyError:
                try:
                    self.updated.setdefault(key, False)
                    self.current.setdefault(key, parent.current[key])
                except KeyError:
                    pass
            else:
                if derivation.costly and len(self.chunk) >= 0x1000:
                    continue
                self[key] = derivation.wrap(derivation(self))

    def set_scope(self, key: str, scope: int):
        current = self.scope
        scope = max(1, scope)
        if key not in self.current:
            raise KeyError(key)
        if scope > current:
            raise ValueError(F'Attempt to increase scope level of variable {key} to {scope}, it is currently at {self.scope}.')
        if scope == current:
            return
        self.rescope[key] = scope

    def get_scope(self, key: str):
        value = self.current[key]
        scope = self.scope
        try:
            stack = self.history[key]
        except KeyError:
            return scope
        for k, (is_link, v) in enumerate(reversed(stack)):
            while is_link:
                is_link, v = stack[v]
            if v == value:
                continue
            return scope - k + 1
        return scope

    def serialize(self, scope: int) -> Dict[str, List[Tuple[bool, Any]]]:
        if not scope:
            return {}
        current_scope = self.scope
        if current_scope == 0:
            padding = [(True, 0)] * (scope - 1)
            return {key: [(False, value)] + padding for key, value in self.current.items()}
        serializable = {key: list(stack) for key, stack in self.history.items()}
        if scope > current_scope:
            padding = scope - current_scope
            for key, stack in serializable.items():
                stack.extend(itertools.repeat((True, (current_scope - 1)), padding))
        for key, stack in serializable.items():
            if key not in self.current:
                stack[~0] = (False, None)
        if scope < current_scope:
            for key, stack in serializable.items():
                del stack[scope:]
        for key, value in self.current.items():
            if value is None:
                raise RuntimeError(F'Meta variable "{key}" was set to None.')
            try:
                spot = self.rescope[key]
            except KeyError:
                spot = current_scope
            finally:
                link = None
            if spot == current_scope and not self.updated[key]:
                continue
            if spot > scope:
                continue
            if spot < 0:
                raise RuntimeError('computed a negative spot for variable placement')
            try:
                stack = serializable[key]
            except KeyError:
                serializable[key] = stack = [(False, None)] * scope
            else:
                for k, (is_link, v) in enumerate(stack):
                    if k >= spot:
                        break
                    while is_link:
                        k, is_link, v = v, *stack[v]
                    if v == value:
                        link = k
                        break
            if link is not None:
                stack[spot - 1] = (True, link)
            else:
                stack[spot - 1] = (False, value)
            for k in range(spot, scope):
                stack[k] = (True, spot - 1)
        vanishing_variables = []
        for key, stack in serializable.items():
            if all(v is None for lnk, v in stack if not lnk):
                vanishing_variables.append(key)
        for key in vanishing_variables:
            del serializable[key]
        return serializable

    def items(self):
        yield from self.tempval.items()
        yield from self.current.items()

    def keys(self):
        yield from self.tempval.keys()
        yield from self.current.keys()

    def variable_names(self):
        yield from self.current.keys()

    def values(self):
        return (v for _, v in self.items())

    __iter__ = keys

    def format_str(
        self,
        spec: str,
        codec: str,
        args: Optional[Iterable] = None,
        symb: Optional[dict] = None,
        escaped: bool = False
    ) -> str:
        """
        Formats the input expression like a normal Python format string expression. Certain refinery
        metadata objects have special formatters for the `r`-transformation, as defined by wrapping
        of type `refinery.lib.meta.CustomStringRepresentation`. The following representations are
        defined:

        - `entropy` and `ic` are formatted as a percentage.
        - `sha1`, `sha256`, `sha512`, and `md5` are formatted as hex strings.
        - `size` is formatted as a human-readable size with unit.
        """
        return self.format(spec, codec, args, symb, False, escaped=escaped)

    def format_bin(
        self,
        spec: str,
        codec: str,
        args: Optional[Iterable] = None,
        symb: Optional[dict] = None
    ) -> ByteString:
        """
        Formats the input expression using a Python F-string like expression. These strings contain
        fields in the format `{expression!T:pipeline}`, where `T` is a transformation character and
        the `pipeline` part is a sequence of `refinery.lib.argformats.multibin` handlers which are
        parsed in reverse. For example, the expression `{v:b64:hex}` will first decode the contents
        of `v` using `refinery.b64`, and then decode the result using `refinery.hex`.

        The transformation character is only required when `expression` is a literal; it specifies
        how to convert the literal to a binary string. The following transformations can be applied:

        - `a`: literal is to be encoded using latin1
        - `u`: literal is to be encoded using utf16
        - `s`: literal is to be encoded using the default codec
        - `q`: literal is a URL-encoded binary string
        - `h`: literal is a hex-encoded binary string
        - `e`: literal is an escaped ASCII string
        """
        return self.format(spec, codec, args, symb, True)

    def format(
        self,
        spec    : str,
        codec   : str,
        args    : Union[list, tuple],
        symb    : dict,
        binary  : bool,
        fixup   : bool = True,
        used    : Optional[set] = None,
        escaped : bool = False
    ) -> Union[str, ByteString]:
        """
        Formats a string using Python-like string fomatting syntax. The formatter for `binary`
        mode is different; each formatting is documented in one of the following two proxy methods:

        - `refinery.lib.meta.LazyMetaOracle.format_str`
        - `refinery.lib.meta.LazyMetaOracle.format_bin`
        """
        # prevents circular import:
        from refinery.lib.argformats import (
            multibin, ParserError, PythonExpression, pending, Chunk)

        symb = symb or {}

        if used is None:
            class dummy:
                def add(self, _): pass
            used = dummy()

        if args is None:
            args = ()
        elif not isinstance(args, (list, tuple)):
            args = list(args)

        if fixup:
            for (store, it) in (
                (args, enumerate(args)),
                (symb, symb.items()),
            ):
                for key, value in it:
                    with contextlib.suppress(TypeError):
                        if isinstance(value, CustomStringRepresentation):
                            continue
                        store[key] = ByteStringWrapper(value, codec)

        formatter = string.Formatter()
        autoindex = 0

        if binary:
            stream = MemoryFile()
            def putstr(s: str): stream.write(s.encode(codec))
        else:
            stream = StringIO()
            putstr = stream.write

        with stream:
            for prefix, field, modifier, conversion in formatter.parse(spec):
                output = value = None
                if prefix:
                    if binary:
                        prefix = prefix.encode(codec)
                    elif escaped:
                        prefix = prefix.encode('raw-unicode-escape').decode('unicode-escape')
                    stream.write(prefix)
                if field is None:
                    continue
                if not field:
                    if not args:
                        raise LookupError('no positional arguments given to formatter')
                    value = args[autoindex]
                    used.add(autoindex)
                    if autoindex < len(args) - 1:
                        autoindex += 1
                if binary and conversion:
                    conversion = conversion.lower()
                    if conversion == 'h':
                        value = bytes.fromhex(field)
                    elif conversion == 'q':
                        value = unquote_to_bytes(field)
                    elif conversion == 's':
                        value = field.encode(codec)
                    elif conversion == 'u':
                        value = field.encode('utf-16le')
                    elif conversion == 'a':
                        value = field.encode('latin1')
                    elif conversion == 'e':
                        value = field.encode(codec).decode('unicode-escape').encode('latin1')
                elif field in symb:
                    value = symb[field]
                    used.add(field)
                if value is None:
                    with contextlib.suppress(ValueError, IndexError):
                        index = int(field, 0)
                        value = args[index]
                        used.add(index)
                if value is None:
                    with contextlib.suppress(KeyError):
                        value = self[field]
                        used.add(field)
                if value is None:
                    try:
                        expression = PythonExpression(field, *self, *symb)
                        value = expression(self, **symb)
                    except ParserError:
                        if not self.ghost:
                            raise KeyError(field)
                        putstr(F'{{{field}')
                        if conversion:
                            putstr(F'!{conversion}')
                        if modifier:
                            putstr(F':{modifier}')
                        putstr('}')
                        continue
                if binary:
                    modifier = modifier.strip()
                    if modifier:
                        expression = self.format(modifier, codec, args, symb, True, False, used)
                        output = multibin(expression.decode(codec), reverse=True, seed=value)
                        if pending(output):
                            output = output(Chunk(value, meta=self))
                    elif isbuffer(value):
                        output = value
                    elif not isinstance(value, int):
                        with contextlib.suppress(TypeError):
                            output = bytes(value)
                if output is None:
                    converter = {
                        'a': ascii,
                        's': str,
                        'r': repr,
                        'H': lambda b: b.hex().upper(),
                        'h': lambda b: b.hex(),
                        'u': lambda b: b.decode('utf-16le'),
                        'e': lambda b: repr(bytes(b)).lstrip('bBrR')[1:-1],
                        'q': lambda b: quote_from_bytes(bytes(b))
                    }.get(conversion)
                    if converter:
                        output = converter(value)
                    elif modifier:
                        output = value
                    elif isinstance(value, CustomStringRepresentation):
                        output = str(value)
                    elif isbuffer(value):
                        output = value.decode('utf8', errors='replace')
                    else:
                        output = value
                    output = output.__format__(modifier)
                    if binary:
                        output = output.encode(codec)
                stream.write(output)
            return stream.getvalue()

    def knows(self, key):
        return (
            key in self.current or # noqa
            key in self.tempval or # noqa
            key in self.cache
        )

    def __contains__(self, key):
        return (
            key in self.current or # noqa
            key in self.tempval or # noqa
            key in self.derivations
        )

    def __len__(self):
        return len(self.current) + len(self.tempval)

    def autowrap(self, key, value):
        try:
            wrap = self.derivations[key].wrap
        except KeyError:
            wrap = ByteStringWrapper
        if not isinstance(value, wrap):
            with contextlib.suppress(TypeError):
                value = ByteStringWrapper(value)
        return value

    def __setitem__(self, key, value):
        new = self.autowrap(key, value)
        if not is_valid_variable_name(key):
            self.tempval[key] = new
            return
        self.current[key] = new
        try:
            stack = self.history[key]
            lnk, old = stack[-1]
        except KeyError:
            self.updated[key] = True
        else:
            while lnk:
                lnk, old = stack[old]
            self.updated[key] = (old != new)

    class nodefault:
        pass

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key, default=nodefault):
        try:
            value = self[key]
        except KeyError:
            if default is self.nodefault:
                raise
            return default
        else:
            self.discard(key)
            return value

    def __getitem__(self, key):
        try:
            value = self.current[key]
        except KeyError:
            try:
                return self.tempval[key]
            except KeyError:
                pass
            return self.__missing__(key)
        if isinstance(value, str):
            value = value.encode('utf8')
        return value

    def discard(self, key):
        try:
            del self.current[key]
        except KeyError:
            try:
                del self.tempval[key]
            except KeyError:
                pass

    __delitem__ = discard

    def __getattr__(self, key):
        if key not in self.current:
            deduction = self.derivations.get(key)
            if deduction is None:
                raise AttributeError(key)
            return deduction.wrap(deduction(self))
        else:
            return self[key]

    def __missing__(self, key):
        try:
            return self.cache[key]
        except KeyError:
            pass
        deduction = self.derivations.get(key)
        if deduction is None:
            raise KeyError(F'The meta variable {key} is unknown.')
        try:
            value = deduction.wrap(deduction(self))
        except _NoDerivationAvailable:
            raise KeyError(F'unable to derive the {key} property here, you have to use the cm unit.')
        else:
            self.cache[key] = value
            return value

    def derive(self, key):
        self[key] = self[key]

    @_derivation('mime')
    def _derive_mime(self):
        from refinery.lib.mime import get_cached_file_magic_info
        return get_cached_file_magic_info(self.chunk).mime

    @_derivation('ext')
    def _derive_ext(self):
        from refinery.lib.mime import get_cached_file_magic_info
        return get_cached_file_magic_info(self.chunk).extension

    @_derivation('magic')
    def _derive_magic(self):
        from refinery.lib.mime import get_cached_file_magic_info
        return get_cached_file_magic_info(self.chunk).description

    @_derivation('size', wrap=SizeInt)
    def _derive_size(self):
        return len(self.chunk)

    @_derivation('entropy', True, Percentage)
    def _derive_entropy(self):
        return entropy(self.chunk)

    @_derivation('ic', True, Percentage)
    def _derive_ic(self):
        return index_of_coincidence(self.chunk)

    @_derivation('crc32')
    def _derive_crc32(self):
        import zlib
        return (zlib.crc32(self.chunk) & 0xFFFFFFFF).to_bytes(4, 'big').hex()

    @_derivation('sha1', True)
    def _derive_sha1(self):
        import hashlib
        return hashlib.sha1(self.chunk).hexdigest()

    @_derivation('sha256', True)
    def _derive_sha256(self):
        import hashlib
        return hashlib.sha256(self.chunk).hexdigest()

    @_derivation('sha512', True)
    def _derive_sha512(self):
        import hashlib
        return hashlib.sha512(self.chunk).hexdigest()

    @_derivation('md5', True)
    def _derive_md5(self):
        import hashlib
        return hashlib.md5(self.chunk).hexdigest()


def metavars(chunk: Union[Chunk, ByteString]) -> LazyMetaOracle:
    """
    This method is the main function used by refinery units to get the meta variable dictionary
    of an input chunk. This dictionary is wrapped using the `refinery.lib.meta.LazyMetaOracleFactory`
    so that access to common variables is always possible.
    """
    try:
        meta = chunk.meta
    except AttributeError:
        meta = LazyMetaOracle(chunk)
    else:
        if not isinstance(meta, LazyMetaOracle):
            raise TypeError(F'Invalid meta variable dictionary on chunk: {meta!r}')
    return meta
