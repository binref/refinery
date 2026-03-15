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

The units `refinery.pf`, `refinery.dump`, and `refinery.run` support format string expressions that
can contain meta variables. For example, the following command will print a recursive listing of
the current directory with human-readable file sizes, entropy in percent, and the md5 hash of each
file:

    ef ** [| pf {size!r} {entropy!r} {md5} {path} ]]

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
import codecs
import contextlib
import itertools
import os
import re
import string

from typing import TYPE_CHECKING, Any, Callable

from refinery.lib.environment import environment
from refinery.lib.mime import get_cached_file_magic_info
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import entropy, index_of_coincidence
from refinery.lib.types import buf, isbuffer, typename

if TYPE_CHECKING:
    from typing import Protocol

    from refinery.lib.frame import Chunk

    class _Derivation(Protocol):
        costly: bool
        name: str
        wrap: type

        def __call__(self, object: LazyMetaOracle) -> str | int | float:
            ...


class CustomStringRepresentation(abc.ABC):
    """
    This abstract class defines an interface for wrapper classes used in `refinery.lib.meta.LazyMetaOracleFactory`.
    These classes have to implement a `str` and `repr` typecast that can be used for the conversion part of a
    format string expression.
    """

    @abc.abstractmethod
    def __str__(self) -> str:
        ...

    @abc.abstractmethod
    def __repr__(self) -> str:
        ...


_INDEX = 'index'
_BIGINT = '__bi__'

_HIGH_ASCII = '¹²³«»¡¿¼½¾¢£¥§©®±µ·÷øÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöùúûüýþÿ'
_8BIT_ASCII = string.printable + _HIGH_ASCII
_PRINT_SAFE = set(_8BIT_ASCII.encode('latin1')) - set(b'|<>\t\n\r\v')
if os.name == 'nt':
    _PRINT_SAFE -= set(b'^"')
else:
    _PRINT_SAFE -= set(b'&*?\'"')

_PT = bytearray(256)
for p in _PRINT_SAFE:
    _PT[p] = 1


def is_print_safe(string: str):
    return string.isprintable() or not any(
        (code := ord(letter)) < len(_PT) and not _PT[code] for letter in string
    )


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

    @classmethod
    def Wrap(cls, string: str | buf | ByteStringWrapper, codec: str | None = None):
        if isinstance(string, cls):
            return string
        return cls(string, codec=codec)

    def __init__(self, string: str | buf, codec: str | None = None):
        if isinstance(string, str):
            self._string = string
            codec = codec or 'utf8'
            string = string.encode(codec)
        elif isbuffer(string):
            self._string = None
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
                    self._string = value = self.decode(codec)
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
            return self._pretty
        except AttributeError:
            pass
        try:
            pretty = None
            prefix = None
            if self and not any(self[1::2]):
                try:
                    pretty = self.decode('utf-16le')
                except UnicodeDecodeError:
                    pass
                else:
                    prefix = 'u'
            if pretty is None:
                pretty = self.string
                prefix = self._CODECS[c] if (c := self.codec) else None
        except AttributeError:
            pretty = None
        else:
            if not is_print_safe(pretty):
                pretty = None
            elif prefix != 's' or self.requires_prefix(pretty):
                pretty = F'{prefix}:{pretty}'
        if pretty is None:
            pretty = F'h:{self.hex()}'
        self._pretty = pretty
        return pretty

    def __str__(self):
        return self.string

    def __format__(self, spec):
        return self.string.__format__(spec)


def is_valid_variable_name(name: str, allow_wildcards: bool = False) -> bool:
    """
    All single-letter, uppercase variable names are reserved.
    """
    if allow_wildcards:
        parts = re.split(r'([\*\?\[\]])', name)
        brackets = 0
        for p in itertools.islice(parts, 1, None, 2):
            if p == '[':
                brackets += 1
            if p == ']':
                brackets -= 1
            if brackets < 0:
                return False
        if brackets != 0:
            return False
        parts = parts[0::2]
    else:
        parts = [name]
    try:
        for part in parts:
            check_variable_name(part, allow_derivations=True)
    except ValueError:
        return False
    else:
        return True


def check_variable_name(name: str | None, allow_derivations=False) -> str | None:
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
        if name == _INDEX or name in LazyMetaOracle.derivations:
            error = 'reserved for a derived property.'
    if error:
        raise ValueError(F'The variable name "{name}" is invalid; it is {error}')
    return name


class SizeInt(int, CustomStringRepresentation):
    """
    The string representation of this int class is a human-readable expression of size, using
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
    The string representation of this floating point class is a human-readable expression of a
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


def _derivation(name, costly: bool = False, wrap: type = ByteStringWrapper) -> Callable[
    [Callable[['LazyMetaOracle'], str | int | float]], _Derivation
]:
    def decorator(method) -> _Derivation:
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

    IndexKey = _INDEX

    derivations: dict[str, _Derivation] = {}
    """
    A dictionary mapping the names of common properties to anonymous functions that compute their
    corresponding value on a chunk of binary input data.
    """

    chunk: buf
    cache: dict[str, str | int | float]
    index: int | None

    history: dict[str, list[tuple[bool, Any]]]
    current: dict[str, Any]
    updated: dict[str, bool]

    def __init__(self, chunk: buf, scope: int = 1, seed: dict[str, list[tuple[bool, Any]]] | None = None):
        self.chunk = chunk
        self.cache = {}
        self.index = None
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
                for k, (x, y) in enumerate(stack):
                    stack[k] = (x, y)
                for is_link, value in reversed(stack):
                    while is_link:
                        is_link, value = stack[value]
                    try:
                        bigint: bytes = value[_BIGINT]
                    except Exception:
                        pass
                    else:
                        value = int.from_bytes(bigint)
                    if value is not None:
                        self.current[key] = self.autowrap(key, value)
                        self.updated[key] = False
                    break
                else:
                    raise ValueError(R'History item was all None.')
            self.history = seed
        else:
            self.history = {}

    def update(self, other: dict | LazyMetaOracle):
        if isinstance(other, LazyMetaOracle):
            self.current.update(other.current)
            self.updated.update(other.updated)
            self.tempval.update(other.tempval)
            self.rescope.update(other.rescope)
            self.history = other.history
            return
        for key, value in other.items():
            self[key] = value

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

    def serialize(self, target_scope: int) -> dict[str, list[tuple[bool, Any]]]:
        if not target_scope:
            return {}
        current_scope = self.scope
        if current_scope == 0:
            padding = [(True, 0)] * (target_scope - 1)
            return {key: [(False, value)] + padding for key, value in self.current.items()}
        serializable = {key: list(stack) for key, stack in self.history.items()}
        if target_scope > current_scope:
            padding = target_scope - current_scope
            for key, stack in serializable.items():
                stack.extend(itertools.repeat((True, (current_scope - 1)), padding))
        for key, stack in serializable.items():
            if key not in self.current:
                stack[~0] = (False, None)
        if target_scope < current_scope:
            for key, stack in serializable.items():
                del stack[target_scope:]
        for key, value in self.current.items():
            if value is None:
                raise RuntimeError(F'Meta variable "{key}" was set to None.')
            elif isinstance(value, int) and value > 0xFFFFFFFFFFFFFFFF:
                q, r = divmod(value.bit_length(), 8)
                q += int(bool(r))
                value = {_BIGINT: value.to_bytes(q)}
            try:
                item_scope = self.rescope[key]
            except KeyError:
                item_scope = current_scope
            if item_scope == current_scope and not self.updated[key]:
                continue
            if item_scope > target_scope:
                continue
            link = index = item_scope - 1
            if index < 0:
                raise RuntimeError('computed a negative index for variable placement')
            try:
                stack: list[tuple[bool, Any]] = serializable[key]
            except KeyError:
                serializable[key] = stack = [(False, None)] * target_scope
            else:
                for k, (is_link, v) in enumerate(stack):
                    if k > index:
                        break
                    while is_link:
                        k, is_link, v = v, *stack[v]
                    if v == value:
                        link = k
                        break
            if link < index:
                stack[index] = (True, link)
            else:
                stack[index] = (False, value)
            for k in range(index + 1, target_scope):
                stack[k] = (True, index)
        vanishing_variables = []
        for key, stack in serializable.items():
            if all(v is None for lnk, v in stack if not lnk):
                vanishing_variables.append(key)
        for key in vanishing_variables:
            del serializable[key]
        return serializable

    def items(self):
        yield (_INDEX, self.index)
        yield from self.tempval.items()
        yield from self.current.items()

    def keys(self):
        yield _INDEX
        yield from self.tempval.keys()
        yield from self.current.keys()

    def variable_names(self):
        yield _INDEX
        yield from self.current.keys()

    def values(self):
        yield from (v for _, v in self.items())

    __iter__ = keys

    def format_str(
        self,
        spec: str,
        codec: str,
        args: list | tuple = (),
        symb: dict | None = None,
        used: set | None = None,
        escaped: bool = False,
        lenient: bool = False,
    ) -> str:
        """
        Formats the input expression and returns a string. This is a thin wrapper around
        `refinery.lib.meta.LazyMetaOracle.format` that decodes the resulting bytes.
        """
        return self.format(spec, codec, args, symb, used=used, escaped=escaped, lenient=lenient).decode(codec)

    def format_bin(
        self,
        spec: str,
        codec: str,
        args: list | tuple = (),
        symb: dict | None = None,
        used: set | None = None,
        escaped: bool = False,
        lenient: bool = False,
    ) -> bytearray:
        """
        Formats the input expression and returns bytes. This is a thin wrapper around
        `refinery.lib.meta.LazyMetaOracle.format`.
        """
        return self.format(spec, codec, args, symb, used=used, escaped=escaped, lenient=lenient)

    def format(
        self,
        spec    : str,
        codec   : str,
        args    : list | tuple = (),
        symb    : dict | None = None,
        used    : set | None = None,
        escaped : bool = False,
        lenient : bool = False,
    ) -> bytearray:
        """
        Formats a string using Python-like string formatting syntax and always returns bytes.
        Format fields use the syntax `{field!format:suffix}`:

        - **field**: A Python expression evaluated against meta variables.
        - **!format** (optional): One of `r`, `s`, `a`, `u`, `h`, `q`, `n`, `z`.
        - **:suffix** (optional): A multibin pipeline applied to the seed value.

        Modifier semantics:

        - `!r`: Takes `repr()` of the resolved value.
        - `!s`: Field is a UTF-8 string literal, not a variable.
        - `!a`: Field is a latin1 string literal.
        - `!u`: Field is a UTF-16LE string literal.
        - `!h`: Field is a hex-encoded literal (shortcut for `!s:h`).
        - `!q`: Field is a URL-encoded literal (shortcut for `!s:q`).
        - `!n`: Field is an escape-sequence literal (shortcut for `!s:n`).
        - `!z`: Field evaluates to integer N; returns N zero bytes.
        """
        from refinery.lib.argformats import (
            Chunk,
            DelayedNumSeqArgument,
            ParserError,
            PythonExpression,
        )

        if symb is None:
            symb = {}
        formatter = string.Formatter()
        autoindex = 0
        stream = MemoryFile()

        def _reconstruct():
            r = F'{{{field}'
            if conversion:
                r = F'{r}!{conversion}'
            if modifier:
                r = F'{r}:{modifier}'
            stream.write(F'{r}}}'.encode(codec))

        def _write(v):
            if isinstance(v, (bytes, bytearray, memoryview)):
                return stream.write(v)
            if not isinstance(v, str):
                v = str(v)
            return stream.write(v.encode(codec))

        with stream:
            for prefix, field, modifier, conversion in formatter.parse(spec):
                value = None

                if prefix:
                    if escaped:
                        prefix = prefix.encode('latin1').decode('unicode-escape')
                    stream.write(prefix.encode(codec))

                if field is None:
                    continue

                if not field:
                    if not args:
                        raise LookupError(
                            'The format string contains a positional placeholder {} but no'
                            ' positional arguments were given. Use {{ and }} for literal'
                            ' braces.')
                    value = args[autoindex]
                    if used is not None:
                        used.add(autoindex)
                    if autoindex < len(args) - 1:
                        autoindex += 1

                if conversion:
                    conversion = conversion.lower()
                    if conversion == 's':
                        value = field.encode('utf-8')
                    elif conversion == 'a':
                        value = field.encode('latin-1')
                    elif conversion == 'u':
                        value = field.encode('utf-16-le')
                    elif conversion == 'h':
                        value = bytes.fromhex(field)
                    elif conversion == 'q':
                        from urllib.parse import unquote_to_bytes
                        value = unquote_to_bytes(field)
                    elif conversion == 'n':
                        value = field.encode('latin-1').decode('unicode-escape').encode('latin-1')
                    elif conversion == 'r':
                        pass
                    elif conversion == 'z':
                        pass
                    else:
                        raise ValueError(
                            F'Unknown format modifier !{conversion}; the supported modifiers'
                            F' are: !r, !s, !a, !u, !h, !q, !n, !z.')

                _literal = conversion in ('s', 'a', 'u', 'h', 'q', 'n')

                if value is None and not _literal:
                    if field in symb:
                        value = symb[field]
                        if used is not None:
                            used.add(field)

                if value is None and not _literal:
                    with contextlib.suppress(ValueError, IndexError):
                        index = int(field, 0)
                        value = args[index]
                        if used is not None:
                            used.add(index)

                if value is None and not _literal:
                    with contextlib.suppress(KeyError):
                        value = self[field]
                        if used is not None:
                            used.add(field)

                if value is None and not _literal:
                    try:
                        field_resolved = self.format(field, codec, args, symb, used, escaped)
                        field_resolved = field if field_resolved is None else field_resolved.decode(codec)
                    except Exception:
                        field_resolved = field
                    try:
                        expression = PythonExpression(field_resolved, *self, *symb)
                        value = expression(self, **symb)
                    except ParserError:
                        if modifier:
                            value = field_resolved
                        elif lenient:
                            _reconstruct()
                            continue
                        else:
                            raise KeyError(F'The expression "{field}" could not be resolved. Use {{{{ and }}}} for literal braces.')
                    except Exception:
                        value = B''

                if conversion == 'z':
                    if value is None:
                        try:
                            value = int(field)
                        except (ValueError, TypeError):
                            raise ValueError(F'The !z modifier requires an integer, got: {field}')
                    elif not isinstance(value, int):
                        try:
                            value = int(value)
                        except (ValueError, TypeError):
                            raise ValueError(F'The !z modifier requires an integer, got: {value!r}')
                    value = bytes(value)

                if conversion == 'r' and value is not None:
                    value = repr(value)

                if value is None:
                    if lenient:
                        _reconstruct()
                        continue
                    raise KeyError(F'The expression "{field}" could not be resolved. Use {{{{ and }}}} for literal braces.')

                if modifier:
                    if not _literal:
                        try:
                            converted = ByteStringWrapper.Wrap(value, codec)
                        except TypeError:
                            if conversion == 'r':
                                converted = value
                            elif isinstance(value, CustomStringRepresentation):
                                converted = str(value)
                            else:
                                converted = value
                        if not isbuffer(converted):
                            try:
                                output = converted.__format__(modifier)
                            except Exception:
                                output = None
                            if output is not None:
                                _write(output)
                                continue
                    else:
                        converted = value
                    modifier_resolved = modifier.strip()
                    expression = self.format(
                        modifier_resolved, codec, args, symb, used, escaped)
                    output = DelayedNumSeqArgument(
                        expression.decode(codec), reverse=True, seed=converted)
                    _write(output(Chunk(converted, meta=self)))
                else:
                    _write(value)

        return stream.getvalue()

    def knows(self, key):
        return (
            key in self.current or # noqa
            key in self.tempval or # noqa
            key in self.cache
        )

    def __contains__(self, key):
        return (
            key == _INDEX
            or key in self.current
            or key in self.tempval
            or key in self.derivations
        )

    def clear(self):
        self.current.clear()
        self.tempval.clear()

    def __len__(self):
        return len(self.current) + len(self.tempval)

    def autowrap(self, key, value):
        try:
            wrap = self.derivations[key].wrap
        except KeyError:
            wrap = ByteStringWrapper
        if not isinstance(value, wrap):
            with contextlib.suppress(TypeError):
                value = wrap(value)
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
        if key == _INDEX:
            return self.index
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
        return get_cached_file_magic_info(self.chunk).mime

    @_derivation('ext')
    def _derive_ext(self):
        return get_cached_file_magic_info(self.chunk).extension

    @_derivation('magic')
    def _derive_magic(self):
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


def metavars(chunk: Chunk | buf) -> LazyMetaOracle:
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
