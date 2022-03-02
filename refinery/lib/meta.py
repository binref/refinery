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
- The `refinery.struct` parses structured data from the beginning of a chunk into meta variables.
- You can use named capture groups in regular expressions when using the `refinery.rex` unit, and
  these matches will be stored under their name as a meta variable in each output chunk.
- There are units that extract data from archive-like formats. Some examples are `refinery.xtzip`,
  `refinery.xtmail`, `refinery.winreg`, and `refinery.perc`. These units will enrich their output
  chunks with a metadata variable indicating the (virtual) path of the extracted item.

### Variable Reference Handlers

There are a number of ways in which meta variables can be used. The most straightforward way is to
use the `refinery.lib.argformats.DelayedArgument.var` handler to read the contents of a variable
and use it as part of a multibin expression. The `refinery.lib.argformats.DelayedArgument.xvar`
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

    ef ** [| cm size | sha256 -t | cfmt {size!r} {entropy!r} {md5} {path} ]]

Another example would be the following command, which dumps the base64 encoded buffer of length at
least 200 from the input to incrementally numbered files:

    emit sample | carve --min=200 b64 [| dump buffer{index}.b64 ]

### Using Push And Pop

The `refinery.push` and `refinery.pop` units can be used to extract sub-pipelines as variables. For
example, the following command extracts the files from a password-protected attachment of an email
message by first extracting the password from the email message body:

    $ emit phish.eml | push [[
    >   | xtmail body.txt | rex -I password:\s*(\w+) {1} | pop password ]
    >   | xtmail evil.zip | xtzip -p var:password | dump {path} ]

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
import hashlib
import string
import zlib
import codecs

from io import StringIO
from urllib.parse import quote_from_bytes, unquote_to_bytes
from typing import Callable, Dict, Iterable, Optional, ByteString, Union

from refinery.lib.structures import MemoryFile
from refinery.lib.tools import isbuffer, entropy, index_of_coincidence
from refinery.lib.mime import get_cached_file_magic_info
from refinery.lib.patterns import formats


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

    def requires_prefix(self) -> bool:
        try:
            from refinery.lib.argformats import DelayedArgument
            return bool(DelayedArgument(self.string).modifiers)
        except Exception:
            return True

    @property
    def string(self):
        value = self._string
        if value is None:
            _codec = self.codec
            codecs = self._CODECS if _codec is None else [_codec]
            for codec in codecs:
                try:
                    value = self.decode(codec)
                except UnicodeDecodeError:
                    pass
                else:
                    self.codec = codec
                    break
            else:
                raise AttributeError('Codec unknown.')
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
            representation = self.string
        except AttributeError:
            representation = None
        else:
            if not formats.printable.fullmatch(representation):
                representation = None
            else:
                prefix = self._CODECS[self.codec]
                if prefix != 's' or self.requires_prefix():
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
    if len(name) == 1 and name.upper() == name:
        return False
    if not name.isidentifier():
        return False
    return True


def check_variable_name(name: Optional[str]) -> Optional[str]:
    """
    All single-letter, uppercase variable names are reserved.
    """
    if name is None:
        return None
    elif is_valid_variable_name(name):
        return name
    raise ValueError(
        F'The variable name {name!r} is invalid: Variable names must be identifiers. Additionally, single uppercase '
        R'letters are reserved for internal use.'
    )


class SizeInt(int, CustomStringRepresentation):
    """
    The string representation of this int class is a a human-readable expression of size, using
    common units such as kB and MB.
    """
    width = 9

    def _s(self, align):
        step = 1000.0
        unit = None
        result = self
        for unit in [None, 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
            if unit and result / step <= 0.1:
                break
            result /= step
        if unit is None:
            width = 3 if align else ''
            return F'{result:{width}} BYTES'
        else:
            width = 6 if align else ''
            return F'{result:{width}.3f} {unit}'

    def __repr__(self):
        return self._s(True)

    def __str__(self):
        return int.__str__(self)


class Percentage(float, CustomStringRepresentation):
    """
    The string representation of this floating point class is a a human-readable expression of a
    percentage. The string representation is a common decimal with 4 digits precision, but casting
    the object using `repr` will yield a percentage.
    """
    def __str__(self):
        return F'{self:.4f}'

    def __repr__(self):
        return F'{self*100:05.2f}%'


class HexByteString(bytes, CustomStringRepresentation):
    def __str__(self):
        return self.hex()

    def __repr__(self):
        return self.hex()


class _NoDerivationAvailable(Exception):
    pass


class _LazyMetaMeta(type):
    def __new__(cls, name: str, bases, namespace: dict):
        derivations: dict = namespace['DERIVATION_MAP']
        for obj in namespace.values():
            try:
                derivations[obj.name] = obj
            except AttributeError:
                pass
        return type.__new__(cls, name, bases, namespace)


def _derivation(name):
    def decorator(method):
        method.name = name
        return method
    return decorator


class LazyMetaOracle(dict, metaclass=_LazyMetaMeta):
    """
    A dictionary that can be queried lazily for all potential options of the common meta variable
    unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed at the
    key `'sha256'`.
    """

    CUSTOM_TYPE_MAP = {
        'entropy' : Percentage,
        'size'    : SizeInt,
        'sha1'    : HexByteString,
        'sha256'  : HexByteString,
        'sha512'  : HexByteString,
        'md5'     : HexByteString,
        'crc32'   : HexByteString,
    }

    DERIVATION_MAP: Dict[str, Callable[[LazyMetaOracle], Union[str, int, float]]] = {}
    """
    A dictionary mapping the names of common properties to anonymous functions that compute their
    corresponding value on a chunk of binary input data.
    """

    ghost: bool
    chunk: ByteString

    def __init__(self, chunk: ByteString, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ghost = False
        self.chunk = chunk
        self.fix()

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self.fix()

    def fix(self):
        for key, value in self.items():
            try:
                ctype = self.CUSTOM_TYPE_MAP[key]
            except KeyError:
                if isinstance(value, ByteStringWrapper):
                    continue
                with contextlib.suppress(TypeError):
                    self[key] = ByteStringWrapper(value)
            else:
                if not isinstance(value, ctype) and issubclass(ctype, type(value)):
                    self[key] = ctype(value)
        return self

    def update_index(self, index: int):
        self['index'] = index

    def serializable(self) -> dict:
        return self

    def items(self):
        for key, value in super().items():
            if not is_valid_variable_name(key):
                continue
            yield key, value

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
        from refinery.lib.argformats import multibin, ParserError, PythonExpression
        # prevents circular import

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
                (self, self.items()),
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

    def __contains__(self, key):
        return super().__contains__(key) or key in self.DERIVATION_MAP

    def __getitem__(self, key):
        item = super().__getitem__(key)
        if isinstance(item, str):
            return item.encode('utf8')
        return item

    def __getattr__(self, key):
        if not super().__contains__(key):
            deduction = self.DERIVATION_MAP.get(key)
            if deduction is None:
                raise AttributeError(key)
            return deduction(self)
        else:
            return self[key]

    def __missing__(self, key):
        deduction = self.DERIVATION_MAP.get(key)
        if deduction is None:
            raise KeyError(F'The meta variable {key} is unknown.')
        try:
            return self.setdefault(key, deduction(self))
        except _NoDerivationAvailable:
            raise KeyError(F'unable to derive the {key} property here, you have to use the cm unit.')

    def discard(self, key):
        try:
            dict.__delitem__(self, key)
        except KeyError:
            pass

    @_derivation('mime')
    def _derive_mime(self):
        return get_cached_file_magic_info(self.chunk).mime

    @_derivation('ext')
    def _derive_ext(self):
        return get_cached_file_magic_info(self.chunk).extension

    @_derivation('magic')
    def _derive_magic(self):
        return get_cached_file_magic_info(self.chunk).description

    @_derivation('size')
    def _derive_size(self):
        return SizeInt(len(self.chunk))

    @_derivation('entropy')
    def _derive_entropy(self):
        return Percentage(entropy(self.chunk))

    @_derivation('ic')
    def _derive_ic(self):
        return Percentage(index_of_coincidence(self.chunk))

    @_derivation('crc32')
    def _derive_crc32(self):
        return HexByteString((zlib.crc32(self.chunk) & 0xFFFFFFFF).to_bytes(4, 'big'))

    @_derivation('sha1')
    def _derive_sha1(self):
        return HexByteString(hashlib.sha1(self.chunk).digest())

    @_derivation('sha256')
    def _derive_sha256(self):
        return HexByteString(hashlib.sha256(self.chunk).digest())

    @_derivation('sha512')
    def _derive_sha512(self):
        return HexByteString(hashlib.sha512(self.chunk).digest())

    @_derivation('md5')
    def _derive_md5(self):
        return HexByteString(hashlib.md5(self.chunk).digest())


def metavars(chunk, ghost: bool = False) -> LazyMetaOracle:
    """
    This method is the main function used by refinery units to get the meta variable dictionary
    of an input chunk. This dictionary is wrapped using the `refinery.lib.meta.LazyMetaOracleFactory`
    so that access to common variables is always possible.
    """
    meta: Union[dict, LazyMetaOracle] = getattr(chunk, 'meta', {})
    if not isinstance(meta, LazyMetaOracle):
        if not isinstance(meta, dict):
            raise TypeError('Invalid meta type.')
        meta = LazyMetaOracle(chunk, meta)
    meta.ghost = ghost
    return meta
