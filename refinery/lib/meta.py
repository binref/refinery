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
    >   | xtmail body.txt | rex -I password:\s*(\w+) $1 | pop password ]
    >   | xtmail evil.zip | xtzip -p var:password | dump {path} ]

The `refinery.push` unit emits two copies of the input data, and the second copy has been moved out
of scope (it is not visible). The first `refinery.xtmail` unit extracts the `body.txt` part and we
obtain the password using `refinery.rex`. The `refinery.pop` unit consumes the first input and will
populate the meta variable dictionaries of all subsequent chunks with a variable named `password`
which contains the data from that first chunk. Note that `refinery.pop` can also be used in other
ways to merge down the metadata from chunks inside sub-pipelines.
"""
import abc
import contextlib
import hashlib
import string
import zlib
import codecs

from io import StringIO
from typing import Callable, Dict, Optional, ByteString, Union

from .structures import MemoryFile
from .tools import isbuffer, entropy, index_of_coincidence
from .mime import get_cached_file_magic_info
from .loader import load_pipeline


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


class ByteStringWrapper(CustomStringRepresentation):
    """
    Represents a binary string and a preferred codec in case it is printable. Casting this wrapper class
    will decode the string using the given codec, using backslash escape sequences to handle decoding
    errors. The `repr` case returns a hexadecimal representation of the binary data. Finally, the object
    proxies attribute access to the wrapped binary string.
    """

    def __init__(self, string: Union[str, ByteString], codec: str = 'latin1', error: str = 'backslashreplace'):
        if isinstance(string, str):
            self._binary = None
            self._string = string
            self._buffer = False
        elif isbuffer(string):
            self._binary = string
            self._string = None
            self._buffer = True
        else:
            raise TypeError(F'The argument {string!r} is not a buffer or string.')
        self.codec = codec
        self.error = error

    @property
    def binary(self):
        value = self._binary
        if value is None:
            encoded = codecs.encode(self._string, self.codec, self.error)
            self._binary = value = memoryview(encoded)
        return value

    @property
    def string(self):
        value = self._string
        if value is None:
            self._string = value = codecs.decode(self._binary, self.codec, self.error)
        return value

    def __getattr__(self, key):
        return getattr(self.binary, key)

    def __repr__(self):
        if self._buffer:
            return self._binary.hex().lower()
        return self._string

    def __bytes__(self):
        value = self.binary
        if isinstance(value, memoryview):
            value = value.obj
        if isinstance(value, bytearray):
            value = bytes(value)
        return value

    def __str__(self):
        return self.string

    def __format__(self, spec):
        return self.string.__format__(spec)


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


COMMON_PROPERTIES: Dict[str, Callable[[ByteString], Union[str, int, float]]] = {
    'mime'    : lambda chunk: get_cached_file_magic_info(chunk).mime,
    'ext'     : lambda chunk: get_cached_file_magic_info(chunk).extension,
    'magic'   : lambda chunk: get_cached_file_magic_info(chunk).description,
    'size'    : lambda chunk: SizeInt(len(chunk)),
    'entropy' : lambda chunk: Percentage(entropy(chunk)),
    'ic'      : lambda chunk: Percentage(index_of_coincidence(chunk)),
    'crc32'   : lambda chunk: F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}',
    'sha1'    : lambda chunk: HexByteString(hashlib.sha1(chunk).digest()),
    'sha256'  : lambda chunk: HexByteString(hashlib.sha256(chunk).digest()),
    'md5'     : lambda chunk: HexByteString(hashlib.md5(chunk).digest()),
    'index'   : NotImplemented,
}
"""
A dictionary mapping the names of common properties to anonymous functions that compute their
corresponding value on a chunk of binary input data.
"""


class LazyMetaOracle(dict):
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
        'md5'     : HexByteString,
    }

    def __init__(self, chunk: ByteString, ghost: bool = False, alias: Optional[Dict[str, str]] = None, *init):
        super().__init__(*init)
        self.alias = alias or {}
        self.ghost = ghost
        self.chunk = chunk

    def fix(self):
        for key, value in self.items():
            ctype = self.CUSTOM_TYPE_MAP.get(key)
            if ctype and not isinstance(value, ctype):
                self[key] = ctype(value)
        return self

    def format_str(self, spec: str, codec: str, *args, **symb) -> str:
        """
        Formats the input expression like a normal Python format string expression. Certain refinery
        metadata objects have special formatters for the `r`-transformation, as defined by wrapping
        of type `refinery.lib.meta.CustomStringRepresentation`. The following representations are
        defined:

        - `entropy` and `ic` are formatted as a percentage.
        - `sha1`, `sha256`, and `md5` are formatted as hex strings.
        - `size` is formatted as a human-readable size with unit.
        """
        return self.format(spec, codec, list(args), symb, False)

    def format_bin(self, spec: str, codec: str, *args, **symb) -> ByteString:
        """
        Formats the input expression using a Python F-string like expression. These strings contain
        fields in the format `{expression!T:pipeline}`, where `T` is a transformation character and
        the `pipeline` part is any refinery pipeline as it would be specified on the command line.
        The following transformations can be applied to the `expression` before it is (optionally)
        processed with the given `pipeline`:

        - `h`: decoded as a hexadecimal string
        - `a`: endcode as latin1
        - `s`: encoded as utf8
        - `u`: encoded as utf16
        - `e`: reads the input as an escaped string
        """
        return self.format(spec, codec, list(args), symb, True)

    def format(
        self,
        spec      : str,
        codec     : str,
        args      : list,
        symbols   : dict,
        binary    : bool,
        fixup     : bool = True,
        variables : Optional[set] = None,
    ) -> Union[str, ByteString]:
        """
        Formats a string using Python-like string fomatting syntax. The formatter for `binary`
        mode is different; each formatting is documented in one of the following two proxy methods:

        - `refinery.lib.meta.LazyMetaOracle.format_str`
        - `refinery.lib.meta.LazyMetaOracle.format_bin`
        """
        from .argformats import ParserError, PythonExpression
        # prevents circular import

        def identity(x):
            return x

        if fixup:
            for (store, it) in (
                (args, enumerate(args)),
                (self, self.items()),
                (symbols, symbols.items()),
            ):
                for key, value in it:
                    with contextlib.suppress(TypeError):
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
                if prefix:
                    if binary:
                        prefix = prefix.encode(codec).decode('unicode-escape').encode('latin1')
                    stream.write(prefix)
                if field is None:
                    continue
                value = None
                if not field:
                    if not args:
                        raise LookupError('no positional arguments given to formatter')
                    value = args[autoindex]
                    if autoindex < len(args) - 1:
                        autoindex += 1
                if binary and conversion:
                    conversion = conversion.lower()
                    if conversion == 'h':
                        value = bytes.fromhex(field)
                    elif conversion == 's':
                        value = field.encode(codec)
                    elif conversion == 'u':
                        value = field.encode('utf-16le')
                    elif conversion == 'a':
                        value = field.encode('latin1')
                    elif conversion == 'e':
                        value = field.encode(codec).decode('unicode-escape').encode('latin1')
                elif field in symbols:
                    value = symbols[field]
                    if variables:
                        variables.add(field)
                if value is None:
                    with contextlib.suppress(IndexError, ValueError):
                        value = args[int(field, 0)]
                if value is None:
                    with contextlib.suppress(KeyError):
                        value = self[field]
                        if variables:
                            variables.add(field)
                if value is None:
                    try:
                        value = PythonExpression.evaluate(field, self)
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
                    if isbuffer(value):
                        output = value
                    else:
                        if not isinstance(value, ByteStringWrapper):
                            value = ByteStringWrapper(str(value), codec)
                        output = value.binary
                    modifier = modifier.strip()
                    if modifier:
                        modifier = self.format(modifier, codec, args, symbols, True, False, variables)
                        pipeline = load_pipeline(modifier.decode(codec))
                        output | pipeline | stream.write
                        continue
                else:
                    converter = {
                        'a': ascii,
                        's': str,
                        'r': repr,
                    }.get(conversion, identity)
                    output = converter(value)
                    output = output.__format__(modifier)
                stream.write(output)
            return stream.getvalue()

    def __contains__(self, key):
        return super().__contains__(key) or key in COMMON_PROPERTIES

    def __missing__(self, key):
        deduction = COMMON_PROPERTIES.get(key)
        if deduction is NotImplemented:
            raise KeyError(F'cannot deduce the {key} property from just the data, you have to use the cm unit.')
        if deduction:
            return self.setdefault(key, deduction(self.chunk))
        if key in self.alias:
            return self[self.alias[key]]
        raise KeyError(F'The meta variable {key} is unknown.')


def metavars(chunk, *pre_populate, ghost: bool = False, alias: Optional[Dict[str, str]] = None) -> LazyMetaOracle:
    """
    This method is the main function used by refinery units to get the meta variable dictionary
    of an input chunk. This dictionary is wrapped using the `refinery.lib.meta.LazyMetaOracleFactory`
    so that access to common variables is always possible.
    """
    alias = alias or None
    oracle = LazyMetaOracle(chunk, ghost, alias, getattr(chunk, 'meta', {}))
    for key in pre_populate:
        oracle[key]
    return oracle.fix()
