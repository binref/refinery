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
import hashlib
import string
import zlib

from io import StringIO
from typing import Callable, Dict, Optional, ByteString, Union

from .tools import isbuffer, entropy, index_of_coincidence
from .mime import get_cached_file_magic_info


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

    def __init__(self, string: ByteString, codec: str):
        self.string = string
        self.codec = codec

    def __getattr__(self, key):
        return getattr(self.string, key)

    def __repr__(self):
        return self.string.hex().upper()

    def __str__(self):
        return self.string.decode(self.codec, 'backslashreplace')

    def __format__(self, spec):
        return F'{self!s:{spec}}'


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
        return self._s(False)


class Percentage(float, CustomStringRepresentation):
    """
    The string representation of this floating point class is a a human-readable expression of a
    percentage. The string representation is a common decimal with 4 digits precision, but casting
    the object using `repr` will yield a percentage.
    """
    def __str__(self):
        return F'{self:.4f}'

    def __repr__(self):
        return F'{self*100:.2f}%'


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


def LazyMetaOracleFactory(chunk, ghost: bool = False, aliases: Optional[Dict[str, str]] = None):
    """
    Create a dictionary that can be queried lazily for all potential options of the common meta
    variable unit. For example, a SHA-256 hash is computed only as soon as the oracle is accessed
    at the key `'sha256'`.
    """
    aliases = aliases or {}

    CUSTOM_TYPE_MAP = {
        'entropy' : Percentage,
        'size'    : SizeInt,
        'sha1'    : HexByteString,
        'sha256'  : HexByteString,
        'md5'     : HexByteString,
    }

    class LazyMetaOracle(dict):
        def fix(self):
            for key, value in self.items():
                ctype = CUSTOM_TYPE_MAP.get(key)
                if ctype and not isinstance(value, ctype):
                    self[key] = ctype(value)
            return self

        def format(self, spec: str, data: ByteString, codec: str) -> str:
            from .argformats import ParserError, PythonExpression

            def identity(x):
                return x

            for key, value in self.items():
                if isbuffer(value):
                    self[key] = ByteStringWrapper(value, codec)

            formatter = string.Formatter()
            data = ByteStringWrapper(data, codec)

            with StringIO() as stream:
                for prefix, field, modifier, conversion in formatter.parse(spec):
                    stream.write(prefix)
                    converter = {
                        'a': ascii,
                        's': str,
                        'r': repr,
                    }.get(conversion, identity)
                    if field is None:
                        continue
                    if not field:
                        field = data
                    else:
                        try:
                            field = self[field]
                        except KeyError as KE:
                            try:
                                field = PythonExpression.evaluate(field, self)
                            except ParserError:
                                if not ghost:
                                    raise KE
                                stream.write(F'{{{field}')
                                if conversion:
                                    stream.write(F'!{conversion}')
                                if modifier:
                                    stream.write(F':{modifier}')
                                stream.write('}')
                                continue
                    output = converter(field)
                    stream.write(output.__format__(modifier))
                return stream.getvalue()

        def __contains__(self, key):
            return super().__contains__(key) or key in COMMON_PROPERTIES

        def __missing__(self, key):
            deduction = COMMON_PROPERTIES.get(key)
            if deduction is NotImplemented:
                raise KeyError(F'cannot deduce the {key} property from just the data, you have to use the cm unit.')
            if deduction:
                return self.setdefault(key, deduction(chunk))
            if key in aliases:
                return self[aliases[key]]
            raise KeyError(F'The meta variable {key} is unknown.')

    return LazyMetaOracle


def metavars(chunk, *pre_populate, ghost: bool = False, aliases: Optional[Dict[str, str]] = None):
    """
    This method is the main function used by refinery units to get the meta variable dictionary
    of an input chunk. This dictionary is wrapped using the `refinery.lib.meta.LazyMetaOracleFactory`
    so that access to common variables is always possible.
    """
    aliases = aliases or None
    cls = LazyMetaOracleFactory(chunk, ghost, aliases)
    meta = cls(**getattr(chunk, 'meta', {}))
    for key in pre_populate:
        meta[key]
    return meta.fix()
