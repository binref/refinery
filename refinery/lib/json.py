"""
This module provides JSON encoding and decoding. All refinery units should use this interface
rather than the standard library JSON module. It first attempts to use the orJSON external library
as backend, which is much faster, and then falls back to the standard library if orJSON is not
available.
"""
from __future__ import annotations

import codecs
import json as pyjson

from datetime import date, datetime, time
from enum import Enum, IntFlag
from uuid import UUID

from refinery.lib.shared import orjson
from refinery.lib.tools import isbuffer
from refinery.lib.types import Any, Callable, Generator


def flattened(data: dict, prefix: str = '', separator: str = '.'):
    """
    Yield the rows of a flattened view for the input JSON dictionary. This is used by several
    refinery units to display a tabular view of what would otherwise be output as JSON.
    """
    def flatten(
        cursor: dict | list | str | int | float | bool, prefix: str
    ) -> Generator[tuple[str, int | float | bool | str]]:
        if isinstance(cursor, dict):
            for key, value in cursor.items():
                new_prefix = key if not prefix else F'{prefix}{separator}{key}'
                yield from flatten(value, new_prefix)
        elif isinstance(cursor, list):
            width = len(F'{len(cursor) - 1:X}')
            for key, value in enumerate(cursor):
                yield from flatten(value, F'{prefix}[0x{key:0{width}X}]')
        else:
            yield (prefix, cursor)
    yield from flatten(data, prefix)


def _common_conversions(o):
    if isinstance(o, Enum):
        return o.name
    if isinstance(o, datetime):
        return o.isoformat(' ', 'seconds')
    if isinstance(o, time):
        return o.isoformat('seconds')
    if isinstance(o, date):
        return o.isoformat()


def convert_key(k: Enum | datetime | date | time | int | float | bool | str) -> str:
    """
    Conversions of several non-string types for dictionary keys to enable JSON serialization.
    """
    return str(k) if (t := _common_conversions(k)) is None else t


def standard_conversions(o):
    """
    Converts `datetime` and `UUID` objects to their canonical string representations, and also
    converts `set`. `tuple`. and `frozenset` objects to `list`s for JSON serialization. Other
    serialization of standard object types should be added here.
    """
    if (t := _common_conversions(o)) is not None:
        return t
    if isinstance(o, IntFlag):
        return [flag.name for flag in o.__class__ if o & flag == flag]
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, (set, tuple, frozenset)):
        return list(o)
    raise TypeError


def preprocess(o, keys: bool = False):
    """
    This method ensures that no integers requiring more than 64 bits are stored within nested
    dictionaries and lists of the input object. Integers that exceed this limit are converted
    to hexadecimal string representations with prefix.

    When the `keys` option is set, the method also uses `refinery.lib.json.convert_key` to turn
    all non-string keys in dictionaries into strings.
    """
    if isinstance(o, dict):
        if not keys:
            for k, v in o.items():
                o[k] = preprocess(v, keys=False)
        else:
            invalid_keys = []
            for k, v in o.items():
                if not isinstance(k, str):
                    invalid_keys.append(k)
                else:
                    o[k] = preprocess(v, keys=True)
            for k in invalid_keys:
                o[convert_key(k)] = preprocess(o.pop(k))
    elif isinstance(o, list):
        for k, v in enumerate(o):
            o[k] = preprocess(v, keys=keys)
    elif isinstance(o, int) and o.bit_length() > 64:
        return hex(o)
    return o


def py_json_dumps(
    object,
    pretty: bool = True,
    checks: bool = True,
    tojson: Callable[[Any], Any] | None = None,
) -> bytes:
    """
    This is the JSON dump method wrapper which is based on the standard library backend. It is
    exposed separately to allow testing.
    """
    if (enc := tojson) is not None:
        class encoder(pyjson.JSONEncoder):
            default = staticmethod(tojson) # type:ignore
        enc = encoder
    if checks:
        object = preprocess(object, keys=True)
    if pretty:
        out = pyjson.dumps(object, ensure_ascii=False, cls=enc, indent=2)
    else:
        out = pyjson.dumps(object, ensure_ascii=False, cls=enc, indent=None, separators=(',', ':'))
    return out.encode('utf8')


try:
    _or_json_loads = orjson.loads
    _or_json_dumps = orjson.dumps
except ImportError:
    dumps = py_json_dumps
    loads = pyjson.loads
else:
    def __loads(data):
        # orjson does not like subclasses of bytearray, and we do that a lot
        return _or_json_loads(memoryview(data))

    def __dumps(
        object,
        pretty: bool = True,
        checks: bool = True,
        tojson: Callable[[Any], Any] | None = None,
    ):
        default = tojson or standard_conversions
        options = (
            0
            | orjson.OPT_PASSTHROUGH_DATETIME
            | orjson.OPT_NON_STR_KEYS
            | orjson.OPT_OMIT_MICROSECONDS
            | orjson.OPT_SERIALIZE_DATACLASS
            | orjson.OPT_SERIALIZE_UUID
        )
        if pretty:
            options |= orjson.OPT_INDENT_2
        if checks:
            object = preprocess(object)
        return _or_json_dumps(
            object,
            option=options,
            default=default,
        )

    loads = __loads
    dumps = __dumps


def bytes_as_array(o):
    """
    A default handler that will convert byte strings to lists of integers.
    """
    if isbuffer(o):
        return [int(b & 0xFF) for b in o]
    return standard_conversions(o)


def bytes_as_string(o):
    """
    A default handler that will convert byte strings to 8-bit ASCII encoded strings.
    """
    if isbuffer(o):
        return codecs.decode(o, 'latin1')
    return standard_conversions(o)


__pdoc__ = {
    'dumps': (
        'A unified proxy method for dumping input data to JSON, using either the orJSON or the '
        'standard library as backend, depending on what is available. The interface more closely '
        'resembles orJSON: The `pretty` option controls whether the output is indented or '
        'minified, and an optional conversion handler can be passed as the `default` parameter '
        'to serialize Python objects that are not handled natively by the backend. Finally, the '
        'option `checks` can be set to false to prevent all preprocessing of the input data. Use '
        'it when you are absolutely certain that the input is JSON-serializable and requires no '
        'normalization of any kind.'
    ),
    'loads': (
        'A unified proxy method for loading JSON data as a Python object, using either orJSON '
        'or the standard library backend.'
    ),
}
