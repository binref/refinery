"""
This module provides JSON encoding and decoding. All refinery units should use this interface
rather than the standard library JSON module. It first attempts to use the orJSON external library
as backend, which is much faster, and then falls back to the standard library if orJSON is not
available.
"""
from __future__ import annotations

import codecs
import json as pyjson
import uuid

from datetime import datetime

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


def _py_standard_conversions(o):
    if isinstance(o, datetime):
        return o.isoformat(' ', 'seconds')
    if isinstance(o, uuid.UUID):
        return str(o).upper()
    if isinstance(o, (set, tuple)):
        return list(o)
    raise TypeError


def _py_json_dumps(
    object,
    pretty: bool = True,
    tojson: Callable[[Any], Any] | None = None,
) -> bytes:
    if tojson is not None:
        class encoder(pyjson.JSONEncoder):
            default = staticmethod(tojson) # type:ignore
        enc = encoder
    else:
        enc = None
    if pretty:
        out = pyjson.dumps(object, ensure_ascii=False, cls=enc, indent=2)
    else:
        out = pyjson.dumps(object, ensure_ascii=False, cls=enc, indent=0, separators=(',', ':'))
    return out.encode('utf8')


def serialize_bigints(o):
    """
    This method ensures that no integers requiring more than 64 bits are stored within nested
    dictionaries and lists of the input object. Integers that exceed this limit are converted
    to hexadecimal string representations with prefix.
    """
    if isinstance(o, dict):
        for k, v in o.items():
            o[k] = serialize_bigints(v)
    elif isinstance(o, list):
        for k, v in enumerate(o):
            o[k] = serialize_bigints(v)
    elif isinstance(o, int) and o.bit_length() > 64:
        return hex(o)
    return o


try:
    _or_json_loads = orjson.loads
    _or_json_dumps = orjson.dumps
except ImportError:
    dumps = _py_json_dumps
    loads = pyjson.loads
    standard_conversions = _py_standard_conversions
else:
    def _or_standard_conversions(o):
        if isinstance(o, datetime):
            return o.isoformat(' ', 'seconds')
        if isinstance(o, (set, tuple)):
            return list(o)
        raise TypeError

    standard_conversions = _or_standard_conversions

    def __loads(data):
        # orjson does not like subclasses of bytearray, and we do that a lot
        return _or_json_loads(memoryview(data))

    def __dumps(
        object,
        pretty: bool = True,
        tojson: Callable[[Any], Any] | None = None,
    ):
        default = tojson or _or_standard_conversions
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
        try:
            return _or_json_dumps(
                serialize_bigints(object),
                option=options,
                default=default,
            )
        except Exception:
            raise
            return _py_json_dumps(object, pretty=pretty, tojson=tojson)

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
        'to serialize Python objects that are not handled natively by the backend.'
    ),
    'loads': (
        'A unified proxy method for loading JSON data as a Python object, using either orJSON '
        'or the standard library backend.'
    ),
}
