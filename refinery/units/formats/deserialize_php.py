from __future__ import annotations

from io import BytesIO

from refinery.lib import json
from refinery.units import Unit


class _phpobject:
    __slots__ = ('__name__', '__php_vars__')

    def __init__(self, name: str, d: dict | None = None):
        object.__setattr__(self, '__name__', name)
        object.__setattr__(self, '__php_vars__', d or {})

    def _asdict(self) -> dict:
        result = {}
        for key, value in self.__php_vars__.items():
            if key[:1] in (' ', '\x00'):
                key = key.split(key[:1], 2)[-1]
            result[key] = value
        return result


class dsphp(Unit):
    """
    Deserialize PHP serialized data and re-serialize as JSON.
    """

    @staticmethod
    def _loads(data: bytes | bytearray | memoryview) -> object:
        fp = BytesIO(bytes(data))

        def _expect(e: bytes):
            v = fp.read(len(e))
            if v != e:
                raise ValueError(F'expected {e!r}, got {v!r}')

        def _read_until(delim: bytes) -> bytes:
            buf = []
            while True:
                char = fp.read(1)
                if char == delim:
                    break
                if not char:
                    raise ValueError('unexpected end of stream')
                buf.append(char)
            return b''.join(buf)

        def _load_array() -> list[tuple]:
            items = int(_read_until(b':')) * 2
            _expect(b'{')
            result = []
            last_item = Ellipsis
            for _ in range(items):
                item = _unserialize()
                if last_item is Ellipsis:
                    last_item = item
                else:
                    result.append((last_item, item))
                    last_item = Ellipsis
            _expect(b'}')
            return result

        def _unserialize() -> object:
            opcode = fp.read(1).lower()
            if opcode == b'n':
                _expect(b';')
                return None
            if opcode in b'idb':
                _expect(b':')
                value = _read_until(b';')
                if opcode == b'i':
                    return int(value)
                if opcode == b'd':
                    return float(value)
                return int(value) != 0
            if opcode == b's':
                _expect(b':')
                length = int(_read_until(b':'))
                _expect(b'"')
                value = fp.read(length)
                _expect(b'"')
                _expect(b';')
                return value.decode('utf-8', 'surrogateescape')
            if opcode == b'a':
                _expect(b':')
                return dict(_load_array())
            if opcode == b'o':
                _expect(b':')
                name_length = int(_read_until(b':'))
                _expect(b'"')
                name = fp.read(name_length).decode('utf-8', 'surrogateescape')
                _expect(b'":')
                return _phpobject(name, dict(_load_array()))
            raise ValueError(F'unexpected opcode: {opcode!r}')

        return _unserialize()

    @staticmethod
    def _dumps(data: object) -> bytes:

        def _serialize(obj: object, keypos: bool) -> bytes:
            if keypos:
                if isinstance(obj, (int, float, bool)):
                    return F'i:{int(obj)};'.encode('latin1')
                if isinstance(obj, str):
                    encoded = obj.encode('utf-8', 'surrogateescape')
                    return F's:{len(encoded)}:'.encode('latin1') + b'"' + encoded + b'";'
                if isinstance(obj, bytes):
                    return F's:{len(obj)}:'.encode('latin1') + b'"' + obj + b'";'
                if obj is None:
                    return b's:0:"";'
                raise TypeError(F'cannot serialize {type(obj)!r} as key')
            if obj is None:
                return b'N;'
            if isinstance(obj, bool):
                return F'b:{int(obj)};'.encode('latin1')
            if isinstance(obj, int):
                return F'i:{obj};'.encode('latin1')
            if isinstance(obj, float):
                return F'd:{obj};'.encode('latin1')
            if isinstance(obj, str):
                encoded = obj.encode('utf-8', 'surrogateescape')
                return F's:{len(encoded)}:'.encode('latin1') + b'"' + encoded + b'";'
            if isinstance(obj, bytes):
                return F's:{len(obj)}:'.encode('latin1') + b'"' + obj + b'";'
            if isinstance(obj, dict):
                parts = []
                for key, value in obj.items():
                    parts.append(_serialize(key, True))
                    parts.append(_serialize(value, False))
                return (
                    F'a:{len(obj)}:'.encode('latin1')
                    + b'{' + b''.join(parts) + b'}'
                )
            if isinstance(obj, (list, tuple)):
                parts = []
                for index, value in enumerate(obj):
                    parts.append(_serialize(index, True))
                    parts.append(_serialize(value, False))
                return (
                    F'a:{len(obj)}:'.encode('latin1')
                    + b'{' + b''.join(parts) + b'}'
                )
            if isinstance(obj, _phpobject):
                name = _serialize(obj.__name__, True)
                body = _serialize(obj.__php_vars__, False)
                return b'O' + name[1:-1] + body[1:]
            raise TypeError(F'cannot serialize {type(obj)!r}')

        return _serialize(data, False)

    def reverse(self, data):
        return self._dumps(json.loads(data))

    def process(self, data):
        def tojson(obj):
            if isinstance(obj, _phpobject):
                return obj._asdict()

        return json.dumps(self._loads(data), tojson=tojson)
