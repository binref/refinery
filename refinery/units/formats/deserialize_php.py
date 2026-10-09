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


class _PhpReader:
    """
    Reads PHP serialized data from a stream.
    """
    def __init__(self, fp: BytesIO):
        self.fp = fp

    def expect(self, e: bytes):
        v = self.fp.read(len(e))
        if v != e:
            raise ValueError(F'expected {e!r}, got {v!r}')

    def read_until(self, delim: bytes) -> bytes:
        buf = []
        while True:
            char = self.fp.read(1)
            if char == delim:
                break
            if not char:
                raise ValueError('unexpected end of stream')
            buf.append(char)
        return b''.join(buf)

    def load_array(self) -> list[tuple]:
        items = int(self.read_until(b':')) * 2
        self.expect(b'{')
        result = []
        last_item = Ellipsis
        for _ in range(items):
            item = self.unserialize()
            if last_item is Ellipsis:
                last_item = item
            else:
                result.append((last_item, item))
                last_item = Ellipsis
        self.expect(b'}')
        return result

    def unserialize(self) -> object:
        opcode = self.fp.read(1).lower()
        if opcode == b'n':
            self.expect(b';')
            return None
        if opcode in b'idb':
            self.expect(b':')
            value = self.read_until(b';')
            if opcode == b'i':
                return int(value)
            if opcode == b'd':
                return float(value)
            return int(value) != 0
        if opcode == b's':
            self.expect(b':')
            length = int(self.read_until(b':'))
            self.expect(b'"')
            value = self.fp.read(length)
            self.expect(b'"')
            self.expect(b';')
            return value.decode('utf-8', 'surrogateescape')
        if opcode == b'a':
            self.expect(b':')
            return dict(self.load_array())
        if opcode == b'o':
            self.expect(b':')
            name_length = int(self.read_until(b':'))
            self.expect(b'"')
            name = self.fp.read(name_length).decode('utf-8', 'surrogateescape')
            self.expect(b'":')
            return _phpobject(name, dict(self.load_array()))
        raise ValueError(F'unexpected opcode: {opcode!r}')


def _serialize(obj: object, keypos: bool) -> bytes:
    """
    Serializes the given object in the PHP format, as an array key if `keypos` is set.
    """
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


class dsphp(Unit):
    """
    Deserialize PHP serialized data and re-serialize as JSON.
    """

    @staticmethod
    def _loads(data: bytes | bytearray | memoryview) -> object:
        return _PhpReader(BytesIO(bytes(data))).unserialize()

    @staticmethod
    def _dumps(data: object) -> bytes:
        return _serialize(data, False)

    def reverse(self, data):
        return self._dumps(json.loads(data))

    def process(self, data):
        def tojson(obj):
            if isinstance(obj, _phpobject):
                return obj._asdict()

        return json.dumps(self._loads(data), tojson=tojson)
