from __future__ import annotations

from refinery.lib import json
from refinery.units import Unit


class dsphp(Unit):
    """
    Deserialize PHP serialized data and re-serialize as JSON.
    """
    @Unit.Requires('phpserialize', ['formats'])
    def _php():
        import phpserialize
        return phpserialize

    def reverse(self, data):
        return self._php.dumps(json.loads(data))

    def process(self, data):
        phpobject = self._php.phpobject

        def tojson(obj):
            if isinstance(obj, bytes) or isinstance(obj, bytearray):
                return obj.decode('utf8')
            if isinstance(obj, phpobject):
                return obj._asdict()

        return json.dumps(
            self._php.loads(
                data,
                object_hook=phpobject,
                decode_strings=True
            ),
            tojson=tojson
        )
