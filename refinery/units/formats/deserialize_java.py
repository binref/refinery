#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import Unit


class dsjava(Unit):
    """
    Deserialize Java serialized data and re-serialize as JSON.
    """

    class _encoder(json.JSONEncoder):
        def default(self, obj):
            try:
                return super().default(obj)
            except TypeError:
                pass
            if isinstance(obj, bytes) or isinstance(obj, bytearray):
                return obj.decode('utf8')

    def process(self, data):
        import javaobj as java
        return json.dumps(
            java.loads(data),
            indent=4,
            cls=self._encoder
        ).encode(self.codec)
