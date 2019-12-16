#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
try:
    import phpserialize as php
except ModuleNotFoundError:
    php = None

from .. import Unit


class dsphp(Unit):
    """
    Deserialize PHP serialized data and re-serialize as JSON.
    """

    class _encoder(json.JSONEncoder):
        def default(self, obj):
            try:
                return super().default(obj)
            except TypeError:
                pass
            if isinstance(obj, bytes) or isinstance(obj, bytearray):
                return obj.decode('utf8')
            if isinstance(obj, php.phpobject):
                return obj._asdict()

    def process(self, data):
        return json.dumps(
            php.loads(
                data,
                object_hook=php.phpobject,
                decode_strings=True
            ),
            indent=4,
            cls=self._encoder
        ).encode(self.codec)
