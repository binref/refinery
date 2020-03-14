#!/usr/bin/env python3
# -*- coding: utf-8 -*-
try:
    import javaobj.v2 as java
except ImportError:
    java = None

import json

from .. import Unit


class JavaEncoder(json.JSONEncoder):

    def encode(self, obj):
        if isinstance(obj, dict):
            obj = {str(key): value for key, value in obj.items()}
        return super().encode(obj)

    def default(self, obj):
        try:
            return super().default(obj)
        except TypeError:
            if isinstance(obj, java.beans.JavaString):
                return str(obj)
            raise


class dsjava(Unit):
    """
    Deserialize Java serialized data and re-serialize as JSON.
    """
    def process(self, data):
        return json.dumps(
            java.loads(data),
            indent=4,
            cls=JavaEncoder
        ).encode(self.codec)
