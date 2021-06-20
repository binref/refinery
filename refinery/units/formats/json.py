#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from ...lib.json import flattened
from . import PathExtractorUnit, UnpackResult


class xtjson(PathExtractorUnit):
    """
    Extract values from a JSON document.
    """
    def unpack(self, data):
        for path, value in flattened(json.loads(data), separator='/'):
            yield UnpackResult(path, str(value).encode(self.codec))
