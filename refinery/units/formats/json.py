#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from . import PathExtractorUnit, UnpackResult


class xtjson(PathExtractorUnit):
    """
    Extract values from a JSON document.
    """
    _STRICT_PATH_MATCHING = True

    def unpack(self, data):

        def crawl(path, cursor):
            if isinstance(cursor, (dict, list)) and path:
                path = F'{path}/'
            if isinstance(cursor, dict):
                for key, value in cursor.items():
                    yield from crawl(F'{path}{key}', value)
            elif isinstance(cursor, list):
                width = len(F'{len(cursor)-1:d}')
                for key, value in enumerate(cursor):
                    yield from crawl(F'{path}#{key:0{width}d}', value)
            if path:
                yield path, cursor, cursor.__class__.__name__

        for path, item, typename in crawl('', json.loads(data)):
            def extract(item=item):
                if isinstance(item, (list, dict)):
                    dumped = json.dumps(item, indent=4)
                else:
                    dumped = str(item)
                return dumped.encode(self.codec)
            yield UnpackResult(path, extract, type=typename)
