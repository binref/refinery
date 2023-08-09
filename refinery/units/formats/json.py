#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Union, Optional

import json

from refinery.units.formats import PathExtractorUnit, UnpackResult, Unit
from refinery.lib.meta import is_valid_variable_name
from refinery.lib.patterns import checks


class xtjson(PathExtractorUnit):
    """
    Extract values from a JSON document.
    """
    _custom_path_separator = '.'

    def unpack(self, data):

        def crawl(path, cursor):
            if isinstance(cursor, dict):
                for key, value in cursor.items():
                    yield from crawl(F'{path}/{key}', value)
            elif isinstance(cursor, list):
                for key, value in enumerate(cursor):
                    yield from crawl(F'{path}({key:d})', value)
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

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        return bool(checks.json.fullmatch(data))


class xj0(Unit):
    """
    Extracts a single field from a JSON document at depth 0. By default, the unit applies a heuristic to
    extract remaining fields as metadata: String values are extracted only if they do not exceed 80
    characters in length and do not contain any line breaks. Floating-point, integer, boolean values, and
    lists of the latter are also extracted.
    """
    def __init__(
        self,
        key: Unit.Arg.Binary(help='Optional key of a value to become the main body of the chunk.') = None,
        raw: Unit.Arg.Switch('-r', group='META', help='Do not extract any other fields as metadata.') = False,
        all: Unit.Arg.Switch('-a', group='META', help='Extract all other fields as metadata.') = False
    ):
        super().__init__(key=key, raw=raw, all=all)

    def process(self, data):

        def acceptable(key, value, inside_list=False):
            if not is_valid_variable_name(key):
                return False
            if isinstance(value, dict):
                return False
            if isinstance(value, (float, int, bool)):
                return True
            if inside_list:
                return False
            if isinstance(value, list):
                return all(acceptable(key, t, True) for t in value)
            if isinstance(value, str):
                if self.args.all:
                    return True
                return len(value) in range(1, 80) and '\n' not in value

        doc: dict = json.loads(data)
        if not isinstance(doc, dict):
            raise ValueError('The input must be a JSON dictionary.')
        key = self.args.key
        result = key and doc.pop(key.decode(self.codec), '').encode(self.codec)
        if self.args.raw:
            return result
        else:
            return self.labelled(result, **{
                key: value for key, value in doc.items() if acceptable(key, value)
            })


class xjl(Unit):
    """
    Returns all JSON elements from a JSON iterable as individual outputs.
    """

    def process(self, data):
        try:
            doc: Union[list, dict] = json.loads(data)
        except Exception:
            from refinery.units.pattern.carve_json import carve_json
            doc = data | carve_json | json.loads
        try:
            it = doc.values()
        except AttributeError:
            it = doc
        for item in it:
            yield json.dumps(item, indent=4).encode(self.codec)
