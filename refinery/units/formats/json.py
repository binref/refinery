#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Union, Optional, Iterable

import json

from refinery.units import Chunk
from refinery.units.formats import PathExtractorUnit, UnpackResult, Unit
from refinery.lib.meta import is_valid_variable_name, metavars
from refinery.lib.patterns import checks


class xtjson(PathExtractorUnit):
    """
    Extract values from a JSON document.
    """
    CustomPathSeparator = '.'

    def unpack(self, data):

        sep = self.CustomPathSeparator

        def crawl(path, cursor):
            if isinstance(cursor, dict):
                for key, value in cursor.items():
                    yield from crawl(F'{path}{sep}{key}', value)
            elif isinstance(cursor, list):
                for key, value in enumerate(cursor):
                    yield from crawl(F'{path}{sep}{key:d}', value)
            if path:
                yield path, cursor, cursor.__class__.__name__

        for path, item, typename in crawl('', json.loads(data)):
            def extract(item=item):
                if isinstance(item, (list, dict)):
                    dumped = json.dumps(item, indent=4)
                else:
                    dumped = str(item)
                try:
                    return dumped.encode('latin1')
                except UnicodeEncodeError:
                    return dumped.encode('utf8')

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
        fmt: Unit.Arg.String(help=(
            'Format expression for the output chunk; may use previously extracted JSON items. The default '
            'is {default}, which represents the input data.')) = '',
        all: Unit.Arg.Switch('-a', group='META', help='Extract all other fields as metadata regardless of length and type.') = False,
        one: Unit.Arg.Switch('-x', group='META', help='Do not extract any other fields as metadata.') = False,
        raw: Unit.Arg.Switch('-r', help='Disable conversion of JSON strings to binary strings in metadata') = False,
    ):
        super().__init__(fmt=fmt, one=one, raw=raw, all=all)

    def process(self, data: Chunk):

        def convert(value, iskey=False):
            if self.args.raw:
                return value
            if isinstance(value, (float, int, bool)):
                return value
            if isinstance(value, str):
                return value.encode(self.codec)
            if iskey:
                raise TypeError
            if isinstance(value, dict):
                return {convert(k): convert(v) for k, v in value.items()}
            if isinstance(value, list):
                return [convert(k) for k in value]

        def acceptable(key, value, nested=False, convert=False):
            if not is_valid_variable_name(key):
                self.log_info(F'rejecting item with invalid name {key}')
                return None
            if isinstance(value, (float, int, bool)):
                return value
            if isinstance(value, dict):
                if not self.args.all:
                    self.log_info(F'rejecting item {key} with dictionary value')
                    return False
                return True
            if isinstance(value, list):
                if nested:
                    self.log_info(F'rejecting item {key} containing a doubly nested list')
                    return False
                return all(acceptable(key, t, True) for t in value)
            if isinstance(value, str):
                if not self.args.all:
                    if len(value) not in range(1, 80):
                        self.log_info(F'rejecting string item {key} because {len(value)} exceeds the length limit')
                        return False
                    if '\n' in value:
                        self.log_info(F'rejecting string item {key} because it contains line breaks')
                        return False
                return True
            return False

        jdoc: dict = json.loads(data)
        if not isinstance(jdoc, dict):
            raise ValueError('The input must be a JSON dictionary.')
        meta = metavars(data)
        args = {k: convert(v) for k, v in jdoc.items() if acceptable(k, v)}
        used = set()
        data[:] = meta.format_bin(self.args.fmt, self.codec, [data], args, used)
        for u in used:
            args.pop(u, None)
        if not self.args.one:
            data.meta.update(args)
        return data


class xjl(Unit):
    """
    Returns all JSON elements from a JSON iterable as individual outputs. When reversed, the unit
    collects all chunks in the frame and wraps them as a JSON list.
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

    def reverse(self, data):
        return json.dumps(data.temp).encode(self.codec)

    def filter(self, chunks: Iterable[Chunk]):
        if not self.args.reverse:
            yield from chunks

        from refinery.lib.tools import begin

        if it := begin(chunks):
            head, rest = it
            collected = [head.decode(self.codec)]
            collected.extend(chunk.decode(self.codec) for chunk in rest)
            head.temp = collected
            yield head
