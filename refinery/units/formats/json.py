from __future__ import annotations

from typing import Iterable

from refinery.lib import json as libjson
from refinery.lib.id import is_likely_json
from refinery.lib.meta import MV, is_valid_variable_name, metavars
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtjson(PathExtractorUnit):
    """
    Extract values from a JSON document.
    """
    CustomPathSeparator = '.'

    @classmethod
    def _crawl(cls, sep: str, path: str, cursor):
        if isinstance(cursor, dict):
            for key, value in cursor.items():
                yield from cls._crawl(sep, F'{path}{sep}{key}', value)
        elif isinstance(cursor, list):
            for key, value in enumerate(cursor):
                yield from cls._crawl(sep, F'{path}{sep}{key:d}', value)
        if path:
            yield path, cursor, cursor.__class__.__name__

    def unpack(self, data):

        sep = self.CustomPathSeparator

        if not isinstance(data, (dict, list)):
            data = libjson.loads(data)

        for path, item, typename in self._crawl(sep, '', data):
            def extract(item=item):
                if isinstance(item, (list, dict)):
                    return libjson.dumps(item)
                dumped = str(item)
                try:
                    return dumped.encode('latin1')
                except UnicodeEncodeError:
                    return dumped.encode('utf8')

            yield UnpackResult(path, extract, **{MV.TYPE: typename})

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_likely_json(data)


class xj0(Unit):
    """
    Extract a single field from a JSON document at depth 0.

    By default, dictionaries are not extracted. Nested lists and dictionaries are never
    extracted.
    """
    def __init__(
        self,
        *fmt: Param[str, Arg.String(help=(
            'Format expression for the output chunk; may use previously extracted JSON items '
            'as format expressions. By default, the input data is returned.'))],
        all: Param[bool, Arg.Switch('-a', group='META',
            help='Extract all other fields as metadata regardless of length and type.')] = False,
        one: Param[bool, Arg.Switch('-x', group='META',
            help='Do not extract any other fields as metadata.')] = False,
        raw: Param[bool, Arg.Switch('-r',
            help='Disable conversion of JSON strings to binary strings in metadata')] = False,
    ):
        super().__init__(fmt=fmt, one=one, raw=raw, all=all)

    def _convert(self, value, iskey=False):
        if self.args.raw:
            return value
        if isinstance(value, (float, int, bool)):
            return value
        if isinstance(value, str):
            return value.encode(self.codec)
        if iskey:
            raise TypeError
        if isinstance(value, dict):
            return {self._convert(k, True): self._convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._convert(k) for k in value]

    def _acceptable(self, key, value, nested=False):
        if not is_valid_variable_name(key, allow_derivations=False):
            self.log_info(F'rejecting item with invalid name {key}')
            return None
        if isinstance(value, (float, int, bool, str)):
            return True
        if isinstance(value, dict):
            if not self.args.all:
                self.log_info(F'rejecting item {key} with dictionary value')
                return False
            return all(self._acceptable(k, val, True) for k, val in value.items())
        if isinstance(value, list):
            if nested:
                self.log_info(F'rejecting item {key} containing a nested list')
                return False
            return all(self._acceptable(key, t, True) for t in value)
        return False

    def process(self, data: Chunk):
        jdoc: dict = libjson.loads(data)
        if not isinstance(jdoc, dict):
            raise ValueError('The input must be a JSON dictionary.')
        meta = metavars(data)
        args = {k: self._convert(v) for k, v in jdoc.items() if self._acceptable(k, v)}
        used = set()
        if fmt := self.args.fmt:
            data[:] = meta.format_bin(' '.join(fmt), self.codec, [data], args, used)
        for u in used:
            args.pop(u, None)
        if not self.args.one:
            data.meta.update(args)
        return data


class xjl(Unit):
    """
    Extract all elements from a JSON iterable as individual outputs.

    When reversed, the unit collects all chunks in the frame and wraps them as a JSON list.
    """

    def process(self, data):
        try:
            doc: list | dict = libjson.loads(data)
        except Exception:
            from refinery.units.pattern.carve_json import carve_json
            doc = data | carve_json | libjson.loads
        if isinstance(doc, dict):
            it = doc.values()
        else:
            it = doc
        for item in it:
            yield libjson.dumps(item)

    def reverse(self, data):
        return libjson.dumps(data.temp, pretty=False)

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
