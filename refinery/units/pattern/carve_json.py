#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import enum
import string
import json

from ... import Unit


class JSONScope(enum.Enum):
    TEXT = B'"'
    LIST = B'['
    DICT = B'{'


class JSONCarver:
    _PRINTABLE_BYTES = set(bytes(string.printable, 'ascii'))
    _MAX_PARSE_DEPTH = 200

    def __init__(self, data, dictonly=False):
        self.data = data
        self.dictonly = dictonly
        self.cursor = 0

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            start = self.data.find(B'{', self.cursor)
            if not self.dictonly:
                lpos = self.data.find(B'[', self.cursor)
                start = lpos if start < 0 else min(lpos, start)
            if start < self.cursor:
                raise StopIteration
            self.cursor = start + 1
            end = self._find_json_end(start)
            if end is None:
                continue
            try:
                if not json.loads(self.data[start:end]):
                    continue
            except json.JSONDecodeError:
                continue
            self.cursor = end + 1
            return self.data[start:end]

    def _find_json_end(self, start):
        token = self.data[start:start + 1]
        scope = [JSONScope(token)]
        cursor = start

        while scope:
            if len(scope) >= self._MAX_PARSE_DEPTH:
                return None
            cursor = cursor + 1
            if cursor >= len(self.data):
                return None
            token = self.data[cursor:cursor + 1]
            if self.data[cursor] not in self._PRINTABLE_BYTES:
                return None
            elif scope[~0] is JSONScope.TEXT:
                if token == B'"' and self.data[cursor - 1:cursor] != B'\\':
                    scope.pop()
                continue
            elif token == B']':
                if scope[~0] is not JSONScope.LIST:
                    return None
                scope.pop()
            elif token == B'}':
                if scope[~0] is not JSONScope.DICT:
                    return None
                scope.pop()
            for t in JSONScope:
                if token == t.value:
                    scope.append(t)
                    continue

        return cursor + 1


class carve_json(Unit):
    """
    Extracts anything from the input data that looks like JSON.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument('-d', '--dictonly', action='store_true',
            help='only extract JSON dictionaries, do not extract lists.')
        return super().interface(argp)

    def process(self, data):
        yield from JSONCarver(data, dictonly=self.args.dictonly)
