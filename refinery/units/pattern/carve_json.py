#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import string
import json
import re

from refinery.units import Arg, Unit


_JSON_DELIMITER = re.compile(BR'[\[\]\{\}"]')

_JSON_TOKEN_TO_TERMINATOR = {
    B'"'[0]: B'"'[0],
    B'['[0]: B']'[0],
    B'{'[0]: B'}'[0],
}


class JSONCarver:
    _PRINTABLE_BYTES = set(bytes(string.printable, 'ascii'))
    _MAX_PARSE_DEPTH = 200

    def __init__(self, data: bytearray, dictonly=False):
        self.data = data
        self.dictonly = dictonly
        self.cursor = 0

    def __iter__(self):
        return self

    def __next__(self):
        data = self.data
        while True:
            start = data.find(B'{', self.cursor)
            if not self.dictonly:
                start_list = data.find(B'[', self.cursor)
                start_dict = start % len(data)
                if start_dict > start_list >= 0:
                    start = start_list
            if start < self.cursor:
                raise StopIteration
            self.cursor = start + 1
            end = self.find_end(data, start)
            if end is None:
                continue
            try:
                if not json.loads(data[start:end]):
                    continue
            except json.JSONDecodeError:
                continue
            except UnicodeDecodeError:
                continue
            self.cursor = end + 1
            return start, data[start:end]

    @classmethod
    def find_end(cls, data: bytearray, start: int):
        token = data[start]
        scope = bytearray()
        cursor = start
        scope.append(_JSON_TOKEN_TO_TERMINATOR[token])
        printable = cls._PRINTABLE_BYTES

        while scope:
            if len(scope) >= cls._MAX_PARSE_DEPTH:
                return None
            delim = _JSON_DELIMITER.search(data, cursor + 1)
            if delim is None:
                return None
            cursor = delim.start()
            token = data[cursor]
            if token not in printable:
                return None
            if scope[~0] == token:
                if token != B'"' or data[cursor - 1] != B'\\'[0]:
                    scope.pop()
            else:
                try:
                    scope.append(_JSON_TOKEN_TO_TERMINATOR[token])
                except KeyError:
                    return None

        return cursor + 1


class carve_json(Unit):
    """
    Extracts anything from the input data that looks like JSON.
    """
    def __init__(self, dictonly: Arg.Switch('-d', help='only extract JSON dictionaries, do not extract lists.') = False):
        super().__init__(dictonly=dictonly)

    def process(self, data):
        for start, chunk in JSONCarver(data, dictonly=self.args.dictonly):
            yield self.labelled(chunk, offset=start)
