from __future__ import annotations

import json
import re
import string

from refinery.lib.types import Param
from refinery.units import Arg, Unit

_JSON_DELIMITER = re.compile(BR'[\[\]\{\}"]')

_JSON_TOKEN_TO_TERMINATOR = {
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
        view = memoryview(data)
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
            if token == 0x22:
                while True:
                    m = re.search(B'\\"', view[cursor + 1:])
                    if m is not None:
                        cursor += m.start() + 1
                    else:
                        return None
                    if data[cursor - 1] != 0x5C:
                        break
                continue
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
    def __init__(
        self, all: Param[bool, Arg.Switch('-a', help=(
            'By default, only dictionaries are carved. Specify this flag to also carve lists.'
        ))] = False
    ):
        super().__init__(all=all)

    def process(self, data):
        for start, chunk in JSONCarver(data, dictonly=not self.args.all):
            yield self.labelled(chunk, offset=start)
