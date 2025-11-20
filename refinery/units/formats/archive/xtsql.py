from __future__ import annotations

import functools
import sqlite3
import sys

from refinery.lib import json
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtsql(PathExtractorUnit):
    """
    Extract files from SQLite3 databases.
    """
    def unpack(self, data: bytearray):
        def _json(object):
            return json.dumps(object, tojson=json.bytes_as_string)

        if sys.version_info[:2] < (3, 11):
            raise NotImplementedError(F'python 3.11 is required to use {self.__class__.__name__}.')

        database = sqlite3.connect(':memory:')
        database.text_factory = bytes
        database.deserialize(data)
        cursor = database.cursor()
        result: dict[str, list[dict[str, int | float | str | bytes]]] = {}

        listing: list[tuple[bytes, bytes]] = cursor.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table';").fetchall()

        for tbl, spec in listing:
            table = tbl.decode('utf8')
            result[table] = t = []
            ct, _tbl, names = spec.partition(tbl)
            ct = ct.rstrip(B'"')
            names = names.lstrip(B'"')
            names = names.strip()
            names, _, _ = names.rpartition(B')')
            if (
                tbl != _tbl
                or ct.strip().upper().split() != [B'CREATE', B'TABLE']
                or not names.startswith(B'(')
            ):
                raise ValueError(F'Unexpeted SQL statement for {table} in master table: {spec}')
            names = [next(iter(name.strip().split()))
                for name in names[1:-1].decode().split(',')]
            for row in cursor.execute(F'SELECT * FROM {table}').fetchall():
                t.append(dict(zip(names, row)))

        yield UnpackResult('db', functools.partial(_json, result))

        for table, rows in result.items():

            yield UnpackResult(F'db/{table}', functools.partial(_json, rows))

            for k, row in enumerate(rows):

                root = F'db/{table}/{k}'
                yield UnpackResult(root, functools.partial(_json, row))

                for name, value in row.items():
                    path = F'{root}/{name}'
                    if value is None:
                        continue
                    if isinstance(value, (int, float)):
                        value = str(value)
                    if isinstance(value, str):
                        value = value.encode(self.codec)
                    if isinstance(value, bytes):
                        yield UnpackResult(path, value)

    @classmethod
    def handles(cls, data):
        return memoryview(data)[:15] == B'SQLite format 3'
