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
        database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, len(data))
        cursor = database.cursor()
        result: dict[str, list[dict[str, int | float | str | bytes]]] = {}

        listing: list[tuple[bytes]] = cursor.execute(
            'SELECT name FROM sqlite_master WHERE type = ?', ('table',)).fetchall()

        for (name,) in listing:
            table = name.decode('utf8')
            quoted = table.replace('"', '""')
            select = F'SELECT * FROM "{quoted}"'
            try:
                if any(step[1] == B'VOpen' for step in cursor.execute(F'EXPLAIN {select}')):
                    self.log_info(F'skipping {table}, which does not store its own rows')
                    continue
                rows = cursor.execute(select).fetchall()
            except sqlite3.Error as error:
                self.log_warn(F'failed to read table {table}: {error!s}')
                continue
            names = [column[0] for column in cursor.description]
            result[table] = [dict(zip(names, row)) for row in rows]

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
