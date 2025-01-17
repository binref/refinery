#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import sqlite3
import sys
import functools

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.json import BytesAsStringEncoder


class xtsql(PathExtractorUnit):
    """
    Extract files from SQLite3 databases.
    """
    def unpack(self, data: bytearray):
        def _json(object):
            with BytesAsStringEncoder as encoder:
                return encoder.dumps(object).encode(self.codec)

        if sys.version_info[:2] < (3, 11):
            raise NotImplementedError(F'python 3.11 is required to use {self.__class__.__name__}.')

        database = sqlite3.connect(':memory:')
        database.deserialize(data)
        cursor = database.cursor()
        result: dict[str, list[dict[str, int | float | str | bytes]]] = {}

        listing: list[tuple[str, str]] = cursor.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table';").fetchall()

        for table, spec in listing:
            result[table] = t = []
            ct, _table, names = spec.partition(table)
            names = names.strip()
            if (
                table != _table
                or ct.strip().upper().split() != ['CREATE', 'TABLE']
                or not names.endswith(')')
                or not names.startswith('(')
            ):
                raise ValueError(F'Unexpeted SQL statement in master table: {spec}')
            names = [next(iter(name.strip().split()))
                for name in names[1:-1].split(',')]
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
    def handles(cls, data: bytearray):
        return memoryview(data)[:15] == B'SQLite format 3'
