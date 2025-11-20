from __future__ import annotations

import sqlite3

from refinery.lib import json
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class sqlite(Unit):
    """
    Extracts data from SQLite3 databases. Each row is returned as a single output chunk in JSON
    format. If no query is provided, the unit will extract all table metadata from the database.
    """
    def __init__(
        self,
        query: Param[
            str, Arg.String('query', help='The SQL query to execute.')
        ] = "SELECT * FROM sqlite_master WHERE type='table';",
    ):
        super().__init__(query=query)

    def process(self, data):
        try:
            with sqlite3.connect(':memory:') as database:
                try:
                    database.deserialize(data)
                except AttributeError:
                    raise NotImplementedError(F'Python >= 3.11 is required to use {self.name}.')
                cursor = database.cursor().execute(self.args.query)
                fields = (
                    [i[0] for i in cursor.description] if cursor.description else []
                )
                for row in cursor:
                    if not fields:
                        cleaned_row = list(row)
                    else:
                        cleaned_row = {}
                        for i in range(len(fields)):
                            if isinstance(row[i], bytes):
                                cleaned_row[i] = row[i].decode(self.codec)
                            else:
                                cleaned_row[fields[i]] = row[i]
                    yield json.dumps(
                        cleaned_row, pretty=False)
        except sqlite3.Error as e:
            raise ValueError(F'Failed to process SQLite database: {e}')
