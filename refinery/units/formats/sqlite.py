from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class sqlite(Unit):
    """
    Extracts data from SQLite3 databases. Each row is returned as a single
    output chunk in JSON format.

    If no query is provided, the unit will extract all tables.
    """

    def __init__(
        self,
        query: Param[
            str, Arg.String("-q", help="The SQL query to execute.")
        ] = "SELECT * FROM sqlite_master WHERE type='table';",
    ):
        super().__init__(query=query)

    @Unit.Requires("sqlite3", ["formats"])
    def _sqlite3_connect():
        import sqlite3

        return sqlite3.connect

    def process(self, data):
        with tempfile.NamedTemporaryFile(dir=os.getcwd(), delete=False) as temp_file:
            temp_file.write(data)
            temp_file.flush()
            temp_path = temp_file.name
        try:
            with self._sqlite3_connect(temp_path) as con:
                cursor = con.cursor().execute(self.args.query)
                fields = (
                    [i[0] for i in cursor.description] if cursor.description else []
                )
                for row in cursor:
                    if fields:
                        cleaned_row = {}
                        for i in range(len(fields)):
                            if isinstance(row[i], bytes):
                                cleaned_row[i] = row[i].decode(self.codec)
                            else:
                                cleaned_row[fields[i]] = row[i]
                        yield json.dumps(cleaned_row).encode(self.codec)
                    else:
                        yield json.dumps(list(row)).encode(self.codec)
        except sqlite3.Error as e:
            raise ValueError(f"Failed to process SQLite database: {e}")
        finally:
            try:
                os.unlink(temp_path)
            except (PermissionError, FileNotFoundError):
                pass
