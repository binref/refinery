from __future__ import annotations

import csv as _csv
import io

from typing import Any

from refinery.lib import json
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import isodate
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class csv(Unit):
    """
    Extracts the rows of a CSV document with header and converts them into JSON chunks.
    """
    def __init__(
        self,
        quote: Param[buf, Arg('-q', help='Specify the quote character, the default is a double quote.')] = B'"',
        delim: Param[buf, Arg('-d', help='Specify the delimiter, the default is a single comma.')] = B','
    ):
        super().__init__(quote=quote, delim=delim)

    def json_to_csv(self, table: list):
        quote = self.args.quote.decode(self.codec)
        delim = self.args.delim.decode(self.codec)

        if not isinstance(table, list):
            raise ValueError('Input must be a JSON list.')

        out = MemoryFile()

        with io.TextIOWrapper(out, self.codec, newline='') as stream:
            writer = _csv.writer(stream, quotechar=quote, delimiter=delim, skipinitialspace=True)
            for row in table:
                if not isinstance(row, list):
                    break
                if not all(isinstance(item, str) for item in row):
                    break
                writer.writerow(row)
            else:
                return out.getvalue()

        keys = {}
        # A dictionary is used here over a set because dictionaries remember insertion order.
        # When feeding the unit a sequence of JSON objects, the user would likely expect the
        # column order in the resulting CSV to derive from the entry oder in the JSON data.

        for row in table:
            for key in row:
                if not isinstance(key, str):
                    continue
                keys[key] = None

        keys = list(keys)
        out = MemoryFile()

        with io.TextIOWrapper(out, self.codec, newline='') as stream:
            writer = _csv.writer(stream, quotechar=quote, delimiter=delim, skipinitialspace=True)
            writer.writerow(keys)
            for row in table:
                writer.writerow([str(row.get(key, '')) for key in keys])
            return out.getvalue()

    def reverse(self, data: bytearray):
        try:
            table: list[dict[str, Any]] = json.loads(data)
        except Exception:
            table: list[dict[str, Any]] = [json.loads(line) for line in data.splitlines()]
        return self.json_to_csv(table)

    def process(self, data):
        quote = self.args.quote.decode(self.codec)
        delim = self.args.delim.decode(self.codec)

        def convert(field: str):
            if field.isdigit() and not field.startswith('0'):
                return int(field)
            date = isodate(field)
            if date is not None:
                return date.isoformat(' ', 'seconds')
            return field

        with io.TextIOWrapper(MemoryFile(data), self.codec) as stream:
            rows = _csv.reader(stream, quotechar=quote, delimiter=delim, skipinitialspace=True)
            keys = next(rows)
            for row in rows:
                out = {key: convert(value) for key, value in zip(keys, row)}
                yield json.dumps(out)
