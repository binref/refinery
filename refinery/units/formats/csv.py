#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Dict, Any

import csv as _csv
import io
import json

from refinery.units import Unit
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import isodate


class csv(Unit):
    """
    Extracts the rows of a CSV document with header and converts them into JSON chunks.
    """
    def __init__(
        self,
        quote: Unit.Arg('-q', help='Specify the quote character, the default is a double quote.') = B'"',
        delim: Unit.Arg('-d', help='Specify the delimiter, the default is a single comma.') = B','
    ):
        super().__init__(quote=quote, delim=delim)

    def reverse(self, data: bytearray):
        quote = self.args.quote.decode(self.codec)
        delim = self.args.delim.decode(self.codec)

        try:
            table: List[Dict[str, Any]] = json.loads(data)
        except Exception:
            table: List[Dict[str, Any]] = [json.loads(line) for line in data.splitlines()]

        if not isinstance(table, list):
            raise ValueError('Input must be a JSON list.')

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
            for row in table:
                writer.writerow([str(row.get(key, '')) for key in keys])
            return out.getvalue()

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
                yield json.dumps(out, indent=4).encode(self.codec)
