#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

    def process(self, data):
        import csv
        import io
        import json

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
            rows = csv.reader(stream, quotechar=quote, delimiter=delim, skipinitialspace=True)
            keys = next(rows)
            for row in rows:
                out = {key: convert(value) for key, value in zip(keys, row)}
                yield json.dumps(out, indent=4).encode(self.codec)
