import json
from json.decoder import WHITESPACE
from typing import Generator, Any

import jq as _jq

from refinery import Unit, Arg


def parse_multiple_json(data: bytes) -> Generator[Any, None, None]:
    doc = data.decode("utf-8")

    decoder = json.JSONDecoder()
    i = 0
    while True:
        i = WHITESPACE.match(doc, i).end()
        if i >= len(doc):
            return

        obj, i = decoder.raw_decode(doc, idx=i)
        yield obj


class jq(Unit):
    meta_key_json_key = "json_key"

    """
    This unit is a thin wrapper around the tool `jq`, with some adjustments to fit the binref-principles.
    Each chunk may contain multiple JSON values, separated by whitespaces. Multiple such values will be
    joined into a single array per chunk, this works similar to the `--slurp` flag of the upstream jq-cli.
    If there is only one value, it will not be wrapped in an array.
    """

    def __init__(self,
                 raw: Arg.Switch("-r", help="output raw data rather than json-encoded data"),
                 sort_keys: Arg.Switch("-s", help="sort keys"),
                 compact: Arg.Switch("-c", help="output compact json, rather than pretty printing"),
                 explode: Arg.Switch("-e", help="output one chunk per array-item or per object-key"),
                 filter: Arg(help="jq compatible filter") = b"."):
        super().__init__(raw=raw, sort_keys=sort_keys, compact=compact, explode=explode, filter=filter)

    def process(self, data: bytearray):
        if not data:
            return data

        parsed = list(parse_multiple_json(data))
        if len(parsed) == 1:
            parsed = parsed[0]

        for obj in _jq.compile(self.args.filter.decode(self.codec)).input(parsed):
            yield from self._chunk_and_format_data(obj)

    def _chunk_and_format_data(self, data):
        if self.args.explode:
            if isinstance(data, list):
                yield from (self.format_json(chunk) for chunk in data)
            elif isinstance(data, dict):
                yield from self._chunk_and_format_dict(data)
        else:
            yield self.format_json(data)

    def _chunk_and_format_dict(self, data: dict):
        for key, value in data.items():
            metas = {self.meta_key_json_key: key}
            yield self.labelled(self.format_json(value), **metas)

    def format_json(self, data) -> bytes:
        if self.args.raw:
            return self._format_json_raw(data)
        else:
            return self._format_json_dumps(data)

    def _format_json_raw(self, data) -> bytes:
        if isinstance(data, (list, dict)):
            # This mimics the behaviour of the upstream jq-cli
            return self._format_json_dumps(data)
        return str(data).encode(self.codec)

    def _format_json_dumps(self, data) -> bytes:
        kwargs = {}
        if self.args.sort_keys:
            kwargs["sort_keys"] = True
        if not self.args.compact:
            kwargs["indent"] = 4
        return json.dumps(data, **kwargs).encode(self.codec)
