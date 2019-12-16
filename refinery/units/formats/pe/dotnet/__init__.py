#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from typing import Any
from enum import Enum
from hashlib import md5, sha1, sha256, sha512
from zlib import crc32

from .... import Unit
from ....encoding.hex import hex
from ....encoding.esc import esc
from ....encoding.url import url
from ....encoding.b64 import b64

from .....lib.dotnet.types import Blob


class BinaryEncoding(Enum):
    hex = hex
    esc = esc
    url = url
    b64 = b64


class BinaryDigest(Enum):
    md5 = md5
    crc32 = crc32
    sha1 = sha1
    sha256 = sha256
    sha512 = sha512


class JSONEncoderUnit(Unit, abstract=True):
    """
    An abstract unit that provides the interface for displaying parsed data
    as JSON. Since the parsed data may contain binary strings, a method for
    encoding binary strings needs to be specified, the default being hex
    encoding.
    """

    def interface(self, argp):
        enc = argp.add_mutually_exclusive_group()
        enc.add_argument(
            '-e', '--encoder', choices=[m.name for m in BinaryEncoding],
            default='hex', nargs='?', metavar='ENC', help=(
                'Select an encoder unit used to represent binary data in '
                'the JSON output. Available are: {}. The default encoder '
                'is hex.'.format(', '.join(m.name for m in BinaryEncoding))
            )
        )
        enc.add_argument(
            '-d', '--digest', choices=[d.name for d in BinaryDigest],
            default=None, nargs='?', metavar='HASH', help=(
                'Alternatively, select a hashing algorithm to digest binary data. '
                'The available algorithms are: {}.'.format(
                    ', '.join(d.name for d in BinaryDigest)
                )
            )
        )
        return super().interface(argp)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.args.encoder = BinaryEncoding[self.args.encoder].value()

        if self.args.digest:
            self.args.digest = BinaryDigest[self.args.digest].value

        class _encoder(json.JSONEncoder):
            def default(e, obj):
                try:
                    return super().default(obj)
                except TypeError:
                    pass

                if isinstance(obj, Blob):
                    obj = bytes(obj)
                if isinstance(obj, bytes) or isinstance(obj, bytearray):
                    if self.args.digest:
                        return self.args.digest(obj).hexdigest()
                    else:
                        return self.args.encoder.reverse(obj).decode('utf8')
                else:
                    return str(obj)

        self._encoder = _encoder

    def to_json(self, obj: Any) -> bytes:
        return json.dumps(obj, cls=self._encoder, indent=4).encode(self.codec)
