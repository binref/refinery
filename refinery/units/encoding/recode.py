#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import codecs

from .. import arg, Unit


class recode(Unit):
    """
    Expects input string data encoded in the `from` encoding and encodes it in
    the `to` encoding, then outputs the result.
    """

    def __init__(
        self,
        decode: arg(metavar='decode-as', type=str, help='Input encoding; Guess encoding by default.') = None,
        encode: arg(metavar='encode-as', type=str, help=F'Output encoding; The default is {Unit.codec}.') = Unit.codec
    ):
        super().__init__(decode=decode, encode=encode)

    def detect(self, data):
        mv = memoryview(data)
        if not any(mv[1::2]): return 'utf-16le'
        if not any(mv[0::2]): return 'utf-16be'
        import chardet
        detection = chardet.detect(data)
        codec = detection['encoding']
        self.log_info(lambda: F'Using input encoding: {codec}, detected with {int(detection["confidence"]*100)}% confidence.')
        return codec

    def process(self, data):
        codec = self.args.decode
        if codec is None:
            codec = self.detect(data)
        return codecs.encode(
            codecs.decode(data, codec, errors='surrogateescape'),
            self.args.encode,
            errors='surrogateescape'
        )
