#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import codecs

from .. import Unit


class recode(Unit):
    """
    Expects input string data encoded in the `from` encoding and encodes it in
    the `to` encoding, then outputs the result.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument(metavar='from', dest='decode', type=str,
            help='input encoding of the data')
        argp.add_argument(metavar='to', dest='encode', nargs='?', default=cls.codec, type=str,
            help=F'output encoding, default is {cls.codec}')
        return super().interface(argp)

    def process(self, data):
        return codecs.encode(
            codecs.decode(
                data,
                self.args.decode,
                errors='surrogateescape'
            ),
            self.args.encode,
            errors='surrogateescape'
        )
