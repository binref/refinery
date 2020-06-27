#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class cfmt(Unit):
    """
    Transform a given chunk by applying a format string operation. Two types of string format
    operations are performed. First, the unit attempts to pass the incoming data as the only
    formatting option, which will only succeed if the formatting string contains exactly one
    placeholder of the form `%b`. Next, the unit will pass a mapping object as the formatting
    option which contains all incoming metadata. The incoming data can be accessed from this
    mapping object under the name `data`, or using the empty string. For example, the
    following formatting option will print the value of the meta variable "path", followed by
    a colon, a space, and the first five bytes of the incoming data:

        "%(path)b: %(data).5b"

    The following would produce the same output:

        "%%(path)b: %.5b"

    But note that `%%` had to be used for the meta variable substitution because the first
    formatting operation (which does not use a mapping object) requires escaping the percent
    sign.
    """

    def __init__(self, *format: arg(help='Binary format strings.')):
        super().__init__(format=format)

    def process(self, data):

        class formatter(dict):
            unit = self

            def __missing__(self, key):
                if key.lower() == b'data' or not key:
                    return data
                result = data[key.decode('utf8')]
                if isinstance(result, str):
                    return result.encode(self.unit.codec)
                return result

        formatter = formatter()

        for result in self.args.format:
            try:
                result %= data
            except TypeError as T:
                self.log_debug(str(T))
            try:
                result %= formatter
            except TypeError as T:
                self.log_debug(str(T))
            yield result
