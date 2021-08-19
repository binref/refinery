#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from jsbeautifier import beautify
from jsbeautifier.unpackers import javascriptobfuscator as _jso

from .. import arg, Unit
from ...lib.decorators import unicoded

# TODO: This is a workaround for the following bug:
# https://github.com/beautify-web/js-beautify/issues/1350
_jso.detect = lambda *_: False


class ppjscript(Unit):
    """
    Pretty-prints JavaScript without any reflection or evaluation.
    """
    def __init__(self, indent: arg.number('-i', help=(
        'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4
    ):
        return super().__init__(indent=indent)

    @unicoded
    def process(self, data: str) -> str:
        return beautify(data, dict(eval_code=False, indent_size=self.args.indent))
