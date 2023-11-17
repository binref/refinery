#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.decorators import unicoded


class ppjscript(Unit):
    """
    Pretty-prints JavaScript without any reflection or evaluation.
    """
    def __init__(self, indent: Arg.Number('-i', help=(
        'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4
    ):
        return super().__init__(indent=indent)

    @Unit.Requires('jsbeautifier', 'display')
    def _jsb():
        import jsbeautifier
        import jsbeautifier.unpackers.javascriptobfuscator
        # TODO: This is a workaround for the following bug:
        # https://github.com/beautify-web/js-beautify/issues/1350
        jsbeautifier.unpackers.javascriptobfuscator.detect = lambda *_: False
        return jsbeautifier

    @unicoded
    def process(self, data: str) -> str:
        return self._jsb.beautify(data, dict(eval_code=False, indent_size=self.args.indent))
