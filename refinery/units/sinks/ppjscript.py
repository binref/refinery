#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit


class ppjscript(Unit):
    """
    Pretty-prints JavaScript without any reflection or evaluation.
    """
    def __init__(
        self,
        indent: Arg.Number('-i', help=(
            'Number of space characters used for indentation in the output. Default is {default}.')) = 4,
        strip_comments: Arg.Switch('-c', help=(
            'Remove all comments from the input before pretty-printing.')) = False,
        strip_lines: Arg.Switch('-b', group='LINES', help=(
            'Remove all line breaks after potentially stripping comments, before beautifying.')) = False,
        keep_lines: Arg.Switch('-B', group='LINES', help=(
            'Preserve line breaks as they occur in the input.')) = False,
        keep_escapes: Arg.Switch('-E', help=(
            'Preserve unnecessary escape sequences in string literals.')) = False,
    ):
        return super().__init__(
            indent=indent,
            strip_comments=strip_comments,
            strip_lines=strip_lines,
            keep_lines=keep_lines,
            keep_escapes=keep_escapes,
        )

    @Unit.Requires('jsbeautifier', 'display', 'extended')
    def _jsb():
        import jsbeautifier
        import jsbeautifier.unpackers.javascriptobfuscator
        # TODO: This is a workaround for the following bug:
        # https://github.com/beautify-web/js-beautify/issues/1350
        jsbeautifier.unpackers.javascriptobfuscator.detect = lambda *_: False
        return jsbeautifier

    def process(self, data: bytes):
        if self.args.strip_comments:
            from refinery.units.obfuscation.js.comments import deob_js_comments
            data = data | deob_js_comments | str
        else:
            data = data.decode(self.codec)
        if self.args.strip_lines:
            data = ' '.join(data.splitlines(False))
        return self._jsb.beautify(data.strip(), dict(
            eval_code=False,
            indent_size=self.args.indent,
            unescape_strings=not self.args.keep_escapes,
            preserve_newlines=self.args.keep_lines,
            indent_level=0,
            keep_function_indentation=False,
            keep_array_indentation=False,
        )).encode(self.codec)
