from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class ppjscript(Unit):
    """
    Pretty-prints JavaScript without any reflection or evaluation.
    """
    def __init__(
        self,
        indent: Param[int, Arg.Number('-i', help=(
            'Number of space characters used for indentation in the output. Default is {default}.'))] = 4,
        strip_comments: Param[bool, Arg.Switch('-c', help=(
            'Remove all comments from the input before pretty-printing.'))] = False,
        strip_lines: Param[bool, Arg.Switch('-b', group='LINES', help=(
            'Remove all line breaks after potentially stripping comments, before beautifying.'))] = False,
        keep_lines: Param[bool, Arg.Switch('-B', group='LINES', help=(
            'Preserve line breaks as they occur in the input.'))] = False,
        keep_escapes: Param[bool, Arg.Switch('-E', help=(
            'Preserve unnecessary escape sequences in string literals.'))] = False,
    ):
        return super().__init__(
            indent=indent,
            strip_comments=strip_comments,
            strip_lines=strip_lines,
            keep_lines=keep_lines,
            keep_escapes=keep_escapes,
        )

    @Unit.Requires('jsbeautifier', ['display', 'extended'])
    def _jsb():
        import jsbeautifier
        import jsbeautifier.unpackers.javascriptobfuscator

        # TODO: This is a workaround for the following bug:
        # https://github.com/beautify-web/js-beautify/issues/1350
        jsbeautifier.unpackers.javascriptobfuscator.detect = lambda *_: False
        return jsbeautifier

    def process(self, data: bytearray):
        if self.args.strip_comments:
            from refinery.units.obfuscation.js.comments import deob_js_comments
            code = data | deob_js_comments | str
        else:
            code = data.decode(self.codec)
        if self.args.strip_lines:
            code = ' '.join(code.splitlines(False))
        options = self._jsb.default_options()
        options.eval_code = False
        options.indent_size = self.args.indent
        options.unescape_strings = not self.args.keep_escapes
        options.preserve_newlines = self.args.keep_lines
        options.indent_level = 0
        options.keep_array_indentation = False
        return self._jsb.beautify(
            code.strip(), options).encode(self.codec)
