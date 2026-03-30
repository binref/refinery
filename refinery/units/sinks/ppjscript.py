from __future__ import annotations

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
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
            'Remove all comments from the input.'))] = False,
        keep_escapes: Param[bool, Arg.Switch('-E', help=(
            'Preserve unnecessary escape sequences in string literals.'))] = False,
    ):
        return super().__init__(
            indent=indent,
            strip_comments=strip_comments,
            keep_escapes=keep_escapes,
        )

    def process(self, data: bytearray):
        code = data.decode(self.codec)
        ast = JsParser(code).parse()
        synth = JsSynthesizer(
            indent=' ' * self.args.indent,
            unescape_strings=not self.args.keep_escapes,
            strip_comments=self.args.strip_comments,
        )
        return synth.convert(ast).encode(self.codec)
