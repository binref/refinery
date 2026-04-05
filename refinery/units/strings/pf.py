from __future__ import annotations

from refinery.lib.meta import metavars
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class pf(Unit):
    """
    Print, format, and transform data using a format string expression.

    Stands for "Print Format". The positional format string placeholder `{}` will be replaced by
    the incoming data, named placeholders have to exist as meta variables in the current chunk.
    For example, the following pipeline can be used to print all files in a given directory with
    their corresponding SHA-256 hash:

        ef ** [| sha256 -t | pf {} {path} ]]

    By default, format string arguments are simply joined along a space character to form a single
    format string. Backslash escape sequences are unescaped by default.
    """

    def __init__(
        self,
        *formats: Param[buf, Arg.Binary(help='Format strings.', metavar='format')],
        variable: Param[str, Arg.String('-n', metavar='N', help='Store the formatted string in a meta variable.')] = '',
        separator: Param[str, Arg.String('-s', group='SEP', metavar='S',
            help='Separator to insert between format strings. The default is a space character.')] = ' ',
        multiplex: Param[bool, Arg.Switch('-m', group='SEP',
            help='Do not join the format strings along the separator, generate one output for each.')] = False,
        raw: Param[bool, Arg.Switch('-r', help='Do not interpret backslash-escape sequences in format strings.')] = False,
    ):
        def fixfmt(fmt: bytes | str):
            if not isinstance(fmt, str):
                fmt = bytes(fmt).decode(self.codec)
            return fmt
        _formats = [fixfmt(f) for f in formats]
        if not multiplex:
            _formats = [fixfmt(separator).join(_formats)]
        super().__init__(formats=_formats, variable=variable, raw=raw)

    def process(self, data):
        meta = metavars(data)
        args = [data]
        variable = self.args.variable
        escaped = not self.args.raw
        for spec in self.args.formats:
            result = meta.format_bin(
                spec,
                codec=self.codec,
                args=args,
                escaped=escaped,
                lenient=True
            )
            if variable:
                result = self.labelled(data, **{variable: result})
            yield result
