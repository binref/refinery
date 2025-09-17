from __future__ import annotations

from functools import partial

from refinery.lib.meta import metavars
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class pf(Unit):
    """
    Stands for "Print Format": Transform a given chunk by applying a format string operation. The
    positional format string placeholder `{}` will be replaced by the incoming data, named
    placeholders have to exist as meta variables in the current chunk. For example, the following
    pipeline can be used to print all files in a given directory with their corresponding SHA-256
    hash:

        ef ** [| sha256 -t | pf {} {path} ]]

    By default, format string arguments are simply joined along a space character to form a single
    format string.
    """

    def __init__(
        self,
        *formats: Param[buf, Arg.Binary(help='Format strings.', metavar='format')],
        variable: Param[str, Arg.String('-n', metavar='N', help='Store the formatted string in a meta variable.')] = None,
        separator: Param[str, Arg.String('-s', group='SEP', metavar='S',
            help='Separator to insert between format strings. The default is a space character.')] = ' ',
        multiplex: Param[bool, Arg.Switch('-m', group='SEP',
            help='Do not join the format strings along the separator, generate one output for each.')] = False,
        binary: Param[bool, Arg.Switch('-b', help='Use the binary formatter instead of the string formatter.')] = False,
        unescape: Param[bool, Arg.Switch('-e', help='Interpret escape sequences in format strings.')] = False,
    ):
        def fixfmt(fmt: bytes | str):
            if unescape:
                if isinstance(fmt, str):
                    fmt = fmt.encode('latin1')
                return bytes(fmt).decode('unicode-escape')
            elif not isinstance(fmt, str):
                fmt = bytes(fmt).decode(self.codec)
            return fmt
        _formats = [fixfmt(f) for f in formats]
        if not multiplex:
            _formats = [fixfmt(separator).join(_formats)]
        super().__init__(formats=_formats, variable=variable, binary=binary)

    def process(self, data):
        meta = metavars(data)
        meta.ghost = True
        args = [data]
        variable = self.args.variable
        if self.args.binary:
            formatter = partial(meta.format_bin, codec=self.codec, args=args)
        else:
            def formatter(spec):
                return meta.format_str(spec, self.codec, args).encode(self.codec)
        for spec in self.args.formats:
            result = formatter(spec)
            if variable is not None:
                result = self.labelled(data, **{variable: result})
            yield result
