from __future__ import annotations

from refinery.units import Arg, Unit


class repl(Unit):
    """
    Performs a simple binary string replacement on the input data.
    """

    def __init__(
        self,
        search : Arg(help='This is the search term.'),
        replace: Arg(help='The substitution string. Leave this empty to remove all occurrences of the search term.') = B'',
        count  : Arg.Number('-n', help='Only replace the given number of occurrences') = -1
    ):
        super().__init__(search=search, replace=replace, count=count)

    def process(self, data: bytearray):
        return data.replace(
            self.args.search,
            self.args.replace,
            self.args.count
        )
