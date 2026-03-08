from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class puny(Unit):
    """
    Punycode encoding and decoding as defined in RFC 3492, commonly used for Internationalized
    Domain Names in Applications (IDNA, RFC 5891). Punycode represents Unicode characters using
    only the ASCII character set, which is required for DNS labels. For example, the domain
    `münchen.de` becomes `xn--mnchen-3ya.de` in IDNA encoding. By default, this unit uses the
    full IDNA encoding which handles the `xn--` ACE prefix used in DNS. Use the `--raw` flag
    to use raw punycode without the IDNA prefix handling. Punycode is encountered in phishing
    analysis, internationalized domain name resolution, and email header inspection.
    """

    def __init__(
        self,
        raw: Param[bool, Arg.Switch('-r', help='Use raw punycode instead of IDNA encoding.')] = False,
    ):
        super().__init__(raw=raw)

    def process(self, data: bytearray):
        codec = 'punycode' if self.args.raw else 'idna'
        return data.decode(codec).encode('latin1')

    def reverse(self, data: bytearray):
        codec = 'punycode' if self.args.raw else 'idna'
        return data.decode('latin1').encode(codec)
