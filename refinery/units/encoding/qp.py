from __future__ import annotations

import quopri

from refinery.units import Unit


class qp(Unit):
    """
    Quoted-Printable (QP) encoding and decoding as specified in RFC 2045, Section 6.7. Quoted-
    Printable is a MIME content transfer encoding that represents non-ASCII bytes as an equals
    sign followed by two hexadecimal digits (e.g. `=C3=BC` for the UTF-8 encoding of `ü`).
    Printable ASCII characters (33-126, except `=`) are represented as themselves, and soft line
    breaks are indicated by `=` at the end of a line. This encoding is predominantly used in
    email messages (MIME), particularly in headers and message bodies that contain non-ASCII
    characters or long lines. It is also found in vCard files and TNEF/MAPI data.
    """
    def process(self, data):
        return quopri.decodestring(bytes(data))

    def reverse(self, data):
        return quopri.encodestring(bytes(data))
