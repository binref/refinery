from __future__ import annotations

import io
import re

from refinery.lib.decorators import unicoded
from refinery.lib.patterns import pattern_vbastr_token
from refinery.units import Unit

_VB_CONSTANTS = {
    'vbcrlf'       : '\r\n',
    'vbcr'         : '\r',
    'vblf'         : '\n',
    'vbnullchar'   : '\0',
    'vbtab'        : '\t',
    'vbback'       : '\b',
    'vbformfeed'   : '\f',
    'vbverticaltab': '\v',
}

_VB_REVERSE = {
    0x0: b'vbNullChar',
    0x8: b'vbBack',
    0x9: b'vbTab',
    0xA: b'vbLf',
    0xB: b'vbVerticalTab',
    0xC: b'vbFormFeed',
    0xD: b'vbCr',
}


def _parse_vbaint(s: str) -> int:
    s = s.rstrip('&%^')
    if s[:2].lower() == '&h':
        return int(s[2:], 16)
    if s[:2].lower() == '&o':
        return int(s[2:] or '0', 8)
    if s[:2].lower() == '&b':
        return int(s[2:], 2)
    return int(s)


class escvb(Unit):
    """
    Decodes Visual Basic (VB/VBA/VBS) string expressions. Handles concatenation of string
    literals, Chr/ChrW calls, and named constants like vbCrLf, joined by & or +.
    """
    @unicoded
    def process(self, data: str) -> str:
        out = io.StringIO()
        for match in re.finditer(pattern_vbastr_token, data, re.IGNORECASE):
            token = match.group()
            if token[0] == '"':
                out.write(token[1:-1].replace('""', '"'))
            elif token[0] in 'cC':
                self.log_always(token)
                _, _, arg = token.partition('(')
                arg, _, _ = arg.partition(')')
                out.write(chr(_parse_vbaint(arg)))
            elif value := _VB_CONSTANTS.get(token.lower()):
                out.write(value)
            else:
                raise RuntimeError
        if v := out.getvalue():
            return v
        elif data[:1] == '"' and data[-1:] == '"':
            return data[1:-1].replace('""', '"')
        return data

    def reverse(self, data):
        run = bytearray()
        out = io.BytesIO()

        def _flush():
            if run:
                if out.tell():
                    out.write(B' & ')
                out.write(B'"')
                out.write(run)
                out.write(B'"')
                run.clear()
            return out

        for b in data:
            if 0x20 <= b <= 0x7E:
                run.append(b)
                if b == 0x22:
                    run.append(b)
                continue
            try:
                seq = _VB_REVERSE[b]
            except KeyError:
                seq = B'Chr(%d)' % b
            if _flush().tell():
                out.write(B' & ')
            out.write(seq)
        return _flush().getvalue()
