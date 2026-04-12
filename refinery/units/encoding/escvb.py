from __future__ import annotations

import io
import re

from refinery.lib.patterns import pattern_vbastr_token
from refinery.units import Unit

_VB_CONSTANTS = {
    b'vbcrlf'       : b'\r\n',
    b'vbcr'         : b'\r',
    b'vblf'         : b'\n',
    b'vbnullchar'   : b'\0',
    b'vbtab'        : b'\t',
    b'vbback'       : b'\b',
    b'vbformfeed'   : b'\f',
    b'vbverticaltab': b'\v',
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

_VB_INTEGER_PREFIX = {
    B'h': 0x10,
    B'H': 0x10,
    B'o': 0x08,
    B'O': 0x08,
    B'b': 0x02,
    B'B': 0x02,
}


def _parse_vbaint(literal: bytes) -> int:
    literal = literal.rstrip(b'&%^')
    if literal[0] == 0x26:
        base = _VB_INTEGER_PREFIX[literal[1:2]]
        literal = literal[2:]
    else:
        base = 10
    return int(literal, base)


class escvb(Unit):
    """
    Decodes Visual Basic (VB/VBA/VBS) string expressions. Handles concatenation of string
    literals, Chr/ChrW calls, and named constants like vbCrLf, joined by & or +.
    """
    def process(self, data: bytearray):
        out = bytearray()
        for match in re.finditer(pattern_vbastr_token.encode(), data, re.IGNORECASE):
            tok = match.group()
            if tok[0] == 0x22:
                out.extend(tok[1:-1].replace(b'""', b'"'))
            elif tok.startswith((B'c', B'C')):
                _, _, arg = tok.partition(b'(')
                arg, _, _ = arg.partition(b')')
                arg = _parse_vbaint(arg)
                try:
                    out.append(arg)
                except ValueError:
                    out.extend(chr(arg).encode(self.codec))
            elif value := _VB_CONSTANTS.get(tok.lower()):
                out.extend(value)
            else:
                raise RuntimeError(F'cannot decode token: {tok.decode()}')
        if out:
            return out
        elif len(data) >= 2 and data[0] == 0x22 == data[-1]:
            return data[1:-1].replace(b'""', b'"')
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
            if 0x22 <= b <= 0x7E or b == 0x20:
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
