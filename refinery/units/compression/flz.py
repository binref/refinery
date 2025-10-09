from __future__ import annotations

from refinery.lib.array import make_array
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, Unit

_MAX_CPY = 0x20
_MAX_LEN = 0x100 + 8
_MAX_LEN_M2 = _MAX_LEN - 2
_MAX_L1_DISTANCE = 0x2000
_MAX_L2_DISTANCE = 0x1FFF
_MAX_FARDISTANCE = 0xFFFF + _MAX_L2_DISTANCE - 1

_HASH_BITS = 13
_HASH_SIZE = (1 << _HASH_BITS)
_HASH_MASK = (_HASH_SIZE - 1)


def _flz_hash(v: int):
    h = (v * 0x9E3779B9) >> (32 - _HASH_BITS)
    return h & _HASH_MASK


def _flz_cmp(p: memoryview, q: memoryview):
    upper = len(q)
    lower = 1
    if upper not in range(1, len(p) + 1):
        raise ValueError
    while lower <= upper and p[:lower] == q[:lower]:
        lower <<= 1
    upper = min(lower, upper)
    lower >>= 1
    while lower < upper:
        midpoint = (lower + upper + 1) // 2
        if p[:midpoint] == q[:midpoint]:
            lower = midpoint
        else:
            upper = midpoint - 1
    return lower + 1


def _flz_literals(runs: int, src: memoryview, dst: bytearray):
    while runs >= _MAX_CPY:
        dst.append(_MAX_CPY - 1)
        dst.extend(src[:_MAX_CPY])
        src = src[_MAX_CPY:]
        runs -= _MAX_CPY
    if runs > 0:
        dst.append((runs - 1) & 0xFF)
        dst.extend(src[:runs])


def _flz1_match(nc: int, distance: int, op: bytearray):
    distance -= 1
    write = op.append
    while nc > _MAX_LEN_M2:
        write((7 << 5) + (distance >> 8) & 0xFF)
        write(_MAX_LEN_M2 - 7 - 2)
        write(distance & 0xFF)
        nc -= _MAX_LEN_M2
    if nc < 7:
        write((nc << 5) + (distance >> 8) & 0xFF)
        write(distance & 0xFF)
    else:
        write((7 << 5) + (distance >> 8) & 0xFF)
        write(nc - 7 & 0xFF)
        write(distance & 0xFF)


def _flz2_match(nc: int, distance: int, op: bytearray):
    distance -= 1
    write = op.append
    if distance < _MAX_L2_DISTANCE:
        if nc < 7:
            write((nc << 5) + (distance >> 8))
            write(distance & 0xFF)
        else:
            write((7 << 5) + (distance >> 8))
            nc -= 7
            while nc > 0xFF:
                nc -= 0xFF
                write(0xFF)
            write(nc)
            write(distance & 0xFF)
    else:
        if nc < 7:
            distance -= _MAX_L2_DISTANCE
            write((nc << 5) + 31)
            write(255)
            write(distance >> 8)
            write(distance & 0xFF)
        else:
            distance -= _MAX_L2_DISTANCE
            write((7 << 5) + 31)
            nc -= 7
            while nc > 0xFF:
                nc -= 0xFF
                write(0xFF)
            write(nc)
            write(255)
            write(distance >> 8)
            write(distance & 0xFF)


class InputOutOfBounds(EOFError):
    pass


class InvalidFlzLevel(ValueError):
    def __init__(self, level: int) -> None:
        super().__init__(F'Invalid level {level!r}, may only be 0 or 1.')


def _flz_compress(
    input: memoryview,
    op: bytearray,
    level: int,
):
    if level not in (0, 1):
        raise InvalidFlzLevel(level)
    elif level:
        matches = _flz2_match
        lim = _MAX_FARDISTANCE
    else:
        matches = _flz1_match
        lim = _MAX_L1_DISTANCE

    total = len(input)
    ip = 0
    ip_bound = total - 4
    ip_limit = total - 12 - 1
    tab = make_array(4, _HASH_SIZE)
    sq = 0
    rp = 0
    anchor = ip
    ip += 2

    while ip < ip_limit:
        while True:
            sb = input[ip:][:3]
            sq = int.from_bytes(sb, 'little')
            hv = _flz_hash(sq)
            rp, tab[hv] = tab[hv], ip
            distance = ip - rp
            if ip < ip_limit:
                ip += 1
            else:
                break
            if distance < lim and sb == input[rp:rp + 3]:
                break
        if ip >= ip_limit:
            break
        if level > 0 and distance >= _MAX_L2_DISTANCE and input[rp:][3:5] != input[ip:][3:5]:
            continue
        else:
            ip -= 1
        if ip > anchor:
            _flz_literals(ip - anchor, input[anchor:], op)
        nc = _flz_cmp(input[rp + 3:], input[ip + 3:ip_bound])
        matches(nc, distance, op)
        ip += nc
        sq = int.from_bytes(input[ip:ip + 4], 'little')
        tab[_flz_hash((sq >> 0) & 0xFFFFFF)], ip = ip, ip + 1
        tab[_flz_hash((sq >> 8) & 0xFFFFFF)], ip = ip, ip + 1
        anchor = ip
    _flz_literals(total - anchor, input[anchor:], op)
    op[0] |= level << 5


def _flz_decompress(input: memoryview, level: int):
    if level not in (0, 1):
        raise InvalidFlzLevel(level)
    ip = 0
    ip_limit = ip + len(input)
    ip_bound = ip_limit - 2
    ctrl = input[0] & 0x1F
    bound_checked = input[:len(input) - 2]
    ip += 1
    op = MemoryFile()
    while True:
        if ctrl >= 0x20:
            length = (ctrl >> 5)
            offset = (ctrl & 31) << 8
            ref = offset + 1
            if length == 7:
                while True:
                    ip, inc = ip + 1, bound_checked[ip]
                    length += inc
                    if level == 0 or inc != 0xFF:
                        break
            ip, inc = ip + 1, input[ip]
            ref += inc
            length += 2
            if level > 0 and inc == 0xFF and offset == 0x1F00:
                ip, offset = ip + 2, (bound_checked[ip] << 8) + input[ip + 1]
                ref = offset + _MAX_L2_DISTANCE + 1
            op.replay(ref, length)
        else:
            if len(t := input[ip:(ip := ip + (ctrl := ctrl + 1))]) != ctrl:
                raise InputOutOfBounds
            op.write(t)
        if ip > ip_bound:
            break
        ctrl = input[ip]
        ip += 1
    return op.getvalue()


class flz(Unit):
    """
    FastLZ (or FLZ for short) compression and decompression. This implementation was ported to
    pure Python from the C reference and is therefore much slower.
    """
    def __init__(
        self,
        level: Param[int, Arg.Number('-l', bound=(1, 2), help=(
            'Specify a FastLZ level (either 0 or 1). By default, compression will select a level '
            'based on buffer length like the reference implementation. Decompression reads level '
            'information from the header by default.'))] = 0
    ):
        super().__init__(level=level)

    def reverse(self, data):
        if not data:
            return data
        if (level := self.args.level) <= 0:
            level = 1 + int(len(data) >= 0x10000)
        output = bytearray()
        _flz_compress(memoryview(data), output, level - 1)
        return output

    def process(self, data):
        try:
            hl = 1 + (data[0] >> 5)
        except IndexError:
            return None
        if (level := self.args.level) == 0:
            level = hl
        if level != hl:
            self.log_info(F'Using level {level} despite header-defined level {hl}.')
        return _flz_decompress(memoryview(data), level - 1)

    @classmethod
    def handles(cls, data):
        if data and (data[0] >> 5) > 1:
            return False
