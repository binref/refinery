"""
This is a port of the Quantum decompression implementation in 7Zip to Python.
"""
from __future__ import annotations

_UPDATE_STEP = 8
_FREQ_SUM_MAX = 3800
_REORDER_COUNT_START = 4
_REORDER_COUNT = 50

_NUM_LIT_SELECTOR_BITS = 2
_NUM_LIT_SELECTORS = 1 << _NUM_LIT_SELECTOR_BITS
_NUM_LIT_SYMBOLS = 1 << (8 - _NUM_LIT_SELECTOR_BITS)
_NUM_MATCH_SELECTORS = 3
_NUM_SELECTORS = _NUM_LIT_SELECTORS + _NUM_MATCH_SELECTORS

_NUM_LEN_SYMBOLS = 27
_MATCH_MIN_LEN = 3
_NUM_SIMPLE_LEN_SLOTS = 6

_NUM_LEN_BOUND = _NUM_SIMPLE_LEN_SLOTS + _MATCH_MIN_LEN + _NUM_MATCH_SELECTORS - 1
_M32 = 0xFFFFFFFF


class _BitStream:
    __slots__ = '_data', '_pos', '_end', '_bits', '_nbits'

    def __init__(self, data: memoryview):
        self._data = data
        self._pos = 0
        self._end = len(data)
        self._bits = 0
        self._nbits = 0

    def read(self, count: int) -> int:
        while self._nbits < count:
            byte = self._data[self._pos] if self._pos < self._end else 0
            self._bits = (self._bits << 8) | byte
            self._pos += 1
            self._nbits += 8
        self._nbits -= count
        result = (self._bits >> self._nbits) & ((1 << count) - 1)
        self._bits &= (1 << self._nbits) - 1
        return result

    @property
    def overread(self) -> bool:
        return self._pos > self._end


class _RangeDecoder:
    __slots__ = '_stream', '_low', '_range', '_code'

    def __init__(self, stream: _BitStream):
        self._stream = stream
        self._low: int = 0
        self._range: int = 0x10000
        self._code: int = stream.read(16)

    def get_threshold(self, total: int) -> int:
        return ((self._code + 1) * total - 1) // self._range

    def decode(self, start: int, end: int, total: int):
        hi = (0 - (self._low + end * self._range // total)) & _M32
        offset = start * self._range // total
        lo = (self._low + offset) & _M32
        code = (self._code - offset) & _M32
        num_bits = 0
        lo ^= hi
        while lo & (1 << 15):
            lo = (lo << 1) & _M32
            hi = (hi << 1) & _M32
            num_bits += 1
        lo ^= hi
        an = lo & hi
        while an & (1 << 14):
            an = (an << 1) & _M32
            lo = (lo << 1) & _M32
            hi = (hi << 1) & _M32
            num_bits += 1
        self._low = lo
        self._range = ((~hi - lo) & 0xFFFF) + 1
        if num_bits:
            code = ((code << num_bits) + self._stream.read(num_bits)) & _M32
        self._code = code

    def read_bits(self, count: int) -> int:
        return self._stream.read(count)


class _Model:
    __slots__ = '_count', '_reorder_count', '_vals', '_freqs'

    def __init__(self, num_items: int, start_val: int):
        self._count = num_items
        self._reorder_count = _REORDER_COUNT_START
        self._vals = list(range(start_val, start_val + num_items))
        self._freqs = [num_items - i for i in range(num_items)] + [0]

    def _rescale_reorder(self):
        self._reorder_count = _REORDER_COUNT
        freqs = self._freqs
        vals = self._vals
        n = self._count
        nxt = 0
        for i in range(n - 1, -1, -1):
            cum = freqs[i]
            freqs[i] = (cum - nxt + 1) >> 1
            nxt = cum
        for i in range(n - 1):
            for k in range(i + 1, n):
                if freqs[i] < freqs[k]:
                    freqs[i], freqs[k] = freqs[k], freqs[i]
                    vals[i], vals[k] = vals[k], vals[i]
        cum = 0
        for i in range(n - 1, -1, -1):
            cum += freqs[i]
            freqs[i] = cum

    def _rescale_simple(self):
        freqs = self._freqs
        n = self._count
        nxt = 1
        for i in range(n - 1, -1, -1):
            freq = freqs[i] >> 1
            if freq < nxt:
                freq = nxt
            freqs[i] = freq
            nxt = freq + 1

    def decode(self, rc: _RangeDecoder) -> int:
        freqs = self._freqs
        if freqs[0] > _FREQ_SUM_MAX:
            self._reorder_count -= 1
            if self._reorder_count == 0:
                self._rescale_reorder()
            else:
                self._rescale_simple()
        total = freqs[0]
        freqs[0] = total + _UPDATE_STEP
        threshold = rc.get_threshold(total)
        k = 1
        while freqs[k] > threshold:
            freqs[k] += _UPDATE_STEP
            k += 1
        k -= 1
        result = self._vals[k]
        start = freqs[k + 1]
        end = freqs[k] - _UPDATE_STEP
        rc.decode(start, end, total)
        return result


class QuantumDecoder:
    """
    A stateful Quantum decompressor for use with CAB archives. The decoder maintains a sliding
    window and adaptive models across consecutive blocks within a folder.
    """
    __slots__ = (
        '_num_dict_bits',
        '_window_size',
        '_window',
        '_window_pos',
        '_over_window',
        '_selector',
        '_literals',
        '_pos_slot',
        '_len_slot',
    )

    _selector: _Model
    _len_slot: _Model
    _literals: list[_Model]
    _pos_slot: list[_Model]

    def __init__(self, num_dict_bits: int):
        if num_dict_bits > 21:
            raise ValueError(F'Invalid Quantum window bits: {num_dict_bits}')
        self._num_dict_bits = num_dict_bits
        win_bits = max(num_dict_bits, 15)
        self._window_size = 1 << win_bits
        self._window = bytearray(self._window_size)
        self._window_pos = 0
        self._over_window = False

    def _init_models(self):
        ndb = self._num_dict_bits
        num_pos_items = 1 if ndb == 0 else ndb << 1
        self._selector = _Model(_NUM_SELECTORS, 0)
        self._literals = [_Model(_NUM_LIT_SYMBOLS, i * _NUM_LIT_SYMBOLS) for i in range(_NUM_LIT_SELECTORS)]
        self._pos_slot = []
        for i in range(_NUM_MATCH_SELECTORS):
            num = 24 + i * 6 + ((i + 1) & 2) * 3
            self._pos_slot.append(_Model(min(num_pos_items, num), 0))
        self._len_slot = _Model(_NUM_LEN_SYMBOLS, _MATCH_MIN_LEN + _NUM_MATCH_SELECTORS - 1)

    def decompress(
        self,
        data: bytes | bytearray | memoryview,
        output_size: int,
        keep_history: bool = False,
    ) -> memoryview:
        view = memoryview(data)
        if len(view) < 2:
            raise ValueError('Quantum compressed block too short.')
        if not keep_history:
            self._window_pos = 0
            self._over_window = False
            self._init_models()
        stream = _BitStream(view)
        rc = _RangeDecoder(stream)
        win = self._window
        win_size = self._window_size
        win_pos = self._window_pos
        if win_pos == win_size:
            win_pos = 0
            self._window_pos = 0
            self._over_window = True
        if output_size > win_size - win_pos:
            raise ValueError('Quantum output would exceed window size.')
        out_start = win_pos
        remaining = output_size
        try:
            selector_model = self._selector
            literal_models = self._literals
            pos_model = self._pos_slot
            len_model = self._len_slot
        except AttributeError as AE:
            raise RuntimeError('Quantum decompressor was not initialized.') from AE
        while remaining > 0:
            selector = selector_model.decode(rc)
            if selector < _NUM_LIT_SELECTORS:
                win[win_pos] = literal_models[selector].decode(rc)
                win_pos += 1
                remaining -= 1
            else:
                match_idx = selector - _NUM_LIT_SELECTORS
                length = match_idx + _MATCH_MIN_LEN
                if match_idx == _NUM_MATCH_SELECTORS - 1:
                    length = len_model.decode(rc)
                    bound = _NUM_LEN_BOUND
                    if length >= bound:
                        length -= _NUM_LEN_BOUND - 4
                        num_direct = length >> 2
                        length = ((4 | (length & 3)) << num_direct) - 8 + _NUM_LEN_BOUND
                        if num_direct < 6:
                            length += rc.read_bits(num_direct)
                dist = pos_model[match_idx].decode(rc)
                if dist >= 4:
                    num_direct = (dist >> 1) - 1
                    dist = ((2 | (dist & 1)) << num_direct) + rc.read_bits(num_direct)
                if remaining < length:
                    raise ValueError('Quantum match length exceeds remaining output.')
                remaining -= length
                src = win_pos - dist - 1
                if src < 0:
                    if not self._over_window:
                        raise ValueError('Quantum match offset before start of data.')
                    wrap = -src
                    src += win_size
                    if wrap < length:
                        for _ in range(wrap):
                            win[win_pos] = win[src]
                            win_pos += 1
                            src += 1
                        length -= wrap
                        src = 0
                for _ in range(length):
                    win[win_pos] = win[src]
                    win_pos += 1
                    src += 1
        self._window_pos = win_pos
        view = memoryview(win)
        return view[out_start:win_pos]
