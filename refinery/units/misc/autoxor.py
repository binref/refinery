from __future__ import annotations

from refinery.lib.id import get_structured_data_type
from refinery.units.blockwise.sub import sub
from refinery.units.blockwise.xor import xor
from refinery.units.misc.xkey import xkey


class autoxor(xkey, docs='{0}{p}{1}'):
    """
    Assumes input that was encrypted with a polyalphabetic block cipher, like XOR-ing each byte
    with successive bytes from a key or by subtracting the respective key byte value from each
    input byte. It uses the `refinery.xkey` unit to attack the cipher and attempts to recover the
    plaintext automatically.
    """
    def process(self, data: bytearray):
        fallback: tuple[str, bytes, bytearray] | None = None

        try:
            result = next(self._attack(data))
        except StopIteration:
            result = None
        else:
            key = result.key
            units: list[type[xor] | type[sub]] = []

            if result.xor is not False:
                units.append(xor)
            if result.xor is not True:
                units.append(sub)

            for unit in units:

                name = unit.name
                bin = data | unit(key) | bytearray
                space = B'\0' | unit(0x20) | bytes

                if t := get_structured_data_type(bin):
                    self.log_info(F'method {name} resulted in non-blob data ({t.mnemonic}); returning buffer')
                    return self.labelled(bin, key=key, method=name)

                if not fallback:
                    fallback = name, key, bin

                if not any(bin):
                    continue

                as_text = bin | unit(space) | bytearray

                try:
                    decoded = as_text.decode('utf8')
                except UnicodeDecodeError:
                    is_text = False
                else:
                    import re
                    is_text = bool(re.fullmatch(r'[\s\w!-~]+', decoded))

                if is_text:
                    self.log_info('detected likely text input; automatically shifting towards space character')
                    key = (b'\x20' * len(key)) | unit(key) | bytes
                    return self.labelled(as_text, key=key, method=name)

        if fallback is None:
            self.log_warn('No key was found; returning original data.')
            return data
        else:
            assert result is not None
            name, key, bin = fallback
            if result.how == self._rt.freq and result.score < 8:
                self.log_warn(
                    F'unrecognized format, no confirmed crib, low score ({result.score:.2f}%); '
                    'the output is likely junk'
                )
            return self.labelled(bin, key=key)
