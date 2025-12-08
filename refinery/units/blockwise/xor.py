from __future__ import annotations

from itertools import islice

from refinery.units.blockwise import BinaryOperationWithAutoBlockAdjustment, FastBlockError


class xor(BinaryOperationWithAutoBlockAdjustment):
    """
    Form the exclusive or of the input data with the given argument.
    """
    @staticmethod
    def operate(a, b):
        return a ^ b

    @staticmethod
    def inplace(a, b):
        a ^= b

    def _fastblock_fallback(self, data):
        from Cryptodome.Util import strxor
        size = len(data)
        it, masked = self._argument_parse_hook(self.args.argument[0])
        arg0 = self._infinitize_argument(len(data), it, masked)
        take = len(data) // self.blocksize + 1
        argb = self.unchunk(islice(arg0, take))
        del argb[size:]
        return strxor.strxor(data, argb)

    def _fastblock(self, data):
        try:
            return super()._fastblock(data)
        except FastBlockError as E:
            try:
                return self._fastblock_fallback(data)
            except Exception:
                raise E
