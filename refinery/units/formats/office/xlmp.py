from __future__ import annotations

from refinery.units.formats.office.xlm import xlm


class xlmp(xlm):
    """
    Deobfuscates Excel v4.0 (XLM) macros from XLS, XLSM, and XLSB documents.

    The output is a pretty-printed trace of the output of the `refinery.xlm` unit, which can be
    used for more granular access.
    """
    def process(self, data: bytearray):
        for chunk in super().process(data):
            cell = chunk['cell']
            pad = ' ' * 2 * chunk.meta_var_int('depth')
            severity = chunk.meta_var_int('severity')
            severity = {1: ' ', 2: '*'}.get(severity, '!')
            value = chunk.decode(self.codec)
            chunk.meta.clear()
            chunk[:] = F'{cell:>10} {severity}  {pad}{value}'.encode(self.codec)
            yield chunk
