from __future__ import annotations

from datetime import datetime

from refinery.lib.meta import metavars
from refinery.lib.py import decompile_buffer, extract_code_from_buffer
from refinery.units.formats.archive import ArchiveUnit


class pyc(ArchiveUnit):
    """
    Decompiles Python bytecode (PYC) files back to source code. A known limitation is that it does
    not work on recent Python versions, but anything below 3.9 should work.
    """
    def unpack(self, data):
        input_path = metavars(data).get(self.args.path.decode(self.codec))
        for k, code in enumerate(extract_code_from_buffer(bytes(data), input_path)):
            if (co := code.container) is None:
                raise ValueError('could not find code in buffer')
            path = co.co_filename or F'__unknown_name_{k:02d}.py'
            date = datetime.fromtimestamp(code.timestamp)
            data = decompile_buffer(code)
            yield self._pack(path, date, data)
