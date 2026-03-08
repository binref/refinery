from __future__ import annotations

from typing import Optional

from refinery.units.formats import Unit
from refinery.units.formats.a3x import A3xRecord, A3xScript


class a3xs(Unit):
    """
    Extract only the decompiled AutoIt script from compiled AutoIt bytecode.
    """

    def process(self, data: bytearray):
        view = memoryview(data)
        cursor = 0

        while cursor >= 0:
            nc = data.find(A3xScript.MAGIC, cursor)
            if nc >= 0:
                cursor = nc
            else:
                rp = data.find(A3xRecord.MAGIC, cursor) - A3xScript.WIDTH
                if rp <= cursor:
                    break
                cursor = rp
            try:
                script = A3xScript.Parse(view[cursor:])
            except Exception:
                cursor += 1
                continue
            else:
                cursor += len(script)
            for record in script.body:
                if not record.is_script():
                    continue
                self.log_info(F'processing script of type {script.type}')
                yield from record.extract_linewise()

    @classmethod
    def handles(cls, data) -> Optional[bool]:
        return A3xScript.MAGIC in data or A3xRecord.MAGIC in data
