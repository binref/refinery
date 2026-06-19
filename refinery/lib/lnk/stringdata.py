from __future__ import annotations

import codecs

from dataclasses import dataclass

from refinery.lib.lnk.flags import LinkFlags
from refinery.lib.structures import StructReader


@dataclass
class StringData:
    description: str | None = None
    relative_path: str | None = None
    working_directory: str | None = None
    command_line_arguments: str | None = None
    icon_location: str | None = None

    def __json__(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

    @classmethod
    def parse(
        cls,
        reader: StructReader[memoryview],
        flags: LinkFlags,
    ) -> StringData:
        result = cls()
        is_unicode = flags.IsUnicode
        entries = (
            (LinkFlags.HasName, 'description'),
            (LinkFlags.HasRelativePath, 'relative_path'),
            (LinkFlags.HasWorkingDir, 'working_directory'),
            (LinkFlags.HasArguments, 'command_line_arguments'),
            (LinkFlags.HasIconLocation, 'icon_location'),
        )
        for flag, attr in entries:
            if not flags & flag:
                continue
            if reader.remaining_bytes < 2:
                break
            count = reader.u16()
            raw = reader.read(count * 2 if is_unicode else count)
            encoding = 'utf-16-le' if is_unicode else 'cp1252'
            try:
                value = codecs.decode(raw, encoding)
            except Exception:
                value = bytes(raw).hex()
            setattr(result, attr, value)
        return result
