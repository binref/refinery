from __future__ import annotations

from refinery.lib.lnk.extradata import ExtraData
from refinery.lib.lnk.flags import LinkFlags
from refinery.lib.lnk.header import ShellLinkHeader
from refinery.lib.lnk.idlist import LinkTargetIDList
from refinery.lib.lnk.linkinfo import LinkInfo
from refinery.lib.lnk.stringdata import StringData
from refinery.lib.structures import StructReader


class LnkFile:
    def __init__(self, data: bytes | bytearray | memoryview):
        reader = StructReader(memoryview(data))
        self.header = ShellLinkHeader(reader)
        flags = self.header.link_flags
        self.targets: LinkTargetIDList | None = None
        if flags & LinkFlags.HasTargetIDList:
            self.targets = LinkTargetIDList(reader)
        self.link_info: LinkInfo | None = None
        if flags & LinkFlags.HasLinkInfo:
            self.link_info = LinkInfo(reader)
        self.string_data = StringData.parse(reader, flags)
        self.extra_data = ExtraData.parse(reader)
        self._size = reader.tell()

    @property
    def size(self) -> int:
        return self._size

    def __json__(self) -> dict:
        result: dict = {}
        result['header'] = self.header.__json__()
        if self.targets is not None:
            result['target_id_list'] = self.targets.__json__()
            target_path = self.targets.path
            if target_path:
                result['target_path'] = target_path
        if self.link_info is not None:
            result['link_info'] = self.link_info.__json__()
        sd = self.string_data.__json__()
        if sd:
            result['data'] = sd
        extra = self.extra_data.__json__()
        if extra:
            result['extra_data'] = extra
        return result
