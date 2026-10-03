"""
The emulated state the system commands of the macro language touch: the files `FOPEN` opens and
`FWRITE` appends to, and the memory regions the Kernel32 pseudo-commands reserve and write.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_PAGE = 4096


@dataclass
class XlmFile:
    """
    One file the program opened: the access it was opened with and the content the program
    has written into it.
    """

    access: str
    content: str = ''


@dataclass
class XlmRegion:
    """
    One region of the memory of the emulated process, as a flat byte array an address names a
    cell of.
    """

    base: int
    size: int
    data: bytearray = field(init=False)

    def __post_init__(self):
        self.data = bytearray(self.size)


class XlmFiles:
    """
    The files a program opens: the name each was opened under, the access it was opened with,
    and the content the program has written into it. A file the program never opened refuses
    every write, the way a handle that does not exist refuses one.
    """

    def __init__(self):
        self._files: dict[str, XlmFile] = {}

    def opened(self, name: str) -> bool:
        """
        Whether the name answers a file the program opened.
        """
        return name in self._files

    def open(self, name: str, access: str = '1') -> None:
        """
        Open the name, or leave the file that already answers it alone.
        """
        self._files.setdefault(name, XlmFile(access))

    def close(self, name: str) -> None:
        """
        Remove a file the program opened, as the undo of an open performs.
        """
        self._files.pop(name, None)

    def first(self) -> str:
        """
        The name of the first file the program opened, for a write that names none: the name of
        the only file a program that opened one means, and a placeholder when it opened none.
        """
        for name in self._files:
            return name
        return 'default_filename'

    def size(self, name: str) -> int | None:
        """
        The length of the content of a file, or `None` for a name the program never opened.
        """
        file = self._files.get(name)
        if file is None:
            return None
        return len(file.content)

    def write(self, name: str, text: str) -> bool:
        """
        Append to a file the program opened, reporting whether it took the write.
        """
        file = self._files.get(name)
        if file is None:
            return False
        file.content += text
        return True

    def truncate(self, name: str, length: int) -> None:
        """
        Cut the content of a file back to the length it had, as the undo of a write performs.
        """
        file = self._files.get(name)
        if file is not None:
            file.content = file.content[:length]


class XlmMemory:
    """
    The memory of the emulated process: the regions `Kernel32.VirtualAlloc` reserves, as flat
    byte arrays an address names a cell of.
    """

    def __init__(self):
        self._regions: list[XlmRegion] = []

    def allocate(self, base: int, size: int) -> int:
        """
        Reserve a region at an address, and answer the address it starts at: an address that
        falls inside a reserved region moves the reservation past the end of every reserved
        region, one page above the highest end.
        """
        for region in self._regions:
            if region.base <= base <= region.base + region.size:
                base = max(
                    region.base + region.size
                    for region in self._regions
                ) + _PAGE
                break
        self._regions.append(XlmRegion(base, size))
        return base

    def release(self) -> None:
        """
        Drop the region the latest allocation reserved, as the undo of an allocation performs.
        """
        if self._regions:
            self._regions.pop()

    def write(self, base: int, data: bytes | bytearray, size: int) -> bool:
        """
        Write bytes at an address, reporting whether the whole write fits inside one reserved
        region; a write that straddles a region boundary does not happen at all.
        """
        for region in self._regions:
            if not region.base <= base <= region.base + region.size:
                continue
            if not region.base <= base + size <= region.base + region.size:
                return False
            offset = base - region.base
            region.data[offset:offset + size] = data[:size]
            return True
        return False

    def peek(self, base: int, size: int) -> bytes | None:
        """
        The bytes a region holds at an address, or `None` when the slice does not fit inside
        one reserved region.
        """
        for region in self._regions:
            if not region.base <= base <= region.base + region.size:
                continue
            if not region.base <= base + size <= region.base + region.size:
                return None
            offset = base - region.base
            return bytes(region.data[offset:offset + size])
        return None

    def restore(self, base: int, data: bytes) -> None:
        """
        Write earlier content back at an address, as the undo of a write performs.
        """
        for region in self._regions:
            if region.base <= base <= region.base + region.size:
                offset = base - region.base
                region.data[offset:offset + len(data)] = data
                return
