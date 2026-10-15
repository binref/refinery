from __future__ import annotations

from refinery.lib.ole.file import OleFile


def ole_entry_offset(document: bytes | bytearray, path: str) -> int:
    """
    The offset of the directory entry at the given path in the given compound file. The entry is
    found by its name, its start sector and its size, at a position where a directory entry can be.
    """
    entry = OleFile(bytes(document)).find(path)
    if entry is None:
        raise LookupError(path)
    name = F'{entry.name}\0'.encode('utf-16le')
    offsets = []
    position = document.find(name)
    while position >= 0:
        if (
            position % 128 == 0
            and int.from_bytes(document[position + 0x40:position + 0x42], 'little') == len(name)
            and int.from_bytes(document[position + 0x74:position + 0x78], 'little') == entry.start
            and int.from_bytes(document[position + 0x78:position + 0x7C], 'little') == entry.size
        ):
            offsets.append(position)
        position = document.find(name, position + 1)
    [offset] = offsets
    return offset


def rename_ole_entry(document: bytes | bytearray, path: str, name: str) -> bytearray:
    """
    Writes a new name into the directory entry at the given path of the given compound file.
    """
    offset = ole_entry_offset(document, path)
    encoded = F'{name}\0'.encode('utf-16le')
    renamed = bytearray(document)
    renamed[offset:offset + 0x40] = encoded.ljust(0x40, B'\0')
    renamed[offset + 0x40:offset + 0x42] = len(encoded).to_bytes(2, 'little')
    return renamed


def link_ole_child(document: bytes | bytearray, path: str, sid: int) -> bytearray:
    """
    Points the child link of the storage at the given path of the given compound file at the
    directory entry with the given number.
    """
    offset = ole_entry_offset(document, path)
    linked = bytearray(document)
    linked[offset + 0x4C:offset + 0x50] = sid.to_bytes(4, 'little')
    return linked
