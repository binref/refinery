from __future__ import annotations

import struct

from refinery.lib.ole.file import OleFile


def ole_entry_offset(document: bytes | bytearray, path: str) -> int:
    """
    The offset of the directory entry at the given path in the given compound file. The entry is
    found by its name, its links, its start sector and its size, at a position where a directory
    entry can be.
    """
    entry = OleFile(bytes(document)).find(path)
    if entry is None:
        raise LookupError(path)
    name = F'{entry.name}\0'.encode('utf-16le')
    links = struct.pack('<III', entry.sid_left, entry.sid_right, entry.sid_child)
    offsets = []
    position = document.find(name)
    while position >= 0:
        if (
            position % 128 == 0
            and int.from_bytes(document[position + 0x40:position + 0x42], 'little') == len(name)
            and document[position + 0x44:position + 0x50] == links
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


def resize_ole_entry(document: bytes | bytearray, path: str, size: int) -> bytearray:
    """
    Writes a new stream size into the directory entry at the given path of the given compound file.
    """
    offset = ole_entry_offset(document, path)
    resized = bytearray(document)
    resized[offset + 0x78:offset + 0x7C] = size.to_bytes(4, 'little')
    return resized


def replace_in_ole_stream(document: bytes | bytearray, path: str, old: bytes, new: bytes) -> bytes:
    """
    Writes the given new bytes over the given old bytes of the stream at the given path of the
    given compound file. The new bytes have the length of the old ones, and the stream holds the
    old bytes exactly once; the bytes around them identify their place in the compound file.
    """
    if len(old) != len(new):
        raise ValueError('The new bytes must have the length of the old bytes.')
    stream = bytes(OleFile(bytes(document)).openstream(path).read())
    if stream.count(old) != 1:
        raise LookupError(F'The stream does not hold {old!r} exactly once.')
    position = stream.index(old)
    start = max(position - 8, 0)
    context = stream[start:position + len(old) + 8]
    if document.count(context) != 1:
        raise LookupError('The place of the bytes in the compound file is not unique.')
    offset = document.index(context) + position - start
    replaced = bytearray(document)
    replaced[offset:offset + len(old)] = new
    return bytes(replaced)


def link_ole_child(document: bytes | bytearray, path: str, sid: int) -> bytearray:
    """
    Points the child link of the storage at the given path of the given compound file at the
    directory entry with the given number.
    """
    offset = ole_entry_offset(document, path)
    linked = bytearray(document)
    linked[offset + 0x4C:offset + 0x50] = sid.to_bytes(4, 'little')
    return linked
