#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from typing import NamedTuple, TYPE_CHECKING, Union

from refinery.units import arg, Unit
from refinery.lib.structures import MemoryFile

import builtins
import logging
import os
import pcapkit
import stat
import uuid

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    TIPAddr = Union[IPv4Address, IPv6Address]


class VirtualFile:
    def __init__(self, data):
        self._data = data
        self._path = str(uuid.uuid4())
        self._size = len(data)

    def __fspath__(self):
        return self._uuid

    def __enter__(self):
        def hook_open(file, *args, **kwargs):
            base = os.path.basename(file)
            if base != self._path:
                return self._open(file, *args, **kwargs)
            fd = MemoryFile(self._data, read_as_bytes=True)
            fd.name = self._path
            return fd

        def hook_stat(file):
            base = os.path.basename(file)
            if base != self._path:
                return self._stat(file)
            M = stat.S_IMODE(0xFFFF) | stat.S_IFREG
            S = self._size
            return os.stat_result((
                M,  # ST_MODE
                0,  # ST_INO
                0,  # ST_DEV
                1,  # ST_NLINK
                0,  # ST_UID
                0,  # ST_GID
                S,  # ST_SIZE
                0,  # ST_ATIME
                0,  # ST_MTIME
                0,  # ST_CTIME
            ))

        self._open = builtins.open
        self._stat = os.stat
        builtins.open = hook_open
        os.stat = hook_stat
        return self._path

    def __exit__(self, *args):
        builtins.open = self._open
        os.stat = self._stat
        return False


class Conversation(NamedTuple):
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int

    @classmethod
    def FromID(cls, stream_id):
        src, sp = stream_id.src
        dst, dp = stream_id.dst
        return cls(str(src), str(dst), sp, dp)

    @property
    def src(self):
        return F'{self.src_addr}:{self.src_port}'

    @property
    def dst(self):
        return F'{self.dst_addr}:{self.dst_port}'

    def __hash__(self):
        return hash(frozenset((self.src, self.dst)))

    def swapped(self):
        cls = self.__class__
        return cls(self.dst_addr, self.src_addr, self.dst_port, self.src_port)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __str__(self):
        return F'[{self.src}] --> [{self.dst}]'

    def src_to_dst(self):
        return {'src': self.src, 'dst': self.dst}

    def dst_to_src(self):
        return {'src': self.dst, 'dst': self.src}


class pcap(Unit):
    """
    Performs TCP stream reassembly from packet capture (PCAP) files. By default, the unit emits the parts of
    each TCP conversation, attaching several pieces of metadata to each such output: Included are the source
    and destination socket address as well as the variable `stream` which identifies the conversation which
    it was part of. The chunks are returned in the order that the bytes were exchanged between source and
    destination. When the `--merge` parameter is specified, the unit instead collects all bytes going forward
    and backwards, respectively, and emitting these as two chunks, for each TCP conversation that took place.
    """

    def __init__(self, merge: arg.switch('-m', help='Merge both parts of each TCP conversation into one chunk.') = False):
        super().__init__(merge=merge)

    def process(self, data):
        logging.getLogger('pcapkit').disabled = True
        merge = self.args.merge
        with VirtualFile(data) as vf:
            extraction = pcapkit.extract(
                fin=vf, engine='scapy', store=False, nofile=True, extension=False, tcp=True, strict=True)
            count, convo = 0, None
            src_buffer = MemoryFile()
            dst_buffer = MemoryFile()
            for stream in extraction.reassembly.tcp:
                this_convo = Conversation.FromID(stream.id)
                if this_convo != convo:
                    if count and merge:
                        if src_buffer.tell():
                            yield self.labelled(src_buffer.getvalue(), **convo.src_to_dst())
                            src_buffer.truncate(0)
                        if dst_buffer.tell():
                            yield self.labelled(dst_buffer.getvalue(), **convo.dst_to_src())
                            dst_buffer.truncate(0)
                    count = count + 1
                    convo = this_convo
                for packet in stream.packets:
                    if not merge:
                        yield self.labelled(packet.data, **this_convo.src_to_dst(), stream=count)
                    elif this_convo.src == convo.src:
                        src_buffer.write(packet.data)
                    elif this_convo.dst == convo.src:
                        dst_buffer.write(packet.data)
                    else:
                        raise RuntimeError(F'direction of packet {convo!s} in conversation {count} is unknown')
