#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.meta import metavars, COMMON_PROPERTIES
from ...lib.frame import Chunk


_COMMON_PROPERTIES_LIST = ', '.join(COMMON_PROPERTIES)


class cm(Unit):
    """
    The Common Meta variables unit populates the set of meta variables of the current chunk with commonly
    used metadata. The unit has no effect outside a frame.
    """
    def __init__(
        self,
        invert  : arg.switch('-x', group='ALL', help='populate only options that have not been specified') = False,
        all     : arg.switch('-a', group='ALL', help='populate all options') = False,
        reset   : arg.switch('-r', help='discard all meta variables that were not explicitly specified') = False,
        size    : arg.switch('-S', help='size of the chunk') = False,
        index   : arg.switch('-I', help='index of the chunk in the current frame') = False,
        ext     : arg.switch('-F', help='guess file extension') = False,
        entropy : arg.switch('-E', help='compute data entropy') = False,
        ic      : arg.switch('-C', help='compute the index of coincidence') = False,
        magic   : arg.switch('-M', help='compute file magic') = False,
        sha1    : arg.switch('-1', help='compute hash: SHA-1') = False,
        sha256  : arg.switch('-2', help='compute hash: SHA-256') = False,
        crc32   : arg.switch('-3', help='compute hash: CRC32') = False,
        md5     : arg.switch('-5', help='compute hash: MD5') = False,
        hashes  : arg.switch('-H', help='compute all common hashes') = False,
        *names  : arg(metavar='name', help=(
            F'A variable name that can include the common properties: {_COMMON_PROPERTIES_LIST}.'
            R' If none is given, the variables index and size are populated. For most of these,'
            R' an optional argument is available that can be used as a shorthand:'))
    ):
        def stringify(name):
            if isinstance(name, str):
                return name
            return name.decode(self.codec)

        names = {stringify(name) for name in names}
        if hashes:
            md5 = sha256 = sha1 = crc32 = True
        if size:
            names.add('size')
        if index:
            names.add('index')
        if ext:
            names.add('ext')
        if entropy:
            names.add('entropy')
        if ic:
            names.add('ic')
        if magic:
            names.add('magic')
        if sha1:
            names.add('sha1')
        if sha256:
            names.add('sha256')
        if crc32:
            names.add('crc32')
        if md5:
            names.add('md5')
        if not names and not reset:
            names.update(('index', 'size'))
        if all:
            if invert:
                raise ValueError('invert and all are both enabled, resulting in empty configuration.')
            names = set(COMMON_PROPERTIES)
        elif invert:
            names = set(COMMON_PROPERTIES) - names
        super().__init__(names=names, reset=reset)

    def process(self, data):
        return data

    def filter(self, chunks):
        names = self.args.names
        reset = self.args.reset
        for index, chunk in enumerate(chunks):
            chunk: Chunk
            if not chunk.visible:
                continue
            meta = metavars(chunk)
            if reset:
                chunk.meta.clear()
            if 'index' in names:
                meta['index'] = index
            for name in names:
                chunk[name] = meta[name]
            yield chunk
