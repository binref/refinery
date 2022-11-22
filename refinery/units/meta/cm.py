#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Arg, Unit
from refinery.lib.meta import metavars, LazyMetaOracle
from refinery.lib.frame import Chunk


_COMMON_PROPERTIES_LIST = ', '.join(LazyMetaOracle.derivations)


class cm(Unit):
    """
    The Common Meta variables unit populates the set of meta variables of the current chunk with commonly
    used metadata. The unit has no effect outside a frame.
    """
    def __init__(
        self,
        invert  : Arg.Switch('-x', group='ALL', help='populate only options that have not been specified') = False,
        all     : Arg.Switch('-a', group='ALL', help='populate all options') = False,
        reset   : Arg.Switch('-r', help='discard all meta variables that were not explicitly specified') = False,
        size    : Arg.Switch('-S', help='size of the chunk') = False,
        ext     : Arg.Switch('-F', help='guess file extension') = False,
        entropy : Arg.Switch('-E', help='compute data entropy') = False,
        ic      : Arg.Switch('-C', help='compute the index of coincidence') = False,
        magic   : Arg.Switch('-M', help='compute file magic') = False,
        sha1    : Arg.Switch('-1', help='compute hash: SHA-1') = False,
        sha256  : Arg.Switch('-2', help='compute hash: SHA-256') = False,
        crc32   : Arg.Switch('-3', help='compute hash: CRC32') = False,
        md5     : Arg.Switch('-5', help='compute hash: MD5') = False,
        hashes  : Arg.Switch('-H', help='compute all common hashes') = False,
        *names  : Arg(metavar='name', help=(
            F'A variable name that can include the common properties: {_COMMON_PROPERTIES_LIST}.'
            R' If none is given, the size variable is populated. For most of these, an optional '
            R'argument is available that can be used as a shorthand:'))
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
            names.add('size')
        if all:
            if invert:
                raise ValueError('invert and all are both enabled, resulting in empty configuration.')
            names = set(LazyMetaOracle.derivations)
        elif invert:
            names = set(LazyMetaOracle.derivations) - names
        super().__init__(names=names, reset=reset)

    def process(self, data):
        return data

    def filter(self, chunks):
        names = self.args.names
        reset = self.args.reset
        for chunk in chunks:
            chunk: Chunk
            if not chunk.visible:
                yield chunk
                continue
            meta = metavars(chunk)
            if reset:
                chunk.meta.clear()
            for name in names:
                chunk[name] = meta[name]
            yield chunk
