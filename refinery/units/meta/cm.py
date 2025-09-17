from __future__ import annotations

from refinery.lib.meta import LazyMetaOracle, metavars
from refinery.lib.types import Param
from refinery.units import Arg, Unit

_COMMON_PROPERTIES_LIST = ', '.join(LazyMetaOracle.derivations)


class cm(Unit):
    """
    The Common Meta variables unit populates the set of meta variables of the current chunk with commonly
    used metadata. The unit has no effect outside a frame.
    """
    def __init__(
        self,
        invert: Param[bool, Arg.Switch('-x', group='ALL', help='populate only options that have not been specified')] = False,
        all: Param[bool, Arg.Switch('-a', group='ALL', help='populate all options')] = False,
        reset: Param[bool, Arg.Switch('-r', help='discard all meta variables that were not explicitly specified')] = False,
        size: Param[bool, Arg.Switch('-S', help='size of the chunk')] = False,
        ext: Param[bool, Arg.Switch('-X', help='guess file extension')] = False,
        entropy: Param[bool, Arg.Switch('-E', help='compute data entropy')] = False,
        ic: Param[bool, Arg.Switch('-C', help='compute the index of coincidence')] = False,
        magic: Param[bool, Arg.Switch('-M', help='compute file magic')] = False,
        sha1: Param[bool, Arg.Switch('-1', help='compute hash: SHA-1')] = False,
        sha256: Param[bool, Arg.Switch('-2', help='compute hash: SHA-256')] = False,
        crc32: Param[bool, Arg.Switch('-3', help='compute hash: CRC32')] = False,
        md5: Param[bool, Arg.Switch('-5', help='compute hash: MD5')] = False,
        hashes: Param[bool, Arg.Switch('-H', help='compute all common hashes')] = False,
        *names: Param[str, Arg.String(metavar='name', help=(
            F'A variable name that can include the common properties: {_COMMON_PROPERTIES_LIST}.'
            R' If none is given, the size variable is populated. For most of these, an optional '
            R'argument is available that can be used as a shorthand:'))]
    ):
        def stringify(name):
            if isinstance(name, (bytes, bytearray)):
                return name.decode(self.codec)
            if isinstance(name, str):
                return name
            raise TypeError(F'Invalid type for name: {name!r}')

        _names = {
            stringify(name) for name in names}
        if hashes:
            md5 = sha256 = sha1 = crc32 = True
        if size:
            _names.add('size')
        if ext:
            _names.add('ext')
        if entropy:
            _names.add('entropy')
        if ic:
            _names.add('ic')
        if magic:
            _names.add('magic')
        if sha1:
            _names.add('sha1')
        if sha256:
            _names.add('sha256')
        if crc32:
            _names.add('crc32')
        if md5:
            _names.add('md5')
        if not _names and not reset:
            _names.add('size')
        if all:
            if invert:
                raise ValueError('invert and all are both enabled, resulting in empty configuration.')
            _names = set(LazyMetaOracle.derivations)
        elif invert:
            _names = set(LazyMetaOracle.derivations) - _names
        super().__init__(names=list(_names), reset=reset)

    def process(self, data):
        return data

    def filter(self, chunks):
        names = self.args.names
        reset = self.args.reset
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            meta = metavars(chunk)
            if reset:
                chunk.meta.clear()
            for name in names:
                chunk[name] = meta[name]
            yield chunk
