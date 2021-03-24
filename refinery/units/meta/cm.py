#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import zlib

from .. import arg, Unit

from ...lib.mime import FileMagicInfo, NoMagicAvailable
from ...lib.tools import entropy


class cm(Unit):
    """
    The Common Meta variables unit populates the set of meta variables of the current chunk with commonly
    used metadata. The unit has no effect outside a frame. If no option is given, the unit populates all
    available variables.
    """
    def __init__(
        self,
        invert  : arg.switch('-x', help='populate only options that have not been specified') = False,
        size    : arg.switch('-S', help='size of the chunk') = False,
        index   : arg.switch('-I', help='index of the chunk in the current frame') = False,
        mime    : arg.switch('-M', help='add MIME type and guessed file extension') = False,
        entropy : arg.switch('-E', help='compute data entropy') = False,
        crc32   : arg.switch('-3', help='compute hash: CRC32') = False,
        sha1    : arg.switch('-1', help='compute hash: SHA-1') = False,
        sha256  : arg.switch('-2', help='compute hash: SHA-256') = False,
        md5     : arg.switch('-5', help='compute hash: MD5') = False,
        hashes  : arg.switch('-H', help='compute all common hashes') = False,

    ):
        args = {
            'size'    : size,
            'index'   : index,
            'mime'   : mime,
            'entropy' : entropy,
            'crc32'   : crc32 or hashes,
            'sha1'    : sha1 or hashes,
            'sha256'  : sha256 or hashes,
            'md5'     : md5 or hashes,
        }
        if not any(args.values()):
            if invert:
                raise ValueError('the --invert option can only be specified with another option.')
            for key in args:
                args[key] = True
        elif invert:
            for key in args:
                args[key] = not args[key]
        super().__init__(**args)

    def process(self, data):
        return data

    def filter(self, chunks):
        index = 0
        for chunk in chunks:
            if not chunk.visible:
                continue
            if self.args.size:
                chunk['size'] = len(chunk)
            if self.args.mime:
                try:
                    info = FileMagicInfo(chunk)
                except NoMagicAvailable:
                    self.log_warn('libmagic not available on this system')
                else:
                    chunk['mime'] = info.mime
                    chunk['ext'] = info.extension
            if self.args.index:
                chunk['index'] = index
                index += 1
            if self.args.entropy:
                chunk['entropy'] = entropy(chunk)
            if self.args.crc32:
                chunk['crc32'] = F'{zlib.crc32(chunk)&0xFFFFFFFF:08X}'
            if self.args.sha1:
                chunk['sha1'] = hashlib.sha1(chunk).hexdigest()
            if self.args.sha256:
                chunk['sha256'] = hashlib.sha256(chunk).hexdigest()
            if self.args.md5:
                chunk['md5'] = hashlib.md5(chunk).hexdigest()
            yield chunk
