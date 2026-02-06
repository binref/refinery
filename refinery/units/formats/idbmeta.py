from __future__ import annotations

import logging

from datetime import datetime, timezone

from refinery.lib.structures import Struct, StructReader
from refinery.units.formats import JSONTableUnit


def _decrypt_user_data(data: bytes):
    encrypted = int.from_bytes(data[:128], 'little', signed=False)
    modulus = int(
        '93AF7A8E3A6EB93D1B4D1FB7EC29299D2BC8F3CE5F84BFE88E47DDBDD5550C3C'
        'E3D2B16A2E2FBD0FBD919E8038BB05752EC92DD1498CB283AA087A93184F1DD9'
        'DD5D5DF7857322DFCD70890F814B58448071BBABB0FC8A7868B62EB29CC2664C'
        '8FE61DFBC5DB0EE8BF6ECF0B65250514576C4384582211896E5478F95C42FDED', 16)
    user = pow(encrypted, 0x13, modulus)
    user = user.to_bytes(128, 'big')
    return user[1:]


class IdbUserData(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        if reader.remaining_bytes != 0x7F:
            raise ValueError('Invalid user data.')
        reader.skip(2)
        self.version = v = reader.u16()
        self.ts0 = ts0 = reader.u32()
        if v == 0:
            if ts0 == 0x10_000:
                raise NotImplementedError
            self.ts0 = ts0
            self.ts1 = None
            self.ts2 = None
            self.uid = None
            reader.seekset(0x27)
        elif v > 750:
            raise NotImplementedError
        else:
            reader.seekset(0x10)
            self.ts1 = datetime.fromtimestamp(reader.u32(), timezone.utc)
            reader.skip(4)
            self.ts2 = datetime.fromtimestamp(reader.u32(), timezone.utc)
            self.uid = '%02X-%02X%02X-%02X%02X-%02X' % tuple(reader.read_exactly(6))
        self.name = reader.read_c_string('utf8')


class idb(JSONTableUnit):
    """
    Extract metadata from IDA Database files. The unit only works up to Version 7.5 of IDA.
    """
    @classmethod
    def handles(cls, data):
        return data[:4] in (B'IDA2', B'IDA1')

    @JSONTableUnit.Requires('python-idb<=0.8.0', 'all')
    def _idb():
        import idb
        import idb.analysis
        for module in ('idb', 'idb.analysis', 'idb.fileformat'):
            logging.getLogger(module).disabled = True
        return idb

    def json(self, data):
        def is_encrypted(b: bytes):
            return b.find(b'\0\0\0\0') >= 0x7F

        result = {}

        idb = self._idb.from_buffer(data)
        api = self._idb.IDAPython(idb)
        for tag in (
            '$ original user',
            '$ user1',
        ):
            try:
                node = api.ida_netnode.netnode(tag)
                if not node:
                    continue
                data = node.supval(0x0)
                if is_encrypted(data):
                    data = _decrypt_user_data(data)
                else:
                    data = data[:0x7F]
                info = IdbUserData.Parse(data)
            except Exception:
                self.log_info(F'failed to parse: {tag}')
                continue
            result.update(name=info.name, version=info.version)
            if info.version != 0:
                result.update(ts1=info.ts1, ts2=info.ts2)

        root = self._idb.analysis.Root(idb)

        for key, field in {
            'imagebase'       : None,
            'open_count'      : None,
            'created'         : None,
            'md5'             : None,
            'sha256'          : None,
            'crc'             : 'crc32',
            'version_string'  : 'version',
            'input_file_path' : 'path',
        }.items():
            try:
                value = getattr(root, key)
            except (AttributeError, KeyError):
                continue
            if value:
                result[field or key] = value

        return result
