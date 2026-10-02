import plistlib
import struct

import pytest

from refinery.lib.dmg.arc import DiskImage

from test import TestBase


def with_chunk_type(dmg: bytes | bytearray, table: int, chunk: int, chunk_type: int) -> bytes:
    """
    Change the type of a chunk in a blkx table of a DMG whose koly header is at its end. The changed
    property list replaces the old one, and the koly header records its new length.
    """
    koly = dmg[-512:]
    xml_offset, xml_length = struct.unpack('>QQ', koly[216:232])
    plist = plistlib.loads(dmg[xml_offset:xml_offset + xml_length])
    entry = plist['resource-fork']['blkx'][table]
    mish = bytearray(entry['Data'])
    record = 204 + 40 * chunk
    mish[record:record + 4] = chunk_type.to_bytes(4, 'big')
    entry['Data'] = bytes(mish)
    xml = plistlib.dumps(plist)
    return bytes(dmg[:xml_offset]) + xml + koly[:224] + len(xml).to_bytes(8, 'big') + koly[232:]


@pytest.mark.cythonized
class TestDiskImage(TestBase):

    def test_chunk_that_decodes_to_less_than_its_sectors_is_padded_with_zeros(self):
        dmg = self.download_sample('06a764a6895f72f34fcddbb5002f63ed94241c67f2c3c6dd732583bc31bb83d3')
        # The fourth chunk of the HFS+ partition is a one-sector LZFSE chunk of 137 bytes, and one
        # more chunk follows it. As a raw chunk, it holds only those 137 bytes.
        dmg = with_chunk_type(dmg, 4, 3, 1)
        partition = list(DiskImage(bytearray(dmg)).partitions())[4]
        self.assertIn('Apple_HFS', partition.name)
        self.assertEqual(len(partition.data), 16304 * 512)
        self.assertEqual(partition.data[16302 * 512 + 137:], bytes(512 - 137 + 512))
        self.assertEqual(len(partition.warnings), 1)
