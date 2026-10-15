import struct

from ... import TestUnitBase


class TestMinidumpExtractor(TestUnitBase):
    """
    The test sample is a minidump of the smallest type (thread stacks and module list, no module
    code) of `ping.exe`, written by the dump function of Windows; it lists 12 modules.
    """

    _SAMPLE = '50c8674de050dd4bd9667b64dbe4136b09aebd4a54a74e7574cb3e0c3e590de3'
    _SYSTEM = 'module/C/Windows/System32'

    def test_every_module_and_memory_region_is_listed(self):
        data = self.download_sample(self._SAMPLE)
        paths = [str(path) for path in data | self.load(list=True)]
        modules = [path for path in paths if path.startswith('module/')]
        self.assertEqual(len(modules), 12)
        self.assertIn(F'{self._SYSTEM}/PING.EXE', modules)
        self.assertIn(F'{self._SYSTEM}/ntdll.dll', modules)
        self.assertEqual(len([path for path in paths if path.startswith('memory/')]), 20)

    def test_two_modules_with_the_same_name_are_both_listed(self):
        data = bytearray(self.download_sample(self._SAMPLE))
        # the stream directory lists type, size and position of each stream; type 4 is the module list
        count, directory = struct.unpack_from('<II', data, 8)
        [modules] = [
            struct.unpack_from('<I', data, directory + 12 * k + 8)[0]
            for k in range(count) if struct.unpack_from('<I', data, directory + 12 * k)[0] == 4
        ]
        # every module entry is 108 bytes long and holds the position of its name at offset 20
        names = {}
        for k in range(struct.unpack_from('<I', data, modules)[0]):
            entry = modules + 4 + 108 * k
            position = struct.unpack_from('<I', data, entry + 20)[0]
            size = struct.unpack_from('<I', data, position)[0]
            name = data[position + 4:position + 4 + size].decode('utf-16le').rpartition('\\')[2]
            names[name] = entry, position
        struct.pack_into('<I', data, names['KERNELBASE.dll'][0] + 20, names['ntdll.dll'][1])
        modules = [str(path) for path in data | self.load('module/*', list=True)]
        self.assertEqual(len(modules), 12)
        self.assertIn(F'{self._SYSTEM}/ntdll.dll/1', modules)
        self.assertIn(F'{self._SYSTEM}/ntdll.dll/2', modules)
        self.assertNotIn(F'{self._SYSTEM}/KERNELBASE.dll', modules)
