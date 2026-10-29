from .. import TestUnitBase


class TestArguments(TestUnitBase):

    def test_binary_instrumented(self):
        add = self.ldu('add', b'\x12')
        sub = self.ldu('sub', b'\x12')
        self.assertEqual(sub(add(b'buffer')), b'buffer')

    def test_binary_commandline(self):
        add = self.ldu('add', '12')
        sub = self.ldu('sub', '12')
        self.assertEqual(sub(add(b'buffer')), b'buffer')

    def test_sequence_argument(self):
        add = self.ldu('add', '(1,2,3)')
        self.assertEqual(add(B'\0\0\0\0\0\0\0'), b'\x01\x02\x03\x01\x02\x03\x01')


class TestArithmeticUnits(TestUnitBase):

    def test_argument_overflow(self):
        for blocksize in (1, 2, 3, 4, 5, 7, 8, 11):
            buffer = self.generate_random_buffer(200 * blocksize)
            key1 = int.from_bytes(self.generate_random_buffer(blocksize), 'big')
            key2 = key1 | (0xDEFACED << (blocksize * 8))
            for unit in ('add', 'sub', 'xor'):
                op1 = self.ldu(unit, str(key1), blocksize=blocksize)
                op2 = self.ldu(unit, str(key2), blocksize=blocksize)
                self.assertEqual(op1(buffer), op2(buffer))

    def assertPathsAgree(self, name, argument, data, **keywords):
        """
        All processing paths of an arithmetic unit must reduce an argument to the block mask in the
        same way: the numpy path in `_fastblock`, the inlined loop from `iterspread`, and the
        failsafe block-by-block path. The second and third path are reached by taking numpy away;
        the failsafe path additionally requires the inlined loop to fail.
        """
        from unittest import mock

        from refinery.units.blockwise import FastBlockError

        def unavailable(self):
            raise FastBlockError

        unit = self.ldu(name, argument, **keywords)
        expected = unit(data)

        with mock.patch.object(type(unit), '_numpy', new=property(unavailable)):
            self.assertEqual(self.ldu(name, argument, **keywords)(data), expected)

        with mock.patch.object(type(unit), '_numpy', new=property(unavailable)):
            with mock.patch('refinery.units.blockwise.iterspread') as spread:
                spread.side_effect = RuntimeError
                self.assertEqual(self.ldu(name, argument, **keywords)(data), expected)

    def test_paths_agree_on_argument_reduction(self):
        data = self.generate_random_buffer(0x101)
        for argument in (
            'inc[8]:eval:0x30',
            'inc:eval:0x30',
            'inc[70]:eval:18446744073709551616',
            'range:-5:',
            'take[3:]:range:-5:',
            '300',
            'cycle:KITTY',
        ):
            for name in ('add', 'shl', 'xor'):
                for blocksize in (1, 2):
                    with self.subTest(F'{name} {argument} -B{blocksize}'):
                        self.assertPathsAgree(name, argument, data, blocksize=blocksize)
