import contextlib
import logging
import unittest

from unittest import mock

from .. import LogRecorder, TestUnitBase
from refinery.lib.loader import load
from refinery.units.blockwise import FastBlockError


REDUCTION_ARGUMENTS = (
    'inc[8]:eval:0x30',
    'inc:eval:0x30',
    'inc[70]:eval:18446744073709551616',
    'range:-5:',
    'take[3:]:range:-5:',
    '300',
    'cycle:KITTY',
)


@contextlib.contextmanager
def logged(unit):
    """
    Collects the messages that the given unit logs while it processes data inside the context.
    Tests run with logging disabled at the critical threshold, so the level is restored for the
    duration of the context.
    """
    recorder = LogRecorder()
    logger = unit.logger
    logger.setLevel(logging.WARNING)
    logger.addHandler(recorder)
    disabled = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    try:
        yield recorder.messages
    finally:
        logging.disable(disabled)
        logger.removeHandler(recorder)
        unit.log_detach()


@contextlib.contextmanager
def logged_unit(name, *args, **kwargs):
    """
    Loads the unit of the given name and collects the messages that it logs while it processes
    data inside the context.
    """
    unit = load(name, *args, **kwargs)
    with logged(unit) as messages:
        yield unit, messages


@contextlib.contextmanager
def numpy_unavailable(unit, cryptodome=False):
    """
    Patches the class of the given unit so that its numpy dependency fails to load. Units such
    as `xor` fall back to a Cryptodome implementation in that case; setting `cryptodome` disables
    that fallback as well, leaving only the inlined loop and the failsafe method.
    """

    def unavailable(self):
        raise FastBlockError

    def no_fallback(self, data):
        raise FastBlockError

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(type(unit), '_numpy', new=property(unavailable)))
        if cryptodome and hasattr(type(unit), '_fastblock_fallback'):
            stack.enter_context(mock.patch.object(
                type(unit),
                '_fastblock_fallback',
                new=no_fallback,
            ))
        yield


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
        All processing paths of an arithmetic unit must reduce an argument to the block mask in
        the same way: the numpy path in `_fastblock`, the path the unit takes when numpy is
        unavailable (the Cryptodome fallback of `xor`), the inlined loop from `iterspread`, and
        the failsafe block-by-block path. The latter two are reached by disabling the Cryptodome
        fallback as well; the failsafe path additionally requires the inlined loop to fail.
        """
        unit = self.ldu(name, argument, **keywords)
        expected = unit(data)

        with numpy_unavailable(unit):
            self.assertEqual(self.ldu(name, argument, **keywords)(data), expected)

        with numpy_unavailable(unit, cryptodome=True):
            self.assertEqual(self.ldu(name, argument, **keywords)(data), expected)

        with numpy_unavailable(unit, cryptodome=True):
            with mock.patch('refinery.units.blockwise.iterspread') as spread:
                spread.side_effect = RuntimeError
                self.assertEqual(self.ldu(name, argument, **keywords)(data), expected)

    def test_paths_agree_on_argument_reduction(self):
        data = self.generate_random_buffer(0x101)
        for argument in REDUCTION_ARGUMENTS:
            for name in ('add', 'shl', 'xor'):
                for blocksize in (1, 2):
                    with self.subTest(F'{name} {argument} -B{blocksize}'):
                        self.assertPathsAgree(name, argument, data, blocksize=blocksize)

    def test_paths_agree_on_argument_reduction_bigendian(self):
        data = self.generate_random_buffer(0x101)
        for argument in REDUCTION_ARGUMENTS:
            for name in ('add', 'shl'):
                for blocksize in (1, 2):
                    with self.subTest(F'{name} {argument} -B{blocksize} -E'):
                        self.assertPathsAgree(
                            name, argument, data, blocksize=blocksize, bigendian=True)

    @unittest.expectedFailure
    def test_xor_bigendian_partial_block_paths_agree(self):
        """
        The Cryptodome fallback of `xor` packs each argument block to full block size and
        truncates the result, while every other path reads a partial final block as a shorter
        integer. In big endian mode, the fallback produces different bytes for such a block.
        The divergence predates the argument reduction rework and is tracked here until the
        fallback is aligned with the other paths.
        """
        data = self.generate_random_buffer(0x101)
        for argument in REDUCTION_ARGUMENTS:
            with self.subTest(argument):
                self.assertPathsAgree('xor', argument, data, blocksize=2, bigendian=True)

    def test_integer_argument_reduction_warning(self):
        data = self.generate_random_buffer(0x21)
        for name in ('rotl', 'shl', 'shr'):
            for argument, blocksize, message in (
                ('300', 1, 'reduced argument to 0x2C; original value was 0x12C'),
                ('70000', 2, 'reduced argument to 0x1170; original value was 0x11170'),
            ):
                for numpy_off in (False, True):
                    with self.subTest(F'{name} {argument} -B{blocksize}, numpy off: {numpy_off}'):
                        with logged_unit(name, argument, blocksize=blocksize) as (unit, log):
                            if numpy_off:
                                with numpy_unavailable(unit):
                                    unit(data)
                            else:
                                unit(data)
                        self.assertEqual(log, [message])

    def test_plain_integer_argument_is_reduced_with_one_warning(self):
        from refinery.units.blockwise.shl import shl
        data = self.generate_random_buffer(0x21)
        for numpy_off in (False, True):
            with self.subTest(F'numpy off: {numpy_off}'):
                unit = shl(300)
                self.assertIs(type(unit.args.argument[0]), int)
                with logged(unit) as log:
                    if numpy_off:
                        with numpy_unavailable(unit):
                            unit(data)
                    else:
                        unit(data)
                self.assertEqual(log, ['reduced argument to 0x2C; original value was 0x12C'])

    def test_argument_reduction_warning_cap(self):
        data = self.generate_random_buffer(0x101)
        expected = [
            'reduced argument to 0x0000; original value was 0x10000000000000000',
            'reduced argument to 0x0001; original value was 0x10000000000000001',
            'reduced argument to 0x0002; original value was 0x10000000000000002',
            'additional warnings are suppressed',
        ]
        for numpy_off in (False, True):
            with self.subTest(F'numpy off: {numpy_off}'):
                with logged_unit(
                    'add', 'inc[70]:eval:18446744073709551616', blocksize=2
                ) as (unit, log):
                    if numpy_off:
                        with numpy_unavailable(unit):
                            unit(data)
                    else:
                        unit(data)
                self.assertEqual(log, expected)
