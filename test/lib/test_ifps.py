import contextlib
import ntpath
import pytest
import time

from typing import Callable
from unittest import mock

from refinery.lib.inno.emulation import EmulatorException
from refinery.lib.inno.pascal import IFPSException

from .. import TestBase, wontfix

_SCRIPT_WITH_NESTED_TRY = '453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc'
_SCRIPT_WITH_TRY_FINALLY = 'ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf'
_SCRIPT_THAT_NAMES_HRESULTS = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_SLEEPS = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_WRITES_NUMBERS_IN_HEX = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_PRINTS_JSON = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_READS_A_SETTING_FROM_THE_REGISTRY = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_LISTS_PROCESSES_IN_A_TRY_BLOCK = '6aebe4aac528782d132f96e970cbba2d182b7b3b78abddce7846a6fecd32b2d1'
_SCRIPT_FOR_AN_OLDER_INNO_SETUP = '2d3f393969037a0d0f19e1e01637bed00e0d766fafbb8916a2f6d0b1f8d4cdcd'
_SCRIPT_WITH_ONE_LOAD_FLAG_AND_ONLY_ANSI_STRINGS = 'fb0fc2e3c2059e6159540920a4ff7f75f92212639b318da7eb7fadece4a46ecc'
_SCRIPT_THAT_WRITES_THE_PASSWORD_BOX = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_WITH_PAGES_OF_ITS_OWN = _SCRIPT_WITH_NESTED_TRY
_INSTALLER_WITH_A_LICENSE_ONLY_IN_ITS_HEADER = 'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'
_INSTALLER_IN_41_LANGUAGES = '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314'
_INSTALLER_THAT_STRIPS_ACCELERATOR_KEYS = 'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c'
_INSTALLER_WITH_A_DIRECTORY_PAGE = 'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42'
_INSTALLER_THAT_WRITES_ITS_PASSWORD_INTO_THE_PASSWORD_BOX = _INSTALLER_WITH_A_DIRECTORY_PAGE
_SCRIPT_THAT_CATCHES_A_DIVISION_BY_ZERO = 'c47352571fb7ac45bd994f4b057ffec15898df4724f2a4cd0d9213e3eedfca29'
_SCRIPT_WITH_A_GLOBAL_RESOURCE_POINTER = 'dd4b75e1045c32756de639404b1d9644394891dfb53adc8b701c7a5c2a4b650c'
_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS = '9e3618e159e10f5344b35e9cbdabf9d234c46aa4c33ab65905b18cf2e9d3f451'
_SAMPLES_WHOSE_EMULATED_INSTALLATION_HAS_NO_SCRIPT_ERROR = (
    '0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642',
    '441094a1a29f4ff248f289e19ae6c8c15abe1ff8bd440aefe85a0e5817482e92',
    '453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc',
    '51ac80ab4daea0877910d13eb9dae07e8c26507e5115ee815eb7dc9410be3c22',
    '5589c0d2de0efdc59eb7325497f18a9a01c095b5cc4859774f75cc91bbdb2757',
    '6aebe4aac528782d132f96e970cbba2d182b7b3b78abddce7846a6fecd32b2d1',
    '922aaca70e288f7fd9ee31ac4db98d0fc90fb7bb92b056d18f69b328cbacc043',
    '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314',
    'a30a12d725e20c7ec403676710b3a2df41bb395fcc80539a28c0da09f5906ee6',
    'a3c40be74f061bd25a3e4b264602f4ace5652eed0ca020362a6d56d336bc650f',
    'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42',
    'c47352571fb7ac45bd994f4b057ffec15898df4724f2a4cd0d9213e3eedfca29',
    'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73',
    'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c',
    'd290117343b7e76b971c7b9eb618e60322af6cd74bd70296dbc00a06ca30d565',
    'eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e',
    'fb0fc2e3c2059e6159540920a4ff7f75f92212639b318da7eb7fadece4a46ecc',
)
_PASCAL_SCRIPT_CASTS = 'Class'
"""
The namespace of Pascal Script's casts of objects, internal functions that no API declares.
"""


@contextlib.contextmanager
def _replaced_external(name: str, call: Callable, namespace: str = '', **changes):
    """
    Replaces the emulated external function of the given name with the given callable. Other fields
    of its emulation info can be changed by keyword.
    """
    from refinery.lib.inno.emulator import IFPSEmulator
    registry = IFPSEmulator.external_symbols[namespace]
    with mock.patch.dict(registry, {name: registry[name]._replace(call=call, **changes)}):
        yield


@contextlib.contextmanager
def _failing_method(classname: str, name: str, argc: int):
    """
    Emulates the method of the given class and name, which the emulator does not implement, as one
    that raises an error. The method takes `argc` values, its object first.
    """
    from refinery.lib.inno.emulator import IFPSEmulatedFunction, IFPSEmulator

    def fail(*_):
        raise RuntimeError(F'{classname}.{name} failed')

    with mock.patch.dict(IFPSEmulator.external_symbols, {classname: {name: IFPSEmulatedFunction(fail, [False] * argc)}}):
        yield


def _failing_external(name: str):
    """
    Makes the emulated external function of the given name raise an error.
    """
    def fail(*_):
        raise RuntimeError(F'{name} failed')

    return _replaced_external(name, fail)


class TestIPFSEmulator(TestBase):

    def test_variable_representation(self):
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.archive import InnoArchive
        data = self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
        inno = InnoArchive(data)
        ismu = InnoSetupEmulator(inno)
        self.assertEqual(repr(ismu.globals[1]), 'GlobalVar1 = 0')
        ismu.globals[1].set(7)
        self.assertEqual(repr(ismu.globals[1]), 'GlobalVar1 = 7')

    def test_the_emulated_clock_starts_at_a_whole_second(self):
        from refinery.lib.inno.emulator import IFPSEmulatorConfig
        self.assertEqual(IFPSEmulatorConfig().start_time.microsecond, 0)

    def test_two_procedure_pointer_constants_for_one_function_are_equal(self):
        from refinery.lib.inno.ifps import Function, IFPSFile, Operand
        ifps = IFPSFile.Parse(self.download_sample('ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf'))
        by_function: dict[str, list[Function]] = {}
        for function in ifps.functions:
            for instruction in function.body or ():
                for operand in instruction.operands:
                    if not isinstance(operand, Operand) or (value := operand.value) is None:
                        continue
                    if isinstance(reference := value.value, Function):
                        by_function.setdefault(reference.name, []).append(reference)
        groups = [references for references in by_function.values() if len(references) > 1]
        self.assertTrue(groups)
        for first, *others in groups:
            for other in others:
                self.assertEqual(first, other)

    def _emulate_with_an_argument_that_is_not_a_number(self, data: bytearray, name: str):
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import IFPSEmulator
        from refinery.lib.inno.pascal import IFPSException
        ifps = InnoArchive(bytearray(data)).ifps
        assert ifps is not None
        function = next(f for f in ifps.functions if f.name.lower() == name)
        with contextlib.suppress(IFPSException):
            list(IFPSEmulator(ifps).emulate_function(function, 'not a number'))

    def test_a_failing_external_leaves_nothing_to_the_collector(self):
        data = self.download_sample('aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42')
        for name in ('strtoint', 'getdir'):
            with self.subTest(function=name):
                self.assertCollectorFreesLessThan(
                    0x40000, lambda: self._emulate_with_an_argument_that_is_not_a_number(data, name)
                )

    def _emulate_the_installation(self, data: bytearray):
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.ifps import IFPSFile
        list(InnoSetupEmulator(IFPSFile.Parse(bytearray(data))).emulate_installation())

    def test_an_emulated_installation_leaves_nothing_to_the_collector(self):
        data = self.download_sample('a3c40be74f061bd25a3e4b264602f4ace5652eed0ca020362a6d56d336bc650f')
        self.assertCollectorFreesLessThan(0x40000, lambda: self._emulate_the_installation(data))

    def test_a_caught_division_by_zero_leaves_nothing_to_the_collector(self):
        data = self.download_sample(_SCRIPT_THAT_CATCHES_A_DIVISION_BY_ZERO)
        self.assertCollectorFreesLessThan(0x40000, lambda: self._emulate_the_installation(data))

    def _stop_in_the_except_block_of_an_index_outside_of_an_array(self, data: bytearray):
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.emulation import NewFunctionCall
        from refinery.lib.inno.ifps import IFPSFile
        emulator = InnoSetupEmulator(IFPSFile.Parse(bytearray(data)), IFPSEmulatorConfig(log_calls=True))
        for event in emulator.emulate_function(emulator.symbols['ORACLERUNTIMEERRORS']):
            if isinstance(event, NewFunctionCall) and event.name == 'GetExceptionMessage':
                break

    def test_an_emulation_stopped_inside_an_except_block_leaves_nothing_to_the_collector(self):
        """
        The password search stops the emulated installation where it finds the password, which can
        be inside an except block.
        """
        data = self.download_sample(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        self.assertCollectorFreesLessThan(
            0x40000, lambda: self._stop_in_the_except_block_of_an_index_outside_of_an_array(data)
        )

    def test_an_exception_handler_of_a_script_runs_on_the_stack_of_its_try_block(self):
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, log_calls=True)
        with _failing_external('SetLength'):
            call = emulator.emulate_function(emulator.symbols['GETADSERVERRESPONSE'])
            logged = [event.args for event in call if isinstance(event, NewFunctionCall) and event.name == 'Log']
        self.assertEqual(logged, [('Failed to get configuration',)])
        self.assertFalse(call.value)

    def _script_emulator(self, sample: str, **config):
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.ifps import IFPSFile
        return InnoSetupEmulator(IFPSFile.Parse(self.download_sample(sample)), IFPSEmulatorConfig(**config))

    def _emulated_value(self, sample: str, function: str, **config):
        emulator = self._script_emulator(sample, **config)
        return emulator.emulate_function(emulator.symbols[function]).value

    def test_a_date_format_of_adjacent_fields_is_formatted_field_by_field(self):
        self.assertRegex(str(self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETSESSIONID')), '^[0-9]{14}$')

    def test_an_exception_in_a_called_function_runs_the_handler_of_its_caller(self):
        windows = self._emulated_value(_SCRIPT_WITH_NESTED_TRY, 'GETWINDOWSDIR')
        with _failing_external('CompareText'):
            temp = self._emulated_value(_SCRIPT_WITH_NESTED_TRY, 'GETWINDOWSTEMPDIR')
        self.assertEqual(temp, F'{windows}\\temp')

    def test_an_exception_in_a_catch_block_leaves_the_function(self):
        from refinery.lib.inno.pascal import IFPSException
        with _failing_external('Log'), self.assertRaises(IFPSException):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE', max_seconds=2)

    def test_an_exception_in_a_try_block_leaves_the_function_after_its_finally_block(self):
        from refinery.lib.inno.pascal import IFPSException
        with _failing_external('GetDateTimeString'), self.assertRaises(IFPSException):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETSESSIONID')

    def test_an_exit_from_a_try_block_runs_its_finally_block(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        emulator.globals[16].set('session')
        call = emulator.emulate_function(emulator.symbols['GETSESSIONID'])
        for _ in call:
            pass
        self.assertEqual(call.value, 'session')

    def test_an_unsigned_integer_variable_wraps_every_assigned_value_into_its_range(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        for code, value, wrapped in (
            (TC.U08, -1, 0xFF),
            (TC.U16, 0x12345, 0x2345),
            (TC.U08, chr(0x20AC), 0xAC),
            (TC.U16, -1.0, 0xFFFF),
            (TC.U32, float(1 << 32), 0),
        ):
            with self.subTest(type=code.name, value=repr(value)):
                variable = Variable(TPrimitive(code))
                variable.set(value)
                self.assertEqual(variable.get(), wrapped)

    def test_a_64_bit_integer_variable_wraps_an_assigned_value_into_its_range(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        for code, value, wrapped in (
            (TC.U64, -1, 0xFFFF_FFFF_FFFF_FFFF),
            (TC.U64, 1 << 64, 0),
            (TC.S64, (1 << 64) + 5, 5),
        ):
            with self.subTest(type=code.name, value=value):
                variable = Variable(TPrimitive(code))
                variable.set(value)
                self.assertEqual(variable.get(), wrapped)

    def test_a_signed_integer_variable_wraps_an_assigned_value_into_its_range(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        held = []
        for code, value in ((TC.S08, 200), (TC.S32, 0x80000000)):
            variable = Variable(TPrimitive(code))
            variable.set(value)
            held.append(variable.get())
        self.assertEqual(held, [-56, -0x80000000])

    def test_an_integer_cast_from_a_boolean_is_written_as_a_number(self):
        """
        Pascal Script compiles the cast `Integer(B)` of a Boolean `B` as a plain assignment.
        """
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        integer = Variable(TPrimitive(TC.S32))
        integer.set(True)
        self.assertEqual(emulator.IntToStr(integer.get()), '1')

    def _installer_emulator(self, **config):
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        data = self.download_sample(_INSTALLER_THAT_STRIPS_ACCELERATOR_KEYS)
        return InnoSetupEmulator(InnoArchive(data), IFPSEmulatorConfig(**config))

    def test_setlength_resizes_a_list(self):
        from refinery.lib.inno.wizard import PageID
        emulator = self._installer_emulator()
        byte_list = emulator.globals[60]
        self.assertEqual(len(byte_list), 0)
        list(emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpWelcome))
        self.assertEqual(len(byte_list), 256)

    def test_a_list_longer_than_the_configured_limit_ends_the_emulation(self):
        from refinery.lib.inno.emulation import EmulatorMaxArray
        from refinery.lib.inno.wizard import PageID
        emulator = self._installer_emulator(max_array_length=255)
        with self.assertRaises(EmulatorMaxArray):
            list(emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpWelcome))
        self.assertEqual(len(emulator.globals[60]), 0)

    def test_a_script_cannot_handle_a_list_longer_than_the_configured_limit(self):
        from refinery.lib.inno.emulation import EmulatorMaxArray
        with self.assertRaises(EmulatorMaxArray):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE', max_array_length=1)

    def test_a_string_change_beyond_the_string_limit_ends_the_emulation_before_the_string_changes(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.emulation import EmulatorMaxString
        from refinery.lib.inno.ifps import TC, TPrimitive
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, max_string_length=10)
        text = Variable(TPrimitive(TC.UnicodeString), data='a,b,c')
        with self.assertRaises(EmulatorMaxString):
            emulator.StringChangeEx(text, ',', ', and ', False)
        self.assertEqual(text.get(), 'a,b,c')

    def test_a_join_beyond_the_string_limit_ends_the_emulation(self):
        from refinery.lib.inno.emulation import EmulatorMaxString
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, max_string_length=10)
        self.assertEqual(emulator.StringJoin(', ', ['a', 'b', 'c', 'd']), 'a, b, c, d')
        with self.assertRaises(EmulatorMaxString):
            emulator.StringJoin(', ', ['a', 'b', 'c', 'd', 'e'])

    def test_an_emulated_function_that_exhausts_the_memory_of_python_ends_the_emulation(self):
        from refinery.lib.inno.emulation import EmulatorMemoryError

        def exhaust(*_):
            raise MemoryError

        with _replaced_external('GetDateTimeString', exhaust), self.assertRaises(EmulatorMemoryError):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETSESSIONID')

    def test_an_abort_ends_the_emulation_when_the_configuration_asks_for_it(self):
        from refinery.lib.inno.emulation import AbortEmulation
        with self.assertRaises(AbortEmulation):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'EXITNOCONFIG', throw_abort=True)

    def test_an_interrupt_inside_an_emulated_function_stops_the_emulation(self):
        def interrupt(*_):
            raise KeyboardInterrupt

        with _replaced_external('GetDateTimeString', interrupt), self.assertRaises(KeyboardInterrupt):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETSESSIONID')

    def test_a_negative_length_empties_a_list_and_a_string(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        emulator = self._installer_emulator()
        byte_list = emulator.globals[60]
        emulator.SetLength(byte_list, 5)
        emulator.SetLength(byte_list, -2)
        self.assertEqual(len(byte_list), 0)
        string = Variable(TPrimitive(TC.UnicodeString), data='abcde')
        emulator.SetLength(string, -2)
        self.assertEqual(string.get(), '')

    def test_a_list_grown_twice_names_its_elements_by_position(self):
        byte_list = self._installer_emulator().globals[60]
        byte_list.resize(2)
        byte_list.resize(4)
        self.assertEqual([byte_list.at(k).name for k in range(len(byte_list))], [F'{byte_list.name}[{k}]' for k in range(4)])

    def test_a_pointer_to_a_copy_of_a_container_keeps_the_values_it_was_copied_from(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TArray, TPrimitive, TRecord
        byte = TPrimitive(TC.U08)
        for container_type, values, changed in (
            (TArray(TC.Array, byte), [1, 2, 3], [4]),
            (TRecord(TC.Record, (byte, TPrimitive(TC.UnicodeString))), [1, 'one'], [2, 'two']),
        ):
            with self.subTest(type=str(container_type)):
                original = Variable(container_type)
                original.set(values)
                pointer = Variable(TPrimitive(TC.Pointer))
                pointer.setptr(original, copy=True)
                original.set(changed)
                self.assertEqual(pointer.get(), values)

    def test_an_array_of_constants_holds_the_constants_it_was_built_from(self):
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, log_calls=True)
        report = emulator.emulate_function(emulator.symbols['SENDREPORT'], '', '', '', '', [])
        formatted = [event.args for event in report if isinstance(event, NewFunctionCall) and event.name == 'Format']
        self.assertIn(('%s.%s.%s.%s', ['1', '34', '2', '8157']), formatted)

    def test_a_reset_restores_the_globals_that_a_script_changed(self):
        from refinery.lib.inno.wizard import PageID
        emulator = self._installer_emulator()
        fresh = [variable.get() for variable in emulator.globals]
        list(emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpWelcome))
        self.assertNotEqual([variable.get() for variable in emulator.globals], fresh)
        emulator.reset()
        self.assertEqual([variable.get() for variable in emulator.globals], fresh)

    def test_a_reset_before_each_constant_expansion_costs_little_more_than_the_expansion(self):
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.json import flattened
        from refinery.lib.structures import struct_to_json
        inno = InnoArchive(self.download_sample(_INSTALLER_THAT_STRIPS_ACCELERATOR_KEYS))
        emulator = inno.emulator
        assert emulator is not None
        strings = []
        for document in (struct_to_json(inno.setup_info), struct_to_json(inno.setup_data)):
            assert isinstance(document, dict)
            strings.extend(value for _, value in flattened(document) if isinstance(value, str))

        def expand_all(reset_before_each: bool) -> float:
            start = time.perf_counter()
            emulator.reset()
            for string in strings:
                if reset_before_each:
                    emulator.reset()
                emulator.expand_constant(string)
            return time.perf_counter() - start

        each = min(expand_all(True) for _ in range(3))
        once = min(expand_all(False) for _ in range(3))
        # A reset that rebuilds the 61 global variables of this script makes the ratio about 400.
        self.assertLess(each / once, 10)

    def test_trim_removes_every_character_up_to_the_space_as_delphi_does(self):
        """
        Pascal Script calls Delphi's `Trim`, `TrimLeft` and `TrimRight`, which remove the characters
        from #0 to the space and keep every other character, such as the no-break space.
        """
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.Trim('\0\t a b \r\n\0'), 'a b')
        self.assertEqual(emulator.TrimLeft('\0 a\0'), 'a\0')
        self.assertEqual(emulator.TrimRight('\0 a\0'), '\0 a')
        self.assertEqual(emulator.Trim('\xa0a\xa0'), '\xa0a\xa0')

    def test_a_compiled_prefix_check_finds_the_prefix_with_pos(self):
        emulator = self._installer_emulator()
        starts_with = emulator.symbols['STARTSWITH']
        self.assertTrue(emulator.emulate_function(starts_with, 'Install', 'Install.exe').value)
        self.assertFalse(emulator.emulate_function(starts_with, 'exe', 'Install.exe').value)
        self.assertFalse(emulator.emulate_function(starts_with, '&', '').value)
        self.assertFalse(emulator.emulate_function(starts_with, '', 'Install').value)

    def test_removing_accelerator_keys_from_an_empty_caption_ends(self):
        emulator = self._installer_emulator(max_opcodes=10_000)
        list(emulator.emulate_function(emulator.symbols['REMOVEACCELERATORKEY'], ''))

    def test_a_parameter_that_takes_any_string_type_is_shown_as_any_string(self):
        decl = self._installer_emulator().symbols['Pos'].decl
        assert decl is not None
        self.assertEqual([str(parameter.type) for parameter in decl.parameters], ['AnyString', 'AnyString'])

    def test_each_type_of_a_script_is_listed_once(self):
        types = self._installer_emulator().ifps.types
        self.assertEqual(len({id(type) for type in types}), len(types))

    def test_a_script_without_a_guid_type_gets_one_for_an_import_that_takes_a_guid(self):
        """
        The declaration of `Trim` is replaced by one that takes a `TGUID`, as `CreateComObject`
        does, in a script that has no type of that name.
        """
        from refinery.lib.inno.ifps import IFPSFile
        from refinery.lib.inno.symbols import IFPSAPI
        trim = IFPSAPI['Trim']
        string, = trim.parameters
        with mock.patch.dict(IFPSAPI, {'Trim': trim._replace(parameters=(string._replace(type='TGUID'),))}):
            ifps = IFPSFile.Parse(self.download_sample(_SCRIPT_WITH_TRY_FINALLY))
        self.assertEqual(ifps.types_by_name['TGUID'].display(), 'struct {LongWord, Word, Word, Byte[8]}')

    def test_every_emulated_function_takes_and_returns_what_inno_setup_or_pascal_script_declares(self):
        from refinery.lib import json
        from refinery.lib.inno.emulator import IFPSEmulator
        from refinery.lib.inno.symbols import IFPSAPI, IFPSClasses
        from refinery.lib.resources import datapath
        with datapath('winapi.json').open('rb') as stream:
            modules = json.loads(stream.read())
        for namespace, handlers in IFPSEmulator.external_symbols.items():
            if namespace in modules or namespace == _PASCAL_SCRIPT_CASTS:
                continue
            declared = IFPSClasses.Classes[namespace].members if namespace else IFPSAPI
            for name, handler in handlers.items():
                with self.subTest(namespace=namespace, name=name):
                    self.assertIn(name, declared)
                    declaration = declared[name]
                    # The handler of a method or a property read takes the object first.
                    receiver = bool(namespace) and declaration.kind not in ('getter', 'setter')
                    returns = declaration.kind == 'property' or not declaration.void
                    self.assertEqual(
                        (handler.argc, not handler.void),
                        (declaration.argc + receiver, returns),
                    )

    def test_a_script_that_sleeps_advances_the_emulated_clock(self):
        emulator = self._script_emulator(_SCRIPT_THAT_SLEEPS)
        list(emulator.emulate_function(emulator.symbols['CALLSHCHANGENOTIFY']))
        # CALLSHCHANGENOTIFY calls Sleep(200).
        self.assertEqual(emulator.seconds_slept, 0.2)

    def test_a_script_that_expands_a_code_constant_keeps_its_own_stack(self):
        """
        The replaced `Log` stands in for a script function that calls `ExpandConstant` with a code
        constant: the catch block of `GETADSERVERRESPONSE` logs and then returns `False`.
        """
        from refinery.lib.inno.emulator import IFPSEmulator

        def log_by_expanding_a_code_constant(emulator: IFPSEmulator, _: str):
            emulator.expand_constant('{code:GETAPPPATH|x}')

        with _failing_external('SetLength'), _replaced_external('Log', log_by_expanding_a_code_constant):
            self.assertEqual(self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE'), 0)

    def test_a_constant_expanded_inside_a_run_counts_against_the_time_limit_of_that_run(self):
        """
        The replaced `Log` stands in for an emulated function that expands a code constant, after
        it took more than half of the time limit. The function of the constant asks twice whether
        Windows is 64-bit, which here takes more than a quarter of the limit each time: the
        expansion alone stays within the limit, but not together with the run that it is part of.
        """
        from refinery.lib.inno.emulator import IFPSEmulator
        from refinery.lib.inno.emulation import EmulatorTimeout
        is_win64 = IFPSEmulator.external_symbols['']['IsWin64'].call
        expanded = []

        def spend(seconds: float):
            started = time.process_time()
            while time.process_time() - started < seconds:
                pass

        def slow_is_win64(*args):
            spend(0.3)
            return is_win64(*args)

        def log_by_expanding_a_code_constant(emulator: IFPSEmulator, _: str):
            spend(0.6)
            emulator.expand_constant('{code:GETAPPPATH|x}')
            expanded.append(True)

        with (
            _failing_external('SetLength'),
            _replaced_external('Log', log_by_expanding_a_code_constant),
            _replaced_external('IsWin64', slow_is_win64),
            self.assertRaises(EmulatorTimeout),
        ):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE', max_seconds=1)
        self.assertEqual(expanded, [])

    def test_a_script_function_named_like_an_inno_function_keeps_its_own_declaration(self):
        function = self._installer_emulator().symbols['IsDotNetInstalled']
        assert function.decl is not None
        self.assertEqual(function.decl.parameters, [])

    def test_a_type_is_only_named_cardinal_when_it_is_an_unsigned_32_bit_integer(self):
        from refinery.lib.inno.ifps import TC
        emulator = self._installer_emulator()
        for type in emulator.ifps.types:
            if str(type) == 'Cardinal':
                self.assertEqual(type.code, TC.U32)

    def test_a_unicode_script_reads_a_declared_string_as_a_unicode_string(self):
        from refinery.lib.inno.ifps import TC
        decl = self._installer_emulator().symbols['Copy'].decl
        assert decl is not None and decl.return_type is not None
        self.assertEqual(decl.return_type.code, TC.UnicodeString)

    def test_a_file_placed_in_a_directory_from_a_wizard_page_keeps_that_directory(self):
        from refinery.lib.inno.archive import InnoArchive
        inno = InnoArchive(self.download_sample(_INSTALLER_WITH_A_DIRECTORY_PAGE))
        self.assertEqual(inno.files[0].path, 'data/$InputDir0/HalfTime.dll')

    def test_the_calls_of_a_script_decide_how_many_load_flags_its_dll_imports_have(self):
        """
        The revision of Pascal Script that compiled this script wrote one load flag into the
        declaration of a DLL import. With that count, `GetTickCount` of `kernel32` returns a value
        and takes no argument, as Windows declares it.
        """
        from refinery.lib.inno.ifps import IFPSFile
        ifps = IFPSFile.Parse(self.download_sample(_SCRIPT_WITH_ONE_LOAD_FLAG_AND_ONLY_ANSI_STRINGS))
        decl = next(function.decl for function in ifps.functions if function.name == 'GetTickCount')
        assert decl is not None
        self.assertEqual((decl.module, decl.void, decl.argc), ('kernel32', False, 0))

    def test_a_script_whose_only_string_type_is_ansistring_reads_a_declared_string_as_an_ansi_string(self):
        from refinery.lib.inno.ifps import IFPSFile, TC
        ifps = IFPSFile.Parse(self.download_sample(_SCRIPT_WITH_ONE_LOAD_FLAG_AND_ONLY_ANSI_STRINGS))
        decl = next(function.decl for function in ifps.functions if function.name == 'GetEnv')
        assert decl is not None and decl.return_type is not None
        self.assertEqual([parameter.type and parameter.type.code for parameter in decl.parameters], [TC.AnsiString])
        self.assertEqual(decl.return_type.code, TC.AnsiString)

    def test_a_property_that_takes_more_arguments_than_any_call_can_pass_is_refused(self):
        import struct
        from refinery.lib.inno.ifps import IFPSFile
        data = self.download_sample(_SCRIPT_THAT_WRITES_THE_PASSWORD_BOX)
        write = b'class:TPASSWORDEDIT|TEXT@|'
        count = data.find(write) + len(write)
        self.assertEqual(data[count:count + 4], struct.pack('<I', 1))
        data[count:count + 4] = struct.pack('<I', len(data))
        with self.assertRaisesRegex(ValueError, 'property TEXT takes'):
            IFPSFile.Parse(data)

    def test_a_call_whose_declaration_disagrees_with_its_emulation_fails_as_that_call(self):
        """
        The declaration of the import of `Log` is changed from a procedure to a function, which the
        emulated `Log` is not.
        """
        import struct
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.emulation import NewEmulationError
        from refinery.lib.inno.ifps import IFPSFile
        data = self.download_sample(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        procedure_of_one_argument = bytes([3]) + b'LOG' + struct.pack('<I', 2) + bytes(2)
        declaration = data.find(procedure_of_one_argument) + 8
        self.assertEqual(data.find(procedure_of_one_argument, declaration), -1)
        data[declaration] = 1
        emulator = InnoSetupEmulator(IFPSFile.Parse(data))
        failures = []
        with self.assertRaises(IFPSException) as raised:
            for event in emulator.emulate_function(emulator.symbols['PUT'], 'Name', 'Value'):
                if isinstance(event, NewEmulationError):
                    failures.append(event)
        self.assertEqual([failure.name for failure in failures], ['Log'])
        self.assertEqual(raised.exception.message, failures[0].message)

    def test_a_negative_hresult_matches_the_case_label_of_its_bit_pattern(self):
        emulator = self._script_emulator(_SCRIPT_THAT_NAMES_HRESULTS)
        e_notimpl = 0x80004001 - (1 << 32)
        self.assertEqual(emulator.emulate_function(emulator.symbols['HRESULT2STR'], e_notimpl).value, 'NOTIMPL')

    def test_a_negative_integer_converts_to_the_hex_digits_of_its_bit_pattern(self):
        emulator = self._script_emulator(_SCRIPT_THAT_WRITES_NUMBERS_IN_HEX, max_opcodes=10_000)
        self.assertEqual(emulator.emulate_function(emulator.symbols['DECTOHEX'], -16, 8).value, 'FFFFFFF0')

    def test_format_receives_each_argument_with_its_type(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC
        received = []

        def record(_, fmt: str, args: Variable) -> str:
            received.append([args.at(k).deref().type.code for k in range(len(args.deref()))])
            return fmt

        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD)
        with _failing_method('TDownloadWizardPage', 'Download', 1), _replaced_external('Format', record, spec=[False, True]):
            list(emulator.emulate_function(emulator.symbols['DOWNLOADFILE'], 'url', 'path'))
        self.assertEqual(received, [
            [TC.UnicodeString, TC.UnicodeString],
            [TC.UnicodeString, TC.UnicodeString, TC.U32, TC.U32, TC.UnicodeString],
        ])

    def test_format_receives_a_number_reached_through_pointers_with_its_type(self):
        """
        `PRINTJSONOBJECT` reaches the value of an object entry, an element of the array of numbers
        in the parser output, through a chain of pointers, and formats it with `%g`.
        """
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC
        received = []

        def record(_, fmt: str, args: Variable) -> str:
            received.append([args.at(k).deref().type.code for k in range(len(args.deref()))])
            return fmt

        json_number = 1
        entry = ['key', [json_number, 0]]
        parser_output = [[1.5], [], [], [], [[entry]], []]
        emulator = self._script_emulator(_SCRIPT_THAT_PRINTS_JSON)
        printer = emulator.symbols['PRINTJSONOBJECT']
        with _replaced_external('Format', record):
            list(emulator.emulate_function(printer, parser_output, 0, 0, None, ''))
        self.assertEqual(received, [[TC.UnicodeString, TC.Double]])

    def test_a_script_error_in_should_skip_page_ends_only_that_event(self):
        """
        For the page that selects the target directory, `ShouldSkipPage` ends by passing the result
        of `ExtractFileDir` to `DirExistsNoRedir`. When `ExtractFileDir` fails, Inno Setup shows the
        error and does not skip the page, which is also the answer of the script without the error.
        Setup asks whether the page is skipped when Next reaches it, and again when the next page
        decides whether it shows the Back button.
        """
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.emulation import NewFunctionCall, NewScriptError, SetupEvent
        from refinery.lib.inno.wizard import PageID
        from refinery.lib.inno.ifps import IFPSFile

        script = IFPSFile.Parse(self.download_sample(_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE))

        def emulator():
            return InnoSetupEmulator(script, IFPSEmulatorConfig(log_calls=True))

        def calls_and_errors(events):
            return [
                event.name if isinstance(event, NewFunctionCall) else event
                for event in events if isinstance(event, (NewFunctionCall, NewScriptError))
            ]

        clean = calls_and_errors(emulator().emulate_installation())
        with _failing_external('ExtractFileDir'):
            failed = calls_and_errors(emulator().emulate_installation())
        checker = emulator()
        unreached = calls_and_errors(checker.emulate_function(checker.symbols['DIREXISTSNOREDIR'], ''))
        errors = [event for event in failed if isinstance(event, NewScriptError)]
        self.assertEqual([(error.name, error.args) for error in errors], 2 * [(SetupEvent.ShouldSkipPage, (PageID.wpSelectDir,))])
        completed = []
        for event in failed:
            completed.extend(unreached if isinstance(event, NewScriptError) else [event])
        # names only: two clean runs differ in time stamps and random numbers, never in the calls
        self.assertEqual(completed, clean)

    def test_each_architecture_function_answers_for_the_processor_of_the_emulated_machine(self):
        """
        Setup answers each of these functions as the architecture identifier of its name: an
        identifier that ends in `compatible` holds when Windows runs code of the architecture, any
        other one when the processor is of the architecture. The emulated machine has an x64
        processor with 64-bit Windows, or an x86 processor with 32-bit Windows.
        """
        names = ['IsArm32Compatible', 'IsArm64', 'IsX64', 'IsX64OS', 'IsX64Compatible', 'IsX86', 'IsX86OS', 'IsX86Compatible']
        for x64, answers in (
            (True, [False, False, True, True, True, False, False, True]),
            (False, [False, False, False, False, False, True, True, True]),
        ):
            emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, x64=x64)
            with self.subTest(x64=x64):
                self.assertEqual([getattr(emulator, name)() for name in names], answers)

    def test_without_its_installer_a_script_finds_every_component_and_task_selected(self):
        """
        The emulator does not know the components and tasks of a script without its installer, so
        it does not test their names, as Setup does not test names without a list of them. A list
        of the selected names holds the names that the emulator knows, which are none.
        """
        from refinery.lib.inno.emulator import EventCall
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        self.assertTrue(emulator.WizardIsComponentSelected('a and not a'))
        self.assertTrue(emulator.WizardIsTaskSelected('a and not a'))
        self.assertEqual(EventCall(emulator.WizardSelectedComponents(False)).value, '')
        self.assertEqual(emulator.WizardSetupType(False), '')

    def test_an_empty_test_of_the_selection_holds_as_in_setup(self):
        """
        Setup's `ShouldProcessEntry` tests no names for an empty expression, also when the wizard
        knows the selection; this wizard selects nothing.
        """
        from refinery.lib.inno.wizard import StandIns, WizardForm
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        form.created = True
        self.assertTrue(emulator.WizardIsComponentSelected(''))
        self.assertTrue(emulator.WizardIsTaskSelected(''))
        self.assertFalse(emulator.WizardIsTaskSelected('a'))

    def test_a_broken_test_of_the_selection_fails_with_the_internal_error_of_setup(self):
        """
        Setup's `EvalExpression` raises an error of the expression as `InternalError` with the text
        `Expression error '%s'`, which Setup's message `ErrorInternal2` writes as
        `Internal error: %1`.
        """
        from refinery.lib.inno.delphi.errors import DelphiException
        from refinery.lib.inno.wizard import StandIns, WizardForm
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        form.created = True
        with self.assertRaises(DelphiException) as raised:
            emulator.WizardIsComponentSelected('a)')
        self.assertEqual(str(raised.exception), 'Internal error: Expression error \'Invalid token \')\' found\'')

    def test_a_member_that_only_places_or_draws_a_list_of_the_wizard_keeps_its_choices(self):
        """
        The script calls these members, which the emulator does not model, on lists of its own.
        Called on the list of components of a wizard whose choices the emulator knows, those that
        place the list or change how it looks keep the choices known; any other one does not.
        """
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        from refinery.lib.inno.wizard import StandIns, WizardForm
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        members = {str(function): function for function in emulator.ifps.functions if function.body is None}
        components = Variable(TPrimitive(TC.Class), data=form.components)
        for name in ('TControl.SetTop', 'TControl.SetHeight', 'TNewCheckListBox.SetBorderStyle', 'TNewCheckListBox.SetAnchors'):
            emulator.unimplemented(members[name], [components, Variable(TPrimitive(TC.S32), data=1)], None)
        self.assertTrue(form.components.known)
        emulator.unimplemented(members['TNewCheckListBox.SetItemEnabled'], [components, Variable(TPrimitive(TC.S32), data=0)], None)
        self.assertFalse(form.components.known)

    def test_a_member_of_another_object_that_takes_a_list_of_the_wizard_keeps_its_choices(self):
        """
        `TWizardForm.IncTopDecHeight` moves and resizes the control that it is given, and the cast
        `SetNil` of Pascal Script, which the script imports, empties a variable that may hold a
        list; neither changes the choices of the list of components of a wizard whose choices the
        emulator knows.
        """
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, DeclSpec, DeclSpecParam, Function, TPrimitive
        from refinery.lib.inno.wizard import StandIns, WizardForm
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        components = Variable(TPrimitive(TC.Class), data=form.components)
        resize = Function('IncTopDecHeight', DeclSpec(
            True,
            [DeclSpecParam(True), DeclSpecParam(True)],
            name='IncTopDecHeight',
            classname='TWizardForm',
            method=True,
        ))
        amount = Variable(TPrimitive(TC.S32), data=-20)
        emulator.unimplemented(resize, [Variable(TPrimitive(TC.Class), data=form), components, amount], None)
        self.assertTrue(form.components.known)
        cast = next(function for function in emulator.ifps.functions if str(function) == 'Class.SetNil')
        emulator.unimplemented(cast, [components], None)
        self.assertTrue(form.components.known)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='the items of a list are not modelled, so reading them gives up its choices',
    )
    def test_reading_the_items_of_a_list_of_the_wizard_keeps_its_choices(self):
        from refinery.lib.inno.emulator import Variable
        from refinery.lib.inno.ifps import TC, TPrimitive
        from refinery.lib.inno.wizard import StandIns, WizardForm
        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        members = {str(function): function for function in emulator.ifps.functions if function.body is None}
        emulator.unimplemented(members['TCustomListBox.GetItems'], [Variable(TPrimitive(TC.Class), data=form.components)], None)
        self.assertTrue(form.components.known)

    def test_every_support_function_that_setup_runs_through_its_wizard_is_emulated(self):
        """
        Setup runs these support functions through `GetWizardForm`, which fails before Setup has
        created its wizard; a function that the emulator does not emulate answers anyway.
        """
        from refinery.lib.inno.emulator import IFPSEmulator
        names = [
            'CreateCustomPage',
            'CreateDownloadPage',
            'CreateExtractionPage',
            'CreateInputDirPage',
            'CreateInputFilePage',
            'CreateInputOptionPage',
            'CreateInputQueryPage',
            'CreateOutputMarqueeProgressPage',
            'CreateOutputMsgMemoPage',
            'CreateOutputMsgPage',
            'CreateOutputProgressPage',
            'GetWizardForm',
            'IsComponentSelected',
            'IsTaskSelected',
            'PageFromID',
            'PageIndexFromID',
            'WizardDirValue',
            'WizardGroupValue',
            'WizardIsComponentSelected',
            'WizardIsTaskSelected',
            'WizardNoIcons',
            'WizardSelectComponents',
            'WizardSelectTasks',
            'WizardSelectedComponents',
            'WizardSelectedTasks',
            'WizardSetupType',
        ]
        self.assertEqual([name for name in names if name not in IFPSEmulator.external_symbols['']], [])

    def test_a_second_installation_runs_the_script_as_the_first(self):
        from refinery.lib.inno.emulation import NewFunctionCall, NewPassword
        emulator = self._script_emulator(_SCRIPT_WITH_PAGES_OF_ITS_OWN, log_calls=True)

        def calls_and_passwords():
            return [
                event if isinstance(event, NewPassword) else event.name
                for event in emulator.emulate_installation() if isinstance(event, (NewFunctionCall, NewPassword))
            ]

        first = calls_and_passwords()
        self.assertIn('NFfB5qf2o1EJOkmBRrMvFcmj4QmKfwyNE5yoMOMRmFE4yfEEEMImIyyEYIQYFiO0', first)
        self.assertEqual(calls_and_passwords(), first)

    def test_check_password_runs_only_when_setup_rejects_the_text_of_the_password_box(self):
        """
        On the password page, the script writes `Zet0` into the password box, and its
        `CheckPassword` writes another text into the box.
        """
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.emulation import NewFunctionCall
        archive = InnoArchive(self.download_sample(_INSTALLER_THAT_WRITES_ITS_PASSWORD_INTO_THE_PASSWORD_BOX))
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                tested = []

                def password_test(text: str) -> bool:
                    tested.append(text)
                    return accepted

                emulator = InnoSetupEmulator(archive, IFPSEmulatorConfig(log_calls=True))
                written = [
                    event.args[1] for event in emulator.emulate_installation(password_test=password_test)
                    if isinstance(event, NewFunctionCall) and event.name == 'TPasswordEdit.SetText'
                ]
                self.assertEqual(tested, ['Zet0'])
                self.assertEqual(written[written.index('Zet0') + 1:], [] if accepted else ['The password is protected!'])

    def test_a_language_without_a_license_shows_the_license_of_the_setup_header(self):
        from refinery.lib.inno.archive import InnoArchive
        setup = InnoArchive(self.download_sample(_INSTALLER_WITH_A_LICENSE_ONLY_IN_ITS_HEADER)).setup_info
        language, = setup.Languages
        self.assertEqual(language.LicenseText, '')
        self.assertTrue(setup.Header.get_license())
        self.assertEqual(setup.wizard_texts(0).license, setup.Header.get_license())

    def test_the_handlers_that_a_script_gives_its_pages_run_when_setup_reaches_the_pages(self):
        """
        The script creates 17 pages and gives each a function that tells whether Setup skips it.
        The pages that are shown also have a function for their activation and one for the Next
        button.
        """
        from refinery.lib.inno.emulation import NewFunctionCall, NewInstruction
        emulator = self._script_emulator(_SCRIPT_WITH_PAGES_OF_ITS_OWN, log_calls=True, log_opcodes=True)
        assigned: dict[str, tuple[object, str]] = {}
        handled: list[tuple[object, str]] = []
        for event in emulator.emulate_installation():
            if isinstance(event, NewFunctionCall) and event.name.startswith('TWizardPage.SetOn'):
                page, handler = event.args
                assigned[handler.name] = (page, event.name.removeprefix('TWizardPage.Set'))
            elif isinstance(event, NewInstruction) and event.offset == 0 and event.function.name in assigned:
                handled.append(assigned[event.function.name])
        pages = {page for page, _ in assigned.values()}
        self.assertEqual(len(pages), 17)
        self.assertEqual({page for page, event in handled if event == 'OnShouldSkipPage'}, pages)
        activations = [k for k, (_, event) in enumerate(handled) if event == 'OnActivate']
        self.assertTrue(activations)
        for k in activations:
            page, _ = handled[k]
            self.assertIn((page, 'OnShouldSkipPage'), handled[:k])
            self.assertEqual(handled[k + 1], (page, 'OnNextButtonClick'))

    def test_an_installation_ends_at_its_time_limit(self):
        from refinery.lib.inno.emulation import EmulatorTimeout
        emulator = self._script_emulator(_SCRIPT_WITH_PAGES_OF_ITS_OWN)
        started = time.process_time()
        with self.assertRaises(EmulatorTimeout):
            for _ in emulator.emulate_installation(max_seconds=0.2):
                pass
        self.assertLess(time.process_time() - started, 1)

    def test_the_password_search_ends_at_its_time_limit(self):
        """
        The script creates a page in `InitializeWizard`, before it writes its password into the
        password box; here, creating the page takes more than a second of processor time.
        """
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import IFPSEmulator
        create_page = IFPSEmulator.external_symbols['']['CreateInputDirPage'].call

        def slow_create_page(*args):
            started = time.process_time()
            while time.process_time() - started < 1.1:
                pass
            return create_page(*args)

        data = self.download_sample(_INSTALLER_THAT_WRITES_ITS_PASSWORD_INTO_THE_PASSWORD_BOX)
        with _replaced_external('CreateInputDirPage', slow_create_page):
            found = {timeout: InnoArchive(data).guess_password(timeout) for timeout in (1, 10)}
        self.assertEqual(found, {1: False, 10: True})

    def test_a_reported_script_error_keeps_no_exception_alive_while_it_is_handled(self):
        import gc
        from refinery.lib.inno.pascal import IFPSException
        from refinery.lib.inno.emulation import NewScriptError

        def exceptions_alive():
            gc.collect()
            return sum(isinstance(item, IFPSException) for item in gc.get_objects())

        emulator = self._script_emulator(_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE)
        with _failing_external('ExtractFileDir'):
            installation = emulator.emulate_installation()
            before = exceptions_alive()
            for event in installation:
                if isinstance(event, NewScriptError):
                    break
            during = exceptions_alive()
            installation.close()
        self.assertEqual(during, before)

    def test_each_setup_event_is_named_as_inno_setup_declares_it(self):
        from refinery.lib.inno.emulation import SetupEvent
        from refinery.lib.inno.symbols import IFPSEvents
        self.assertEqual([IFPSEvents[event].name for event in SetupEvent], [event.value for event in SetupEvent])

    def test_the_emulated_installation_of_each_sample_reports_no_error(self):
        """
        The emulated installation goes on after a script error, and the script can handle the error
        of an emulated function that fails. Such a failure on one of these samples therefore does
        not end the installation and only shows up here.
        """
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.emulation import NewEmulationError, NewScriptError
        from refinery.lib.inno.ifps import IFPSFile
        for sample in _SAMPLES_WHOSE_EMULATED_INSTALLATION_HAS_NO_SCRIPT_ERROR:
            with self.subTest(sample=sample):
                data = self.download_sample(sample)
                script = IFPSFile.Parse(data) if data.startswith(IFPSFile.Magic) else InnoArchive(data)
                events = InnoSetupEmulator(script).emulate_installation()
                errors = [str(event) for event in events if isinstance(event, (NewScriptError, NewEmulationError))]
                self.assertEqual(errors, [])

    def test_a_failing_emulated_function_is_reported_when_the_script_handles_its_error(self):
        from refinery.lib.inno.emulation import NewEmulationError, NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS, log_calls=True)
        with _failing_external('RaiseException'):
            events = list(emulator.emulate_function(emulator.symbols['ORACLECALLERHANDLER']))
        logged = [event.args for event in events if isinstance(event, NewFunctionCall) and event.name == 'Log']
        failures = [event for event in events if isinstance(event, NewEmulationError)]
        self.assertEqual(logged, [
            ('ORACLE CallerMessage = RaiseException failed',),
            ('ORACLE CallerTrace = amfe',),
        ])
        self.assertEqual(failures, [NewEmulationError('RaiseException', 'RaiseException failed')])

    def test_a_failing_emulated_function_without_a_message_is_reported_by_its_error_type(self):
        from refinery.lib.inno.emulation import NewEmulationError

        def fail_without_a_message(*_):
            raise RuntimeError

        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        with _replaced_external('RaiseException', fail_without_a_message):
            events = list(emulator.emulate_function(emulator.symbols['ORACLECALLERHANDLER']))
        self.assertIn(NewEmulationError('RaiseException', 'RuntimeError'), events)

    def test_the_message_that_the_script_reads_of_an_abort_is_a_string(self):
        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        with self.assertRaises(IFPSException) as raised:
            emulator.Abort()
        self.assertIs(type(raised.exception.message), str)

    def test_an_emulated_function_that_writes_beyond_a_record_is_reported_as_a_failure(self):
        """
        The emulated `GetWindowsVersionEx` fills the eight fields of the record it receives; this
        replacement also writes a ninth.
        """
        from refinery.lib.inno.emulation import NewEmulationError

        def write_beyond_the_record(_, version):
            version[8] = 0

        emulator = self._script_emulator(_SCRIPT_WITH_NESTED_TRY)
        with _replaced_external('GetWindowsVersionEx', write_beyond_the_record):
            failures = {event.name for event in emulator.emulate_installation() if isinstance(event, NewEmulationError)}
        self.assertIn('GetWindowsVersionEx', failures)

    def test_an_emulated_function_that_exhausts_the_recursion_of_python_ends_the_emulation(self):
        from refinery.lib.inno.emulation import EmulatorMaxCalls

        def recurse(*arguments):
            return recurse(*arguments)

        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        with _replaced_external('IntToStr', recurse), self.assertRaises(EmulatorMaxCalls) as raised:
            list(emulator.emulate_function(emulator.symbols['ORACLELOOPS']))
        self.assertEqual(str(raised.exception), 'Calling IntToStr exceeded the recursion limit of Python.')

    def test_a_function_that_is_not_emulated_sets_its_last_output_argument_to_one(self):
        """
        During an uninstallation, the script reads a setting into the last argument of
        `RegQueryDWordValue`, which is not emulated, and answers whether that setting is 1.
        """
        emulator = self._script_emulator(_SCRIPT_THAT_READS_A_SETTING_FROM_THE_REGISTRY)
        with _replaced_external('IsUninstaller', lambda _: True):
            setting = emulator.emulate_function(emulator.symbols['GETINSTALLSETTINGBOOL'], 'Some', False).value
        self.assertTrue(setting)

    def test_a_message_argument_is_one_digit_counted_from_one(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.FmtMessage('%1 and %2', ['a', 'b']), 'a and b')
        self.assertEqual(emulator.FmtMessage('%2 of %3', ['a', 'b']), 'b of %3')
        self.assertEqual(emulator.FmtMessage('100%% %10', ['a']), '100% a0')

    def test_a_jump_to_where_no_instruction_starts_ends_the_emulation(self):
        emulator = self._script_emulator(_SCRIPT_THAT_READS_A_SETTING_FROM_THE_REGISTRY)
        function = emulator.symbols['GETINSTALLSETTINGBOOL']
        jump = function.code[0x3E]
        self.assertEqual(jump.operands[0], 0xFA)
        jump.operands[0] = 0xFB
        with self.assertRaises(EmulatorException):
            emulator.emulate_function(function, 'Some', False).value

    def test_a_code_constant_that_expands_itself_ends_the_emulation(self):
        from refinery.lib.inno.emulation import EmulatorMaxCalls
        for config in ({'max_call_stack': 5}, {}):
            emulator = self._script_emulator(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS, **config)
            with self.subTest(**config), self.assertRaises(EmulatorMaxCalls):
                emulator.emulate_function(emulator.symbols['CODERECURSION'], 'x').value

    def _script_with_a_changed_instruction(self, function: str, opcode: int, change: Callable[[bytes], bytes]):
        """
        Parses the script that logs how Pascal Script handles errors after changing the encoding of
        the first instruction of the given opcode in the given function.
        """
        from refinery.lib.inno.ifps import IFPSFile
        data = self.download_sample(_SCRIPT_THAT_LOGS_HOW_PASCAL_SCRIPT_HANDLES_ERRORS)
        body = next(f for f in IFPSFile.Parse(bytearray(data)).functions if f.name == function).body
        assert body is not None
        code = b''.join(instruction.encoded for instruction in body)
        start = data.find(code)
        self.assertGreaterEqual(start, 0)
        self.assertEqual(data.find(code, start + 1), -1)
        instruction = next(instruction for instruction in body if instruction.opcode == opcode)
        offset = start + instruction.offset
        data[offset:offset + instruction.size] = change(instruction.encoded)
        return IFPSFile.Parse(data)

    def test_a_try_statement_without_an_end_ends_the_emulation_before_its_try_block(self):
        """
        The loop of `ORACLELOOPS` adds its counter to the trace of the script and then enters the
        try statement, whose blocks add letters. The trace is the only global variable of the
        script, after the two that Inno Setup declares.
        """
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.ifps import Op
        script = self._script_with_a_changed_instruction(
            'ORACLELOOPS',
            Op.PushEH,
            lambda encoded: encoded[:13] + bytes(4 * [0xFF]),
        )
        emulator = InnoSetupEmulator(script)
        with self.assertRaises(EmulatorException):
            list(emulator.emulate_function(emulator.symbols['ORACLELOOPS']))
        self.assertEqual(emulator.globals[2].get(), '1')

    def test_the_end_of_a_block_whose_try_statement_is_in_another_function_ends_the_emulation(self):
        """
        Without its try statement, the end of the try block in `MESSAGEINSIDETRY` would end a block
        of the try statement in the function that calls it.
        """
        from refinery.lib.inno.emulator import InnoSetupEmulator
        from refinery.lib.inno.ifps import Op
        script = self._script_with_a_changed_instruction(
            'MESSAGEINSIDETRY',
            Op.PushEH,
            lambda encoded: bytes([Op.Nop]) * len(encoded),
        )
        emulator = InnoSetupEmulator(script)
        with self.assertRaises(EmulatorException):
            list(emulator.emulate_function(emulator.symbols['ORACLEMESSAGES']))

    def test_a_declaration_with_parameters_keeps_its_kind(self):
        from refinery.lib.inno.symbols import IFPSClasses, IFPSEvents
        self.assertEqual(IFPSEvents['NextButtonClick'].kind, 'function')
        self.assertEqual(IFPSClasses.Classes['TStrings'].members['Strings'].kind, 'property')

    def test_the_language_that_the_configuration_names_is_active_as_with_the_lang_parameter_of_setup(self):
        """
        The installer has the languages `en`, `de` and `fr`, among others, with the language IDs of
        English, German and French.
        """
        from refinery.lib.inno.archive import InnoArchive
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        archive = InnoArchive(self.download_sample(_INSTALLER_IN_41_LANGUAGES))
        active = {}
        for language, lcid in (('DE', 0x0409), ('none of them', 0x040C), ('none of them', 0x0409)):
            emulator = InnoSetupEmulator(archive, IFPSEmulatorConfig(language=language, lcid=lcid))
            active[language, lcid] = emulator.expand_constant('{language}')
        self.assertEqual(active, {
            ('DE', 0x0409): 'de',
            ('none of them', 0x040C): 'fr',
            ('none of them', 0x0409): 'en',
        })

    def test_the_system_folders_of_a_64_bit_windows_are_those_that_a_32_bit_setup_sees(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, x64=True)
        windows = emulator.expand_constant('{win}')
        self.assertEqual(
            [emulator.expand_constant(constant) for constant in ('{sys}', '{sysnative}', '{syswow64}')],
            [F'{windows}\\System32', F'{windows}\\Sysnative', F'{windows}\\SysWOW64'],
        )
        self.assertEqual(ntpath.dirname(emulator.expand_constant('{cmd}')), emulator.expand_constant('{sys}'))

    def test_the_native_system_folder_of_a_32_bit_windows_is_its_system_folder(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, x64=False)
        self.assertEqual(emulator.expand_constant('{sysnative}'), emulator.expand_constant('{sys}'))

    def test_a_closing_brace_outside_of_a_constant_is_kept(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.expand_constant('a}b'), 'a}b')

    @wontfix('no script nests a constant hundreds of levels deep; the emulation ends at the recursion limit of Python')
    def test_a_constant_nested_a_thousand_levels_deep_expands_to_its_innermost_default(self):
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.expand_constant('{%NOSUCHVARIABLE|' * 1000 + 'z' + '}' * 1000), 'z')

    def test_an_index_outside_of_an_array_raises_an_error_that_the_script_handles(self):
        """
        The script sizes an array with `SetArrayLength` and stores into its first element, inside a
        try block whose except block returns False.
        """
        emulator = self._script_emulator(_SCRIPT_THAT_LISTS_PROCESSES_IN_A_TRY_BLOCK)
        with _replaced_external('SetArrayLength', lambda *_: None):
            self.assertFalse(emulator.emulate_function(emulator.symbols['IPR'], 'explorer.exe').value)

    def _messages_of_a_failed_download(self, error_code: int) -> list[str]:
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD, log_calls=True)
        with (
            _failing_method('TDownloadWizardPage', 'Download', 1),
            _replaced_external('GetLastError', lambda _: error_code, namespace='kernel32'),
        ):
            call = emulator.emulate_function(emulator.symbols['DOWNLOADFILE'], 'url', 'path')
            return [event.args[0] for event in call if isinstance(event, NewFunctionCall) and event.name == 'Log']

    def test_a_negative_error_code_is_formatted_in_hex_as_its_bit_pattern(self):
        *_, message = self._messages_of_a_failed_download(0x80072EE7)
        self.assertIn('failed with code -2147012889 (0x80072EE7)', message)

    def test_a_negative_error_code_gets_the_description_of_its_bit_pattern(self):
        *_, message = self._messages_of_a_failed_download(0x80072EE7)
        description = self._script_emulator(_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD).SysErrorMessage(0x80072EE7)
        self.assertTrue(message.endswith(description))

    def test_a_script_for_an_older_inno_setup_calls_string_change_without_a_result(self):
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_FOR_AN_OLDER_INNO_SETUP, log_calls=True)
        changes = [
            event.args[1:] for event in emulator.emulate_installation()
            if isinstance(event, NewFunctionCall) and event.name == 'StringChange'
        ]
        self.assertEqual(set(changes), {('\\', '/')})

    def test_an_emulated_com_property_is_unassigned(self):
        """
        The script reads the `Status` and `StatusText` of an emulated HTTP request, which answer
        Unassigned; Delphi converts Unassigned to 0 and to the empty string.
        """
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, log_calls=True)
        call = emulator.emulate_function(emulator.symbols['GETADSERVERRESPONSE'])
        logged = [event.args for event in call if isinstance(event, NewFunctionCall) and event.name == 'Log']
        self.assertEqual(logged[-1], ('HTTP Error: 0 ',))
        self.assertFalse(call.value)

    def test_every_wmi_query_of_a_script_is_in_the_call_log(self):
        """
        The emulated WMI locator answers its `ConnectServer` call with Unassigned, so the script
        sends each query to a nil service object, which raises an error that the script handles.
        """
        from refinery.lib.inno.emulation import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_THAT_LISTS_PROCESSES_IN_A_TRY_BLOCK, log_calls=True)
        calls = [
            event.args for event in emulator.emulate_installation()
            if isinstance(event, NewFunctionCall) and event.name == 'IDispatchInvoke' and event.args[2] == 'ExecQuery'
        ]
        self.assertEqual({service for service, *_ in calls}, {None})
        self.assertEqual([arguments[0].value for *_, arguments in calls], [
            'SELECT NumberOfCores FROM Win32_Processor',
            'SELECT TotalPhysicalMemory FROM Win32_ComputerSystem',
            'SELECT * FROM Win32_SystemDriver',
            'SELECT Caption FROM Win32_Process WHERE NOT Caption IS NULL',
            'SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE \'%PNP0F13%\' AND DeviceID LIKE \'%22F5829E%\'',
            'SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE \'%PNP0303%\' AND DeviceID LIKE \'%22F5829E%\'',
            'SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE \'%RHT1234%\' AND DeviceID LIKE \'%22F5829E%\'',
            'SELECT Name FROM Win32_Processor',
            'SELECT Name FROM Win32_Service WHERE Name="A3E64E56_fl"',
        ])

    def test_an_installer_built_before_inno_setup_6_4_3_does_not_mask_float_errors(self):
        """
        Delphi sets the control word `$1332` before Delphi 12, which builds Inno Setup from 6.4.3 on.
        The x87 reports its reserved bit `$40` as set.
        """
        self.assertEqual(self._installer_emulator().Get8087CW(), 0x1372)

    def test_the_sine_of_pi_is_that_of_the_x87(self):
        """
        The x87 subtracts its pi of 66 bits from the Double nearest to pi, which leaves
        1.2246063538223773e-16 instead of the exact sine 1.2246467991473532e-16.
        """
        import math
        from refinery.lib.inno.delphi.x87 import Format
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.runtime.fpu.store(emulator.Sin(math.pi), Format.Double), 1.2246063538223773e-16)

    def test_the_language_id_of_the_machine_selects_the_regional_format_of_windows(self):
        from refinery.lib.inno.delphi.numbers import FormatSettings
        german = FormatSettings.of_locale(0x0407)
        english = FormatSettings.of_locale(0x0409)
        self.assertEqual((german.decimal_separator, german.thousand_separator, german.currency_string), (',', '.', '\u20ac'))
        self.assertEqual((english.decimal_separator, english.thousand_separator, english.currency_string), ('.', ',', '$'))

    def test_an_extended_that_overflows_the_double_of_a_variant_raises_an_error_of_the_script(self):
        from refinery.lib.inno import pascal
        from refinery.lib.inno.delphi import x87
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win32
        from refinery.lib.inno.ifps import TC, Dialect, TPrimitive
        machine = pascal.Machine(Dialect.Inno6, Win32(FormatSettings(), x87.DEFAULT_CONTROL_WORD))
        with self.assertRaises(IFPSException) as raised:
            pascal.store(TPrimitive(TC.Variant), TPrimitive(TC.Extended), x87.real(1, 5000), machine)
        self.assertEqual(raised.exception.kind, pascal.PSError.MathError)

    def test_a_double_beyond_the_range_of_a_currency_in_a_comparison_raises_an_error_of_the_script(self):
        from fractions import Fraction
        from refinery.lib.inno import pascal
        from refinery.lib.inno.delphi import x87
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win32
        from refinery.lib.inno.ifps import TC, COp, Dialect, TPrimitive
        machine = pascal.Machine(Dialect.Inno6, Win32(FormatSettings(), x87.DEFAULT_CONTROL_WORD))
        with self.assertRaises(IFPSException):
            pascal.compare(COp.LT, TPrimitive(TC.Currency), Fraction(1), TPrimitive(TC.Double), 1e300, machine)

    def test_a_64_bit_setup_reads_an_int64_operand_as_a_double_before_it_computes(self):
        """
        Pascal Script reads the operand with `PSGetReal`, whose Extended is a Double in 64-bit code.
        """
        from refinery.lib.inno import pascal
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win64
        from refinery.lib.inno.ifps import TC, AOp, COp, Dialect, TPrimitive
        machine = pascal.Machine(Dialect.Inno7, Win64(FormatSettings()))
        double = TPrimitive(TC.Double)
        int64 = TPrimitive(TC.S64)
        # 2**53 + 1 rounds to the Double 2**53, and 2**53 + 0.5 rounds to 2**53 as well.
        self.assertEqual(pascal.calculate(AOp.Add, double, 0.5, int64, 2 ** 53 + 1, machine), 2.0 ** 53)
        self.assertTrue(pascal.compare(COp.EQ, double, 2.0 ** 53, int64, 2 ** 53 + 1, machine))

    def test_a_64_bit_setup_converts_an_int64_variant_to_a_double_before_it_computes(self):
        from refinery.lib.inno.delphi import variants
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win64
        from refinery.lib.inno.delphi.variants import Variant, VarType
        runtime = Win64(FormatSettings())
        result = variants.operate(
            variants.Operator.Add,
            Variant(VarType.Double, 0.5),
            Variant(VarType.Int64, 2 ** 53 + 1),
            runtime,
        )
        # 2**53 + 1 rounds to the Double 2**53, and 2**53 + 0.5 rounds to 2**53 as well.
        self.assertEqual(result, Variant(VarType.Double, 2.0 ** 53))

    def test_a_64_bit_setup_compares_two_int64_variants_as_integers(self):
        from refinery.lib.inno.delphi import variants
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win64
        from refinery.lib.inno.delphi.variants import Variant, VarType
        runtime = Win64(FormatSettings())
        order = variants.compare(Variant(VarType.Int64, 2 ** 53), Variant(VarType.Int64, 2 ** 53 + 1), runtime)
        self.assertEqual(order, -1)

    def test_64_bit_windows_reads_digits_without_exponent_beyond_a_double_as_an_infinity_after_a_currency_string_with_an_e(self):
        """
        The currency string of Romanian (Romania) is `lei`; the number has no exponent.
        """
        import math
        from refinery.lib.inno.delphi import variants
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win64
        from refinery.lib.inno.delphi.variants import Variant, VarType
        runtime = Win64(FormatSettings.of_locale(0x0418))
        self.assertEqual(variants.to_real(Variant(VarType.OleStr, F'{"1" * 310} lei'), runtime), math.inf)

    def test_a_64_bit_currency_quotient_beyond_the_range_of_a_currency_ends_the_emulation(self):
        from fractions import Fraction
        from refinery.lib.inno.delphi.errors import Undefined
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Operation, Win64
        runtime = Win64(FormatSettings())
        with self.assertRaises(Undefined):
            runtime.currency_arithmetic(Operation.Divide, Fraction(922337203685477), Fraction(1, 10000))

    def test_an_int64_beyond_the_range_of_a_currency_raises_an_invalid_operation_before_inno_setup_6_4_3(self):
        """
        The x87 converts the Int64 to a Currency; the control word `$1332` does not mask invalid
        operations.
        """
        from refinery.lib.inno import pascal
        from refinery.lib.inno.delphi import x87
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win32
        from refinery.lib.inno.ifps import TC, Dialect, TPrimitive
        machine = pascal.Machine(Dialect.Inno6, Win32(FormatSettings(), x87.DEFAULT_CONTROL_WORD))
        with self.assertRaises(IFPSException) as raised:
            pascal.store(TPrimitive(TC.Currency), TPrimitive(TC.S64), 10 ** 16, machine)
        self.assertEqual(raised.exception.kind, pascal.PSError.MathError)

    def test_a_comparison_writes_one_into_a_uint64_from_inno_setup_7_on(self):
        """
        The compiler of Inno Setup 7 casts `Ord` to a UInt64, and its Pascal Script writes the result
        of a comparison into 64-bit integers.
        """
        from refinery.lib.inno import pascal
        from refinery.lib.inno.delphi import x87
        from refinery.lib.inno.delphi.numbers import FormatSettings
        from refinery.lib.inno.delphi.runtime import Win32
        from refinery.lib.inno.ifps import TC, Dialect, TPrimitive
        runtime = Win32(FormatSettings(), x87.MASKED_CONTROL_WORD)
        self.assertEqual(pascal.boolean(TPrimitive(TC.U64), True, pascal.Machine(Dialect.Inno7, runtime)), 1)
        with self.assertRaises(IFPSException):
            pascal.boolean(TPrimitive(TC.U64), True, pascal.Machine(Dialect.Inno6, runtime))

    def test_the_sine_of_negative_zero_in_a_64_bit_setup_is_negative_zero(self):
        from refinery.lib.inno.delphi import x87
        sine = x87.SSE().sine(-0.0)
        self.assertEqual(sine, 0.0)
        self.assertTrue(x87.is_negative(sine))

    def test_a_currency_that_python_code_gives_a_variant_is_a_currency(self):
        from fractions import Fraction
        from refinery.lib.inno.delphi.variants import VarType, from_python
        self.assertEqual(from_python(Fraction(3, 2)).type, VarType.Currency)

    def test_a_currency_constant_is_shown_as_its_decimal_text(self):
        from fractions import Fraction
        from refinery.lib.inno.ifps import TC, TPrimitive, Value
        self.assertEqual(str(Value(TPrimitive(TC.Currency), Fraction(-3, 2))), '-1.5')

    def test_separators_between_quotes_do_not_count_toward_the_array_limit_of_a_split(self):
        from refinery.lib.inno.emulator import TSplitType
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, max_array_length=3)
        self.assertEqual(emulator.StringSplitEx('a,"b,c,d",e', [','], '"', TSplitType.stAll), ['a', '"b,c,d"', 'e'])

    def test_excluded_empty_parts_do_not_count_toward_the_array_limit_of_a_split(self):
        from refinery.lib.inno.emulator import TSplitType
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, max_array_length=3)
        self.assertEqual(emulator.StringSplitEx('a,,,,,,b', [','], '', TSplitType.stExcludeEmpty), ['a', 'b'])

    def test_an_exact_denormal_result_raises_an_unmasked_underflow(self):
        from refinery.lib.inno.delphi import x87
        from refinery.lib.inno.delphi.errors import EUnderflow
        fpu = x87.FPU(x87.MASKED_CONTROL_WORD & ~x87.Fault.Underflow)
        with self.assertRaises(EUnderflow):
            fpu.multiply(x87.real(1, -16000), x87.real(1, -400))

    def test_a_global_resource_pointer_starts_as_nil(self):
        from refinery.lib.inno.ifps import TC
        emulator = self._script_emulator(_SCRIPT_WITH_A_GLOBAL_RESOURCE_POINTER)
        self.assertEqual([v.type.code for v in emulator.globals], [TC.ResourcePointer])
        self.assertIsNone(emulator.globals[0].get())
        list(emulator.emulate_installation())

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='StringOfChar keeps the whole character; Pascal Script keeps its low byte as an ANSI character',
    )
    def test_string_of_char_repeats_the_low_byte_of_the_character_as_an_ansi_character(self):
        """
        Pascal Script reads the character as an integer and casts it to an `AnsiChar`, which keeps
        the low byte $AC of the euro sign; the code page 1252 of English (United States) reads it
        as the sign of negation.
        """
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY)
        self.assertEqual(emulator.StringOfChar('\u20ac', 2), '\u00ac\u00ac')
