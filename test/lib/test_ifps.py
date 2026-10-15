import contextlib
import pytest
import time

from typing import Callable
from unittest import mock

from refinery.lib.inno.emulator import EmulatorException

from .. import TestBase

_SCRIPT_WITH_NESTED_TRY = '453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc'
_SCRIPT_WITH_TRY_FINALLY = 'ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf'
_SCRIPT_THAT_NAMES_HRESULTS = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_SLEEPS = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_THAT_WRITES_NUMBERS_IN_HEX = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_PRINTS_JSON = _SCRIPT_WITH_TRY_FINALLY
_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE = _SCRIPT_WITH_NESTED_TRY
_SCRIPT_FOR_AN_OLDER_INNO_SETUP = '2d3f393969037a0d0f19e1e01637bed00e0d766fafbb8916a2f6d0b1f8d4cdcd'
_INSTALLER_THAT_STRIPS_ACCELERATOR_KEYS = 'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c'
_INSTALLER_WITH_A_DIRECTORY_PAGE = 'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42'


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
    that raises an error.
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
        from refinery.lib.inno.emulator import IFPSEmulator, IFPSException
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

    def test_an_exception_handler_of_a_script_runs_on_the_stack_of_its_try_block(self):
        from refinery.lib.inno.emulator import NewFunctionCall
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

    @pytest.mark.xfail(strict=True, reason='an exception does not leave a script function for a handler of its caller')
    def test_an_exception_in_a_called_function_runs_the_handler_of_its_caller(self):
        windows = self._emulated_value(_SCRIPT_WITH_NESTED_TRY, 'GETWINDOWSDIR')
        with _failing_external('CompareText'):
            temp = self._emulated_value(_SCRIPT_WITH_NESTED_TRY, 'GETWINDOWSTEMPDIR')
        self.assertEqual(temp, F'{windows}\temp')

    @pytest.mark.xfail(strict=True, reason='an exception inside a catch block enters the same catch block again')
    def test_an_exception_in_a_catch_block_leaves_the_function(self):
        from refinery.lib.inno.emulator import IFPSException
        with _failing_external('Log'), self.assertRaises(IFPSException):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE', max_seconds=2)

    @pytest.mark.xfail(strict=True, reason='a try block with a finally block swallows the exception')
    def test_an_exception_in_a_try_block_leaves_the_function_after_its_finally_block(self):
        from refinery.lib.inno.emulator import IFPSException
        with _failing_external('GetDateTimeString'), self.assertRaises(IFPSException):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETSESSIONID')

    @pytest.mark.xfail(strict=True, reason='an exit from a try block skips its finally block')
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
        from refinery.lib.inno.emulator import PageID
        emulator = self._installer_emulator()
        byte_list = emulator.globals[60]
        self.assertEqual(len(byte_list), 0)
        list(emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpWelcome))
        self.assertEqual(len(byte_list), 256)

    def test_a_list_longer_than_the_configured_limit_ends_the_emulation(self):
        from refinery.lib.inno.emulator import EmulatorMaxArray, PageID
        emulator = self._installer_emulator(max_array_length=255)
        with self.assertRaises(EmulatorMaxArray):
            list(emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpWelcome))
        self.assertEqual(len(emulator.globals[60]), 0)

    def test_a_script_cannot_handle_a_list_longer_than_the_configured_limit(self):
        from refinery.lib.inno.emulator import EmulatorMaxArray
        with self.assertRaises(EmulatorMaxArray):
            self._emulated_value(_SCRIPT_WITH_TRY_FINALLY, 'GETADSERVERRESPONSE', max_array_length=1)

    def test_an_abort_ends_the_emulation_when_the_configuration_asks_for_it(self):
        from refinery.lib.inno.emulator import AbortEmulation
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
        from refinery.lib.inno.emulator import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, log_calls=True)
        report = emulator.emulate_function(emulator.symbols['SENDREPORT'], '', '', '', '', [])
        formatted = [event.args for event in report if isinstance(event, NewFunctionCall) and event.name == 'Format']
        self.assertIn(('%s.%s.%s.%s', ['1', '34', '2', '8157']), formatted)

    def test_a_reset_restores_the_globals_that_a_script_changed(self):
        from refinery.lib.inno.emulator import PageID
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
            if namespace in modules:
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

    @pytest.mark.xfail(
        strict=True,
        raises=EmulatorException,
        reason='a script function that expands a code constant clears the stack of its caller',
    )
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

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='an Inno Setup declaration replaces the declaration of a script function of the same name',
    )
    def test_a_script_function_named_like_an_inno_function_keeps_its_own_declaration(self):
        function = self._installer_emulator().symbols['IsDotNetInstalled']
        assert function.decl is not None
        self.assertEqual(function.decl.parameters, [])

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='an Inno Setup declaration renames the types of a script function of the same name',
    )
    def test_a_type_is_only_named_cardinal_when_it_is_an_unsigned_32_bit_integer(self):
        from refinery.lib.inno.ifps import TC
        emulator = self._installer_emulator()
        for type in emulator.ifps.types:
            if str(type) == 'Cardinal':
                self.assertEqual(type.code, TC.U32)

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='a declared String resolves to the first string type of the script')
    def test_a_unicode_script_reads_a_declared_string_as_a_unicode_string(self):
        from refinery.lib.inno.ifps import TC
        decl = self._installer_emulator().symbols['Copy'].decl
        assert decl is not None and decl.return_type is not None
        self.assertEqual(decl.return_type.code, TC.UnicodeString)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='when a script reads and writes a property, its reader is named Set and its writer Get',
    )
    def test_a_file_placed_in_a_directory_from_a_wizard_page_keeps_that_directory(self):
        from refinery.lib.inno.archive import InnoArchive
        inno = InnoArchive(self.download_sample(_INSTALLER_WITH_A_DIRECTORY_PAGE))
        self.assertEqual(inno.files[0].path, 'data/$InputDir0/HalfTime.dll')

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
        with _failing_method('TDownloadWizardPage', 'Download', 0), _replaced_external('Format', record, spec=[False, True]):
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
        For the page that selects the target directory, `ShouldSkipPage` ends with the call
        `DirExistsNoRedir(ExtractFileDir(..))`. When `ExtractFileDir` fails, Inno Setup shows the
        error and does not skip the page, which is also the answer of the script without the error.
        """
        from refinery.lib.inno.emulator import NewFunctionCall, NewScriptError, PageID

        def calls_and_errors(events):
            return [
                event.name if isinstance(event, NewFunctionCall) else event
                for event in events if isinstance(event, (NewFunctionCall, NewScriptError))
            ]

        def installation():
            emulator = self._script_emulator(_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE, log_calls=True)
            return calls_and_errors(emulator.emulate_installation())

        clean = installation()
        with _failing_external('ExtractFileDir'):
            failed = installation()
        emulator = self._script_emulator(_SCRIPT_THAT_EXTRACTS_A_DIRECTORY_TO_SKIP_A_PAGE, log_calls=True)
        unreached = calls_and_errors(emulator.emulate_function(emulator.symbols['DIREXISTSNOREDIR'], ''))
        errors = [event for event in failed if isinstance(event, NewScriptError)]
        self.assertEqual([(error.name, error.args) for error in errors], [('ShouldSkipPage', (PageID.wpSelectDir,))])
        k = failed.index(errors[0])
        # names only: two clean runs differ in time stamps and random numbers, never in the calls
        self.assertEqual(failed[:k] + unreached + failed[k + 1:], clean)

    def _messages_of_a_failed_download(self, error_code: int) -> list[str]:
        from refinery.lib.inno.emulator import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_THAT_LOGS_A_FAILED_DOWNLOAD, log_calls=True)
        with (
            _failing_method('TDownloadWizardPage', 'Download', 0),
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

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='a call is read with the declaration of the current Inno Setup, where StringChange returns a value',
    )
    def test_a_script_for_an_older_inno_setup_calls_string_change_without_a_result(self):
        from refinery.lib.inno.emulator import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_FOR_AN_OLDER_INNO_SETUP, log_calls=True)
        changes = [
            event.args[1:] for event in emulator.emulate_installation()
            if isinstance(event, NewFunctionCall) and event.name == 'StringChange'
        ]
        self.assertEqual(set(changes), {('\\', '/')})

    @pytest.mark.xfail(
        strict=True,
        raises=EmulatorException,
        reason='an operation on values of mismatched types ends the emulation instead of raising a script exception',
    )
    def test_a_type_mismatch_in_a_try_block_runs_its_except_block(self):
        """
        The emulated COM object answers its `StatusText` property with 0, which the script adds to a
        string. Pascal Script raises this type mismatch as an exception that the script can handle.
        """
        from refinery.lib.inno.emulator import NewFunctionCall
        emulator = self._script_emulator(_SCRIPT_WITH_TRY_FINALLY, log_calls=True)
        call = emulator.emulate_function(emulator.symbols['GETADSERVERRESPONSE'])
        logged = [event.args for event in call if isinstance(event, NewFunctionCall) and event.name == 'Log']
        self.assertEqual(logged[-1], ('Failed to get configuration',))
        self.assertFalse(call.value)
