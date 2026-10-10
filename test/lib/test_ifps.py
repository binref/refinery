import contextlib
import pytest

from unittest import mock

from .. import TestBase

_SCRIPT_WITH_NESTED_TRY = '453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc'
_SCRIPT_WITH_TRY_FINALLY = 'ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf'


@contextlib.contextmanager
def _failing_external(name: str):
    """
    Makes the emulated external function of the given name raise an error.
    """
    from refinery.lib.inno.emulator import IFPSEmulator
    registry = IFPSEmulator.external_symbols['']

    def fail(*_):
        raise RuntimeError(F'{name} failed')

    with mock.patch.dict(registry, {name: registry[name]._replace(call=fail)}):
        yield


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

    def test_an_exception_handler_of_a_script_runs_on_the_stack_of_its_try_block(self):
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator, NewFunctionCall
        from refinery.lib.inno.ifps import IFPSFile
        data = self.download_sample('ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf')
        emulator = InnoSetupEmulator(IFPSFile.Parse(data), IFPSEmulatorConfig(log_calls=True))
        call = emulator.emulate_function(emulator.symbols['GETADSERVERRESPONSE'])
        logged = [event.args for event in call if isinstance(event, NewFunctionCall) and event.name == 'Log']
        self.assertEqual(logged, [('Failed to get configuration',)])
        self.assertFalse(call.value)

    def _emulated_value(self, sample: str, function: str, **config):
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.ifps import IFPSFile
        emulator = InnoSetupEmulator(IFPSFile.Parse(self.download_sample(sample)), IFPSEmulatorConfig(**config))
        call = emulator.emulate_function(emulator.symbols[function])
        for _ in call:
            pass
        return call.value

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
        from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
        from refinery.lib.inno.ifps import IFPSFile
        emulator = InnoSetupEmulator(IFPSFile.Parse(self.download_sample(_SCRIPT_WITH_TRY_FINALLY)), IFPSEmulatorConfig())
        emulator.globals[16].set('session')
        call = emulator.emulate_function(emulator.symbols['GETSESSIONID'])
        for _ in call:
            pass
        self.assertEqual(call.value, 'session')
