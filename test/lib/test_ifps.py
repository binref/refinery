import contextlib

from .. import TestBase


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
        from refinery.lib.inno.ifps import FunctionReference, IFPSFile, Operand
        ifps = IFPSFile.Parse(self.download_sample('ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf'))
        by_function: dict[int, list[FunctionReference]] = {}
        for function in ifps.functions:
            for instruction in function.body or ():
                for operand in instruction.operands:
                    if not isinstance(operand, Operand) or (value := operand.value) is None:
                        continue
                    if isinstance(reference := value.value, FunctionReference):
                        by_function.setdefault(id(reference.function), []).append(reference)
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
