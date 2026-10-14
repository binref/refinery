import codecs
import pytest
import re

from refinery.lib.inno.archive import InnoArchive
from refinery.lib.inno.emulator import (
    EmulatorException,
    IFPSEmulatorConfig,
    IFPSException,
    InnoSetupEmulator,
    NewFunctionCall,
)
from refinery.lib.inno.ifps import Operand

from .. import TestBase

_INSTALLER = '0f294be9f6ce0207e538c859a8e7e0dab2a887c4913396c9768b048d3f9e0ddc'
_INSTALLER_LOG = '3c781880fb796b1233b7d4d8e40d7e9f0326abb63b06661537605c9b61adeb32'
_ORACLE_LINE = re.compile(r'ORACLE (\S+) = (.*)')


class TestTheEmulatorLogsWhatInnoSetupLogged(TestBase):
    """
    The installer was built with Inno Setup 6.5.0 from a script whose procedures log values that
    Pascal Script computes, one procedure per area. The installer ran on Windows with a log file.
    Each test emulates one procedure and compares every value it logs with the value in that log.
    """

    def _real_values(self) -> dict[str, str]:
        log = codecs.decode(self.download_sample(_INSTALLER_LOG), 'utf-8-sig')
        return {match[1]: match[2] for line in log.splitlines() if (match := _ORACLE_LINE.search(line))}

    def assertEmulatedAsLogged(self, procedure: str):
        emulator = InnoSetupEmulator(InnoArchive(self.download_sample(_INSTALLER)), IFPSEmulatorConfig(log_calls=True))
        function = emulator.symbols[procedure]
        constants = {
            value
            for instruction in function.body or ()
            for operand in instruction.operands
            if isinstance(operand, Operand)
            and operand.value is not None
            and isinstance(value := operand.value.value, str)
        }
        real = {name: value for name, value in self._real_values().items() if name in constants}
        emulated = {}
        for event in emulator.emulate_function(function):
            if (
                isinstance(event, NewFunctionCall)
                and event.name == 'Log'
                and (match := _ORACLE_LINE.fullmatch(event.args[0]))
            ):
                emulated[match[1]] = match[2]
        self.assertTrue(real)
        self.assertEqual(emulated, real)

    @pytest.mark.xfail(
        strict=True, raises=AssertionError, reason='a signed integer variable holds the unsigned bit pattern of a negative value'
    )
    def test_stores(self):
        self.assertEmulatedAsLogged('ORACLESTORES')

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='a signed integer that overflows holds a value outside its range')
    def test_arithmetic(self):
        self.assertEmulatedAsLogged('ORACLEARITHMETIC')

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='div and mod round toward negative infinity instead of toward zero')
    def test_division(self):
        self.assertEmulatedAsLogged('ORACLEDIVISION')

    @pytest.mark.xfail(
        strict=True, raises=EmulatorException, reason='shr shifts in sign bits and a negative shift count ends the emulation'
    )
    def test_shifts(self):
        self.assertEmulatedAsLogged('ORACLESHIFTS')

    @pytest.mark.xfail(
        strict=True, raises=AssertionError, reason='an Integer and a Cardinal with the same bit pattern compare as different numbers'
    )
    def test_comparisons(self):
        self.assertEmulatedAsLogged('ORACLECOMPARISONS')

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='an Integer compared with a Currency does not raise')
    def test_comparisons_of_an_integer_with_a_currency_and_a_variant(self):
        self.assertEmulatedAsLogged('ORACLEMIXEDCOMPARISONS')

    def test_float_constants(self):
        self.assertEmulatedAsLogged('ORACLECONSTANTS')

    def test_format(self):
        self.assertEmulatedAsLogged('ORACLEFORMAT')

    @pytest.mark.xfail(strict=True, raises=IFPSException, reason='floats are not converted to text as Delphi converts them')
    def test_floats(self):
        self.assertEmulatedAsLogged('ORACLEFLOATS')

    @pytest.mark.xfail(strict=True, raises=EmulatorException, reason='in on a set ends the emulation')
    def test_sets(self):
        self.assertEmulatedAsLogged('ORACLESETS')

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='a Boolean holding 2 is false')
    def test_booleans(self):
        self.assertEmulatedAsLogged('ORACLEBOOLEANS')

    @pytest.mark.xfail(strict=True, raises=EmulatorException, reason='Variant operators follow Python instead of Delphi')
    def test_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTS')
