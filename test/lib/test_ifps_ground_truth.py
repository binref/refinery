import codecs
import pytest
import re
import sys
import tracemalloc

from itertools import zip_longest
from typing import Iterable
from unittest import mock

from fractions import Fraction

from refinery.lib.inno.archive import (
    Architecture,
    AutoBool,
    Flags,
    InnoArchive,
    PrivilegesRequired,
    SetupDirective,
    SetupFileFlags,
    SetupFileType,
    SetupMessageName,
    SetupRunFlags,
    SetupTypeEnum,
    TextDirective,
    YesNoDirective,
)
from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.emulation import (
    EmulatorMaxArray,
    EmulatorMaxCalls,
    EmulatorMaxString,
    EmulatorUndefined,
    EntryField,
    EntryLocation,
    EntryParameter,
    EntrySection,
    InternalError,
    NewEmulationError,
    NewFunctionCall,
    NewScriptError,
)
from refinery.lib.inno.emulator import IFPSEmulator, IFPSEmulatorConfig, InnoSetupEmulator
from refinery.lib.inno.ifps import TC, AOp, DeclSpecParam, Dialect, Function, IFPSFile, Op, Operand, Value
from refinery.lib.inno.pascal import IFPSException
from refinery.lib.inno.wizard import PageID, TextBox
from refinery.lib.types import buf
from refinery.lib.un7z import SzArchive

from .. import TestBase, wontfix

_ORACLE_LINE = re.compile(r'ORACLE (\S+) = (.*)')
_MESSAGE_REFERENCE = re.compile(r'!(\d+)')
_VALUE_ORACLE = '2925fbf3b9181fec5e7af99418388e386aa1991fe9b0ae895f44f2f686d1ce1c'
"""
A 7-Zip archive of three builds of one value oracle: for each build, the compiled script and the
`ORACLE` lines of the log of its run. Inno Setup 6.5.0 built `inno6`, Inno Setup 7.1.0 built `x86`
as a 32-bit Setup and `x64` as a 64-bit Setup.
"""


def _archived_file(test: TestBase, archive: str, name: str) -> buf:
    for file in SzArchive(test.download_sample(archive)).files:
        if file.name == name:
            return file.extractor(None)()
    raise LookupError(name)


def _value_oracle_file(test: TestBase, build: str, extension: str) -> buf:
    return _archived_file(test, _VALUE_ORACLE, F'value-oracle-7c-{build}.{extension}')


_ERROR_SCRIPT = '9e3618e159e10f5344b35e9cbdabf9d234c46aa4c33ab65905b18cf2e9d3f451'
_ERROR_LOG = {
    'CallerMessage'            : 'deep',
    'CallerTrace'              : 'amfe',
    'ExceptBlockMessage'       : 'second',
    'ExceptBlockTrace'         : 'aeo',
    'FinallyMessage'           : 'passing',
    'FinallyTrace'             : 'afe',
    'FinallyRaisesMessage'     : 'second',
    'FinallyRaisesTrace'       : 'afe',
    'ExitFinallyResult'        : '99',
    'ExitFinallyTrace'         : 'afy',
    'ExitExceptResult'         : '2',
    'ExitExceptTrace'          : 'a',
    'ExitCallingFinallyResult' : '102',
    'ExitCallingFinallyTrace'  : 'afy',
    'ExceptFinallyQuiet'       : 'abfy',
    'ExceptFinallyRaised'      : 'aefy',
    'FinallyExceptQuiet'       : 'abfy',
    'FinallyExceptRaised'      : 'afey',
    'SecondFinallyMessage'     : 'in finally',
    'SecondFinallyTrace'       : 'affo',
    'BreakFinallyTrace'        : '1tfn2fn3tfny',
    'BreakExceptTrace'         : '1tn2n3tny',
    'ContinueFinallyTrace'     : '1tfn2fn3tfny',
    'DynamicIndexMessage'      : 'Out Of Range',
    'StaticIndexMessage'       : 'Out Of Range',
    'NegativeIndexMessage'     : 'Out Of Range',
    'DivisionMessage'          : 'Division by zero',
    'ModuloMessage'            : 'Division by zero',
    'OverflowMessage'          : 'Integer overflow',
    'InvalidFloatTrace'        : 'n',
    'FloatDivisionTrace'       : 'n',
    'MessageWithoutException'  : '(There is no current exception)',
    'MessageAfterHandled'      : '(There is no current exception)',
    'MessageInner'             : 'inner',
    'MessageOuterAfterInner'   : 'outer',
    'MessageInCallee'          : 'seen by callee',
    'MessageInsideCalleeTry'   : '(There is no current exception)',
    'QuietExitResult'          : '12',
    'QuietExitTrace'           : 'af',
    'TwoFinalliesExitResult'   : '1',
    'TwoFinalliesExitTrace'    : 'afg',
    'ExitInsideFinallyMessage' : 'kept in flight',
    'ExitInsideFinallyTrace'   : 'fco',
    'MessageInFinally'         : '(There is no current exception)',
    'CodeInFinallyTrace'       : 'fyc',
    'CodeSeesMessage'          : 'seen by code',
    'CodeLogged'               : 'z',
    'CodeLogsValue'            : 'z',
    'AbortMessage'             : 'Operation aborted',
    'AbortTrace'               : 'e',
    'CodeValue'                : 'code:x',
    'CodeKeepsLocals'          : 'kept',
    'CodeFailsMessage'         : 'code failed: y',
    'CodeFailsTrace'           : 'ae',
    'End'                      : 'reached',
    'DeinitializeSetup'        : 'entered',
}

_HOST_ORACLE = '4f43e9adcaa9885af020444b74f9ed9bb32f207d60ae7e1192af422e1b3a9e9a'
"""
A 7-Zip archive of an installer that Inno Setup 6.5.0 built, `host-oracle-6.exe`, whose script logs
the events that Setup sends, the values that Setup gives the script, the calls of the script that
Setup makes for its entries, and Setup's texts, paths and wizard; with the `ORACLE` lines of the
logs of two runs from a folder on the drive `W:` of 64-bit Windows, installing for the current
user: `host-oracle-6-normal.log` clicked Next on every page of the wizard,
`host-oracle-6-silent.log` ran silently. `host-oracle-6-run2.ifps` is the compiled script of a
second build whose `CheckSerial` also raises an error while the script writes the serial and which
changes the `CharCase` of a box; `host-oracle-6-run2-normal.log` is the log of its run with the
wizard.
"""
_HOST_EVENT = re.compile(r'Event\d+')
_HOST_VALUES_THAT_ARE_NOT_EMULATED = frozenset({
    'ConstEnvMissing',
    'ConstSys',
    'ConstSysNative',
    'ConstSysWow64',
    'ProgressCalls',
    'ProgressLast',
})
"""
The values that the host oracle logged of the machine that it ran on, which the emulated machine
does not share: a variable that its environment did not have, the spelling of its system folders,
and the progress of the installation, which counts the bytes that Setup installed.
"""
_HOST_VALUES_LEFT_OUT_OF_THE_LOGS = frozenset({
    'ConstAutoCf',
    'ConstAutoPf',
})
"""
The values that the stored logs of the host oracle leave out because they hold the name of the
account that ran it.
"""
_HOST_VALUES_OF_THE_INSTALL_MODE = (
    'Is64BitInstallMode',
    'IsWin64',
    'ConstCommonPf',
    'ConstCommonCf',
    'ConstDao',
    'ConstCommonPf32',
    'ConstCommonPf64',
)
_HOST_LOG_OF_A_32_BIT_INSTALL_MODE = {
    'Is64BitInstallMode' : '0',
    'IsWin64'            : '1',
    'ConstCommonPf'      : R'[C:\Program Files (x86)]',
    'ConstCommonCf'      : R'[C:\Program Files (x86)\Common Files]',
    'ConstDao'           : R'[C:\Program Files (x86)\Common Files\Microsoft Shared\DAO]',
    'ConstCommonPf32'    : R'[C:\Program Files (x86)]',
    'ConstCommonPf64'    : R'[C:\Program Files]',
}
"""
What `InitializeSetup` of an earlier version of the host oracle logged for the install mode when it
was built without `ArchitecturesInstallIn64BitMode` and ran on 64-bit Windows.
"""


def _host_oracle_lines(test: TestBase, run: str) -> list[tuple[str, str]]:
    """
    The names and values that a run of the host oracle logged, in order.
    """
    log = codecs.decode(_archived_file(test, _HOST_ORACLE, F'host-oracle-6-{run}.log'), 'utf8')
    return [(match[1], match[2]) for line in log.splitlines() if (match := _ORACLE_LINE.fullmatch(line))]


def _host_oracle_log(test: TestBase, run: str) -> dict[str, str]:
    """
    The values that a run of the host oracle logged, by their names.
    """
    return dict(_host_oracle_lines(test, run))


def _logged_lines(events: Iterable[object]) -> list[tuple[str, str]]:
    """
    The names and values of the oracle lines that the events log, in order.
    """
    return [
        (match[1], match[2]) for event in events
        if isinstance(event, NewFunctionCall)
        and event.name == 'Log'
        and (match := _ORACLE_LINE.fullmatch(event.args[0]))
    ]


def _logged_values(events: Iterable[object], values: dict[str, str]) -> dict[str, str]:
    """
    Adds the name and value of each oracle line that the events log to the given values, as the
    events come, so that the values logged before an error are kept.
    """
    for event in events:
        if (
            isinstance(event, NewFunctionCall)
            and event.name == 'Log'
            and (match := _ORACLE_LINE.fullmatch(event.args[0]))
        ):
            values[match[1]] = match[2]
    return values


def _a_key_of_windows(name: str, value: str) -> bool:
    """
    Whether an oracle line depends on a key that the registry of every Windows has or lacks: the
    emulated registry has no keys, but the emulated `RegKeyExists` finds every key.
    """
    return name == 'RegKeyExistsMissing' or value == 'code:registry.d.valuedata'


def _a_member_of_the_empty_wizard_form_that_it_inherits(name: str) -> bool:
    """
    Whether an oracle line logs a member that the wizard form inherits, called on the empty variable
    of the form: the emulator gives nil for every object that it does not model, so it cannot tell
    the empty variable from such an object.
    """
    return name in ('NilFormMethod', 'NilFormMethodInner')


def _comparable(lines: Iterable[tuple[str, str]]) -> list[str]:
    """
    The oracle lines that the emulator reproduces, as `name = value`, each event under the name
    `Event`.
    """
    comparable = []
    for name, value in lines:
        if (
            name in _HOST_VALUES_THAT_ARE_NOT_EMULATED
            or name in _HOST_VALUES_LEFT_OUT_OF_THE_LOGS
            or _a_key_of_windows(name, value)
            or _a_member_of_the_empty_wizard_form_that_it_inherits(name)
        ):
            continue
        if _HOST_EVENT.fullmatch(name):
            name = 'Event'
        comparable.append(F'{name} = {value}')
    return comparable


def _resolved(values: dict[str, str]) -> dict[str, str]:
    """
    The value oracle logs each exception message once, as the value of `msg.N`, and every value
    that contains the message as `!N`, numbered in the order of the run. Returns the values without
    the messages, with each reference replaced by `!` and the message.
    """
    messages = {name: value for name, value in values.items() if name.startswith('msg.')}
    return {
        name: _MESSAGE_REFERENCE.sub(lambda m: F'!{messages.get(F"msg.{m[1]}", m[0])}', value)
        for name, value in values.items() if name not in messages
    }


def _string_constants(functions: Iterable[Function]) -> set[str]:
    return {
        value
        for function in functions
        for instruction in function.body or ()
        for operand in instruction.operands
        if isinstance(operand, Operand)
        and operand.value is not None
        and isinstance(value := operand.value.value, str)
    }


def _reached(function: Function) -> list[Function]:
    """
    The function and the script functions that it calls, directly or through others.
    """
    reached = [function]
    for caller in reached:
        for instruction in caller.body or ():
            if instruction.opcode is Op.Call:
                reached.extend(
                    callee for callee in instruction.operands
                    if isinstance(callee, Function) and callee.body is not None and callee not in reached
                )
    return reached


def _cells(values: dict[str, str], left_out: frozenset[tuple[str, int]]) -> dict[tuple[str, int], str]:
    """
    The cells of each row, separated by `|`, by the name of the row and their position; without
    the cells that are left out.
    """
    return {
        (name, k): cell
        for name, row in values.items()
        for k, cell in enumerate(row.split('|'))
        if (name, k) not in left_out
    }


class _ScriptOracleTest(TestBase):
    """
    Inno Setup ran a script whose procedures log what they compute; the tests emulate the script.
    """

    def emulator(self, **config) -> InnoSetupEmulator:
        raise NotImplementedError

    def assertRunsAdvancedAlternatelyLogWhatEachLogsAlone(self, *procedures: str, **config):
        """
        Emulates the procedures on one emulator, first one after the other and then all at once,
        taking one event from each run in turn. With the configuration option `log_opcodes`, each
        instruction is an event.
        """
        emulator = self.emulator(**config)
        alone = [_logged_values(emulator.emulate_function(emulator.symbols[p]), {}) for p in procedures]
        runs = [emulator.emulate_function(emulator.symbols[p]) for p in procedures]
        alternately = list(zip_longest(*runs))
        self.assertTrue(all(alone))
        self.assertEqual([_logged_values(events, {}) for events in zip(*alternately)], alone)


class _OracleTest(_ScriptOracleTest):
    """
    Inno Setup 6.5.0 built an installer from a script whose procedures log values that Pascal Script
    computes, one procedure per area. The installer ran with a log file on a German Windows, whose
    language ID is 0x0407: `log` holds every value of that log and `script` is the compiled script
    taken from that installer.
    """
    script: str
    log: dict[str, str]

    def emulator(self, **config):
        script = IFPSFile.Parse(self.download_sample(self.script))
        config.setdefault('setup_version', (6, 5, 0))
        return InnoSetupEmulator(script, IFPSEmulatorConfig(log_calls=True, lcid=0x0407, **config))

    def assertEmulatedAsLogged(self, procedure: str, *names: str):
        """
        Emulates one procedure and compares what it logs with the log: the values of the given
        names, or else every value that it logs with the logged values whose names are string
        constants of the procedure and of the script functions it calls. Exception messages are
        compared by their text.
        """
        emulator = self.emulator()
        function = emulator.symbols[procedure]
        emulated = _resolved(_logged_values(emulator.emulate_function(function), {}))
        log = _resolved(self.log)
        if names:
            self.assertLessEqual(set(names), _string_constants(emulator.ifps.functions))
            emulated = {name: value for name, value in emulated.items() if name in names}
        else:
            names = tuple(_string_constants(_reached(function)))
            self.assertTrue(log.keys() & names)
        real = {name: value for name, value in log.items() if name in names}
        self.assertEqual(emulated, real)


class _ValueOracleTest(_ScriptOracleTest):
    """
    One build of the value oracle. Its procedures log values that Pascal Script computes, one area
    per procedure, as rows of cells separated by `|`; the installer ran with a log file on a German
    Windows, whose language ID is 0x0407. Each test emulates one procedure in a new emulator after
    `InitPowers`, which sets the globals that the procedures read, and compares what it logs with
    the log cell by cell. A cell of a known defect is left out and has a test of its own. Each
    build is a test class.
    """
    __test__ = False
    build: str
    setup_version: tuple[int, int, int]
    defects: frozenset[tuple[str, int]] = frozenset()

    def log(self) -> dict[str, str]:
        values = {}
        for line in codecs.decode(_value_oracle_file(self, self.build, 'log'), 'utf8').splitlines():
            if match := _ORACLE_LINE.fullmatch(line):
                values[match[1]] = match[2]
        return _resolved(values)

    def emulator(self, **config):
        script = IFPSFile.Parse(_value_oracle_file(self, self.build, 'ifps'))
        config.setdefault('setup_version', self.setup_version)
        return InnoSetupEmulator(script, IFPSEmulatorConfig(
            log_calls=True,
            lcid=0x0407,
            max_seconds=0,
            max_opcodes=2_000_000,
            **config,
        ))

    def emulated(self, emulator: InnoSetupEmulator, procedure: str) -> dict[str, str]:
        logged = {}
        for name in ('INITPOWERS', procedure):
            _logged_values(emulator.emulate_function(emulator.symbols[name]), logged)
        return _resolved(logged)

    def assertEmulatedAsLogged(self, procedure: str, *prefixes: str, **config):
        """
        Emulates one procedure and compares its rows with the rows that it logged. Its rows are those
        whose names are string constants of the procedure and of the script functions it calls,
        such a constant that ends in a separator followed by a number, or start with one of the
        given prefixes.
        """
        emulator = self.emulator(**config)
        constants = _string_constants(_reached(emulator.symbols[procedure]))
        stems = tuple(constant for constant in constants if constant.endswith(('.', '_')))
        log = self.log()
        names = {
            name for name in log
            if name in constants
            or name.startswith(prefixes)
            or any(name.startswith(stem) and name[len(stem):].isdigit() for stem in stems)
        }
        self.assertTrue(names)
        self.assertEqual(
            _cells(self.emulated(emulator, procedure), self.defects),
            _cells({name: log[name] for name in names}, self.defects),
        )

    def assertCellsEmulatedAsLogged(self, procedure: str, *cells: tuple[str, int]):
        emulated = self.emulated(self.emulator(), procedure)
        log = self.log()
        self.assertEqual(
            {(name, k): emulated[name].split('|')[k] for name, k in cells},
            {(name, k): log[name].split('|')[k] for name, k in cells},
        )


class _EveryBuild(_ValueOracleTest):
    """
    The procedures that every build runs: they store, compute with, compare, convert, parse, and
    format values of every type: integers, floats, Currency, sets, strings, Variants, and arrays.
    """

    def test_stores(self):
        self.assertEmulatedAsLogged('ORACLESTORES')

    def test_arithmetic(self):
        self.assertEmulatedAsLogged('ORACLEARITHMETIC')

    def test_division(self):
        self.assertEmulatedAsLogged('ORACLEDIVISION')

    def test_shifts(self):
        self.assertEmulatedAsLogged('ORACLESHIFTS')

    def test_comparisons(self):
        self.assertEmulatedAsLogged('ORACLECOMPARISONS')

    def test_comparisons_of_an_integer_with_a_currency_and_a_variant(self):
        self.assertEmulatedAsLogged('ORACLEMIXEDCOMPARISONS')

    def test_float_constants(self):
        self.assertEmulatedAsLogged('ORACLECONSTANTS')

    def test_format(self):
        self.assertEmulatedAsLogged('ORACLEFORMAT')

    def test_floats(self):
        self.assertEmulatedAsLogged('ORACLEFLOATS')

    def test_sets(self):
        self.assertEmulatedAsLogged('ORACLESETS')

    def test_booleans(self):
        self.assertEmulatedAsLogged('ORACLEBOOLEANS')

    def test_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTS')

    def test_format_of_values_reached_through_pointers(self):
        self.assertEmulatedAsLogged('ORACLEPOINTERS')

    def test_format_of_unusual_specifiers(self):
        self.assertEmulatedAsLogged('ORACLEFORMATEDGES')

    def test_booleans_in_variants(self):
        self.assertEmulatedAsLogged('ORACLEBOOLEANVARIANTS')

    def test_comparisons_of_integers_with_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOMPARISONS')

    def test_variants_holding_floats_as_text(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTTEXT')

    def test_a_loop_with_a_variant_counter(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOUNTER')

    def test_format_of_an_array_of_strings(self):
        self.assertEmulatedAsLogged('ORACLEARRAYOFSTRINGS')

    def test_an_infinite_float_constant(self):
        self.assertEmulatedAsLogged('ORACLEINFINITY')

    def test_values_of_every_type_stored_into_a_variant(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTSTORES')

    def test_conversions_of_variants_of_every_type(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCONVERSIONS', 'vconv.')

    def test_operators_on_every_pair_of_variant_types(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTOPERATORS', 'vop.')

    def test_comparisons_of_every_pair_of_variant_types(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOMPARISONMATRIX', 'vcmp.')

    def test_variants_of_small_integer_types_that_overflow(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTOVERFLOW')

    def test_negation_and_not_of_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTUNARY')

    def test_typed_variables_that_compute_with_a_variant(self):
        self.assertEmulatedAsLogged('ORACLETYPEDCALCULATIONS')

    def test_typed_variables_compared_with_a_variant(self):
        self.assertEmulatedAsLogged('ORACLETYPEDCOMPARISONS')

    def test_text_of_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTTEXTS')

    def test_infinities_nan_and_float_errors_under_both_control_words(self):
        self.assertEmulatedAsLogged('ORACLEFLOATSPECIALS')

    def test_float_to_str_of_large_and_small_values(self):
        self.assertEmulatedAsLogged('ORACLEFLOATTOSTRRANGE')

    def test_precision_and_rounding_of_floats_and_currency(self):
        self.assertEmulatedAsLogged('ORACLEFLOATPRECISION')

    def test_format_of_floats(self):
        self.assertEmulatedAsLogged('ORACLEFLOATFORMATS')

    def test_parsing_of_integers(self):
        self.assertEmulatedAsLogged('ORACLEPARSING')

    def test_parsing_of_floats(self):
        self.assertEmulatedAsLogged('ORACLEFLOATPARSING')

    def test_a_string_index_outside_of_the_string_raises_an_error(self):
        self.assertEmulatedAsLogged('ORACLESTRINGINDEX')

    def test_a_dynamic_array_assigned_to_another_variable_is_shared(self):
        self.assertEmulatedAsLogged('ORACLESHAREDARRAYS')

    def test_text_and_conversions_at_the_edges_of_their_ranges(self):
        self.assertEmulatedAsLogged('ORACLEPROBES')

    def test_built_in_functions_for_floats_and_variants(self):
        self.assertEmulatedAsLogged('ORACLEBUILTINS')

    def test_a_split_keeps_the_separators_between_quote_characters(self):
        self.assertEmulatedAsLogged('ORACLESPLIT')

    def test_operations_on_the_zero_of_every_type(self):
        self.assertEmulatedAsLogged('ORACLEZEROS', 'zero.')

    def test_a_new_variant_and_an_unset_result_are_unassigned(self):
        self.assertEmulatedAsLogged('ORACLEUNASSIGNED')

    def test_a_call_on_a_nil_com_object_raises_an_error(self):
        self.assertEmulatedAsLogged('ORACLENILINVOKE')

    def test_a_currency_computed_with_a_cardinal_or_an_int64(self):
        self.assertEmulatedAsLogged('ORACLECURRENCYOPERANDS')

    def test_parsing_of_numbers_with_many_digits(self):
        self.assertEmulatedAsLogged('ORACLELONGPARSING')

    def test_variant_strings_beyond_the_range_of_a_double(self):
        self.assertEmulatedAsLogged('ORACLEOLELIMITS')

    def test_text_of_floats_near_the_ends_of_their_range(self):
        self.assertEmulatedAsLogged('ORACLELARGETEXT')

    def test_parsing_scales_by_one_power_of_ten(self):
        self.assertEmulatedAsLogged('ORACLEPARSINGPOWERS')

    def test_text_and_format_of_random_floats(self):
        self.assertEmulatedAsLogged('ORACLEFITTEXT')

    def test_parsing_of_random_numbers(self):
        self.assertEmulatedAsLogged('ORACLEFITVAL')

    def test_random_floats_stored_as_singles(self):
        self.assertEmulatedAsLogged('ORACLEFITSINGLES')

    def test_sine_cosine_square_root_and_rounding_of_floats_below_2_to_the_53(self):
        self.assertEmulatedAsLogged('ORACLEFITMATH')

    def test_arithmetic_of_random_floats(self):
        self.assertEmulatedAsLogged('ORACLEFITARITHMETIC')

    def test_rounding_under_each_control_word(self):
        self.assertEmulatedAsLogged('ORACLEROUNDING')

    def test_currency_arithmetic(self):
        self.assertEmulatedAsLogged('ORACLECURRENCY7')

    def test_comparisons_of_currency(self):
        self.assertEmulatedAsLogged('ORACLECURRENCYCOMPARISONS')

    def test_variants_that_hold_a_currency_and_a_float(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCURRENCYFLOATS')

    def test_division_of_the_smallest_integer_by_minus_one_and_by_zero(self):
        self.assertEmulatedAsLogged('ORACLEINTEGERDIVISION7')

    def test_an_exit_through_finally_blocks(self):
        self.assertEmulatedAsLogged('ORACLEEXITPOINTS')

    def test_an_index_outside_of_an_array(self):
        self.assertEmulatedAsLogged('ORACLEARRAYINDEX')

    def test_a_dynamic_array_assigned_to_an_array_of_another_type(self):
        self.assertEmulatedAsLogged('ORACLEARRAYASSIGNMENT')

    def test_inc_dec_and_a_for_loop_on_a_variant(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTINCREMENT')

    def test_characters_beyond_ansi(self):
        self.assertEmulatedAsLogged('ORACLEWIDECHARACTERS')

    def test_size_of_every_type(self):
        self.assertEmulatedAsLogged('ORACLESIZES')

    def test_casts_of_objects(self):
        self.assertEmulatedAsLogged('ORACLECLASSCASTS')

    def test_variant_strings_of_long_numbers_converted_to_a_double(self):
        self.assertEmulatedAsLogged('ORACLEOLE7')

    def test_a_static_array_stored_into_a_variant(self):
        self.assertEmulatedAsLogged('ORACLESTATICARRAYVARIANT')

    def test_text_of_floats_whose_decimal_exponent_is_estimated_too_high(self):
        self.assertEmulatedAsLogged('ORACLEOVERSHOOTTEXT')

    def test_variant_currency_divided_by_floats_with_decimals(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCURRENCYDECIMALS')

    def test_currency_from_integers_beyond_its_range(self):
        self.assertEmulatedAsLogged('ORACLECURRENCYFROMINTEGERS')

    def test_an_int64_in_an_open_array(self):
        self.assertEmulatedAsLogged('ORACLEOPENARRAYINT64')

    @wontfix('VarArrayGet is not emulated; it reads nothing from an array in a Variant')
    def test_an_element_of_a_static_array_in_a_variant(self):
        self.assertCellsEmulatedAsLogged('ORACLESTATICARRAYVARIANT', ('variant.static_array', 1))


class _A32BitBuild(_ValueOracleTest):
    """
    The procedures of a build for a 32-bit Setup, which computes floats on the x87.
    """

    def test_sine_cosine_square_root_and_rounding_of_floats_of_2_to_the_53_or_more(self):
        self.assertEmulatedAsLogged('ORACLEFITMATHLARGE')

    def test_long_strings_raise_the_errors_of_delphi_before_they_are_built(self):
        """
        The last probe asks for a string of 2,000,000,000 characters, which Setup refused; the
        emulation ends there, as the string exceeds the limit of the configuration. Every other
        probe that Setup refused is refused before the emulator builds its string.
        """
        emulator = self.emulator(max_string_length=40_000_000)
        logged = {}
        tracemalloc.start()
        try:
            with self.assertRaises(EmulatorMaxString):
                _logged_values(emulator.emulate_function(emulator.symbols['ORACLELONGSTRINGS']), logged)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 200_000_000)
        log = self.log()
        logged = _resolved(logged)
        self.assertEqual(logged.pop('strings.step'), '4')
        self.assertEqual(logged, {name: log[name] for name in logged})
        self.assertEqual(logged.keys() | {'strings.step', 'strings.char_2g'}, {n for n in log if n.startswith('strings.')})

    @wontfix('the x87 computes the sine of the Double nearest to 1/3 with an error of 0.55 units in the last place; the emulator rounds the exact sine')
    def test_the_sine_of_a_third_is_that_of_the_x87(self):
        self.assertCellsEmulatedAsLogged('ORACLEROUNDING', ('round.nearest', 15))


class _AnInnoSetup7Build(_ValueOracleTest):
    """
    The procedures of a build of Inno Setup 7, whose Pascal Script has the type UInt64.
    """

    def test_uint64_arithmetic_comparisons_and_conversions(self):
        self.assertEmulatedAsLogged('ORACLEUINT64')

    def test_text_of_uint64_values_and_their_parsing(self):
        self.assertEmulatedAsLogged('ORACLEUINT64TEXT')

    def test_variants_of_a_uint64_and_another_integer(self):
        self.assertEmulatedAsLogged('ORACLEUINT64VARIANTINTEGERS')

    def test_integers_divided_by_a_uint64(self):
        self.assertEmulatedAsLogged('ORACLEINT64BYUINT64')

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='as keeps every object; the emulator does not model the classes of Setup that it would check',
    )
    def test_a_cast_with_as_to_a_class_that_the_object_is_not(self):
        self.assertCellsEmulatedAsLogged('ORACLECLASSCASTS', ('class.as', 1))

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='as keeps every object; the emulator does not model the classes of Setup that it would check',
    )
    def test_a_cast_of_nil_with_as(self):
        self.assertCellsEmulatedAsLogged('ORACLECLASSCASTS', ('class.as', 2))


class TestTheEmulatorLogsWhatInnoSetup6Logged(_EveryBuild, _A32BitBuild):
    """
    The build of Inno Setup 6.5.0.
    """
    __test__ = True
    build = 'inno6'
    setup_version = (6, 5, 0)
    defects = frozenset({
        ('round.nearest', 15),
        ('variant.static_array', 1),
        ('wide.string_of_char', 0),
    })

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='StringOfChar keeps the whole character; Pascal Script keeps its low byte as an ANSI character',
    )
    def test_string_of_char_of_a_character_beyond_ansi(self):
        self.assertCellsEmulatedAsLogged('ORACLEWIDECHARACTERS', ('wide.string_of_char', 0))

    @wontfix('Inno Setup 5.5.3 and 5.5.4 copy a shared dynamic array that keeps its length; the emulator follows 5.5.5 and later')
    def test_inno_setup_5_5_4_copies_a_shared_dynamic_array_that_keeps_its_length(self):
        emulator = self.emulator(setup_version=(5, 5, 4))
        logged = _resolved(_logged_values(emulator.emulate_function(emulator.symbols['ORACLESHAREDARRAYS']), {}))
        self.assertEqual(logged['share.resized_to_same_length'], 'a')

    def test_a_split_into_more_parts_than_the_array_limit_ends_the_emulation(self):
        emulator = self.emulator(max_array_length=3)
        logged = {}
        with self.assertRaises(EmulatorMaxArray):
            _logged_values(emulator.emulate_function(emulator.symbols['ORACLESPLIT']), logged)
        self.assertEqual(logged, {})

    def test_a_format_number_of_more_than_40_digits_ends_the_emulation(self):
        """
        The loop of the procedure that writes widths of 11 to 40 digits into a format is changed to
        go on to 41 digits. Setup raised an error for every width of 11 to 40 digits and crashed
        for one of 5000 digits.
        """
        emulator = self.emulator(max_string_length=40_000_000)
        procedure = emulator.symbols['ORACLELONGSTRINGS']
        replaced = 0
        for instruction in procedure.body or ():
            for k, operand in enumerate(instruction.operands):
                if isinstance(operand, Operand) and (constant := operand.value) and constant.value == 40:
                    instruction.operands[k] = operand._replace(value=Value(constant.type, 41))
                    replaced += 1
        self.assertEqual(replaced, 1)
        logged = {}
        with self.assertRaises(EmulatorUndefined):
            _logged_values(emulator.emulate_function(procedure), logged)
        self.assertEqual(logged['strings.step'], 'width 41')

    def test_an_exponent_that_reaches_beyond_the_table_of_powers_of_ten_ends_the_emulation(self):
        """
        The text of a constant that the procedure parses is changed to one whose exponent is read
        as -2**31. Delphi then scales by a power of ten from after the end of its table: two runs
        of the oracle parsed this text to NaN and to 2.38E+4756.
        """
        emulator = self.emulator()
        procedure = emulator.symbols['ORACLEPARSINGPOWERS']
        replaced = 0
        for instruction in procedure.body or ():
            for k, operand in enumerate(instruction.operands):
                if isinstance(operand, Operand) and (constant := operand.value) and constant.value == '1e4932':
                    instruction.operands[k] = operand._replace(value=Value(constant.type, '1e2147483648'))
                    replaced += 1
        self.assertEqual(replaced, 1)
        with self.assertRaises(EmulatorUndefined):
            for _ in emulator.emulate_function(procedure):
                pass

    def test_two_runs_advanced_alternately_by_instruction_log_what_each_logs_alone(self):
        self.assertRunsAdvancedAlternatelyLogWhatEachLogsAlone('ORACLECOMPARISONS', 'ORACLESETS', log_opcodes=True)


class TestTheEmulatorLogsWhatInnoSetup7Logged(_EveryBuild, _A32BitBuild, _AnInnoSetup7Build):
    """
    The build of Inno Setup 7.1.0 for a 32-bit Setup.
    """
    __test__ = True
    build = 'x86'
    setup_version = (7, 1, 0)
    defects = frozenset({
        ('round.nearest', 15),
        ('variant.static_array', 1),
        ('class.as', 1),
        ('class.as', 2),
    })


class TestTheScriptTellsWhichInnoSetupCompiledIt(TestBase):
    """
    The three builds of the value oracle compile the same script.
    """

    def script(self, build: str) -> IFPSFile:
        return IFPSFile.Parse(_value_oracle_file(self, build, 'ifps'))

    def function(self, build: str, name: str) -> Function:
        return next(function for function in self.script(build).functions if function.name == name)

    def test_the_types_of_a_script_tell_the_pascal_script_and_the_platform_that_compiled_it(self):
        self.assertEqual(
            {build: (self.script(build).dialect, self.script(build).platform) for build in ('inno6', 'x86', 'x64')},
            {
                'inno6' : (Dialect.Inno6, Platform.Win32),
                'x86'   : (Dialect.Inno7, Platform.Win32),
                'x64'   : (Dialect.Inno7, Platform.Win64),
            },
        )

    def test_inno_setup_7_compiles_each_as_of_a_procedure_into_an_instruction(self):
        """
        The procedure casts with `as` three times.
        """
        procedure = self.function('x86', 'ORACLECLASSCASTS')
        casts = [str(i) for i in procedure.body or () if i.opcode is Op.Calculate and i.operator is AOp.As]
        self.assertEqual(len(casts), 3)
        self.assertTrue(all(' as ' in cast for cast in casts))

    def test_a_script_for_a_64_bit_setup_holds_its_extended_constants_as_doubles(self):
        """
        The last float constant of the function is `4503599627370497.5`. Inno Setup 6.5 writes the
        Extended that holds it; the compiler of Inno Setup 7.1 computes it as a Double, which rounds
        it to the even neighbor, and writes that Double as an Extended into the script of a 32-bit
        Setup.
        """
        def constants(build: str) -> list[x87.Real]:
            return [
                value
                for instruction in self.function(build, 'MATHINPUT').body or ()
                for operand in instruction.operands
                if isinstance(operand, Operand) and operand.value and operand.value.type.code is TC.Extended
                if isinstance(value := operand.value.value, (float, x87.Extended))
            ]
        x64 = constants('x64')
        self.assertEqual(x87.exact(constants('inno6')[-1]), Fraction(9007199254740995, 2))
        self.assertEqual(x64[-1], 4503599627370498.0)
        self.assertEqual(x64, constants('x86'))


class TestTheEmulatorLogsWhatA64BitSetupOfInnoSetup7Logged(_EveryBuild, _AnInnoSetup7Build):
    """
    The build of Inno Setup 7.1.0 for a 64-bit Setup, which computes floats with SSE.
    """
    __test__ = True
    build = 'x64'
    setup_version = (7, 1, 0)
    random_numbers_of_more_than_16_digits = (
        ('fit.val.0', 4),
        ('fit.val.3', 3),
        ('fit.val.8', 2),
        ('fit.val.17', 1),
        ('fit.val.24', 8),
        ('fit.val.29', 7),
        ('fit.val.36', 5),
        ('fit.val.37', 9),
        ('fit.val.38', 2),
        ('fit.val.54', 9),
        ('fit.val.61', 4),
        ('fit.val.64', 2),
        ('fit.val.78', 0),
        ('fit.val.81', 8),
        ('fit.val.fixed.1', 9),
        ('fit.val.fixed.2', 0),
        ('fit.val.fixed.2', 1),
        ('fit.val.fixed.4', 6),
    )
    a_number_of_18_digits_under_each_control_word = (
        ('round.nearest', 12),
        ('round.down', 12),
        ('round.up', 12),
        ('round.zero', 12),
        ('round.double_precision', 12),
        ('round.single_precision', 12),
    )
    sines_and_cosines_below_2_to_the_53 = (
        ('fit.math.1', 4),
        ('fit.math.2', 3),
        ('fit.math.special', 5),
        ('fit.math.random.2', 3),
    )
    defects = frozenset({
        *random_numbers_of_more_than_16_digits,
        *a_number_of_18_digits_under_each_control_word,
        *sines_and_cosines_below_2_to_the_53,
        ('parse.extreme', 2),
        ('parse.exponent_limit', 4),
        ('fit.text.52', 5),
        ('fit.tenths.15', 14),
        ('ole7.double', 6),
        ('class.as', 1),
        ('class.as', 2),
        ('variant.static_array', 1),
    })

    def test_strings_of_up_to_20_million_characters(self):
        self.assertEmulatedAsLogged('ORACLELONGSTRINGS', max_string_length=40_000_000)

    def test_the_sine_of_2_to_the_53_or_more_ends_the_emulation(self):
        with self.assertRaises(EmulatorUndefined):
            self.emulated(self.emulator(), 'ORACLEFITMATHLARGE')

    @wontfix('64-bit Delphi reduces the operand of a sine or cosine of 2**53 or more in a way that is not known')
    def test_sine_cosine_square_root_and_rounding_of_floats_of_2_to_the_53_or_more(self):
        self.assertEmulatedAsLogged('ORACLEFITMATHLARGE')

    @wontfix('64-bit Delphi computes a sine or cosine within one unit in the last place, not always correctly rounded, by an algorithm that is not known')
    def test_sines_and_cosines_below_2_to_the_53_that_64_bit_delphi_does_not_round_correctly(self):
        self.assertCellsEmulatedAsLogged('ORACLEFITMATH', *self.sines_and_cosines_below_2_to_the_53)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='64-bit Val is modelled on an x87 at 53 bits, which rounds some numbers of more than 16 digits differently',
    )
    def test_parsing_of_random_numbers_of_more_than_16_digits(self):
        self.assertCellsEmulatedAsLogged('ORACLEFITVAL', *self.random_numbers_of_more_than_16_digits)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='64-bit Val is modelled on an x87 at 53 bits, which rounds some numbers of more than 16 digits differently',
    )
    def test_parsing_of_a_number_of_18_digits_under_each_control_word(self):
        self.assertCellsEmulatedAsLogged('ORACLEROUNDING', *self.a_number_of_18_digits_under_each_control_word)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='64-bit Val reads a number of thousands of digits with a negative exponent as zero; the emulator as an infinity',
    )
    def test_parsing_of_5000_digits_with_a_negative_exponent(self):
        self.assertCellsEmulatedAsLogged('ORACLELONGPARSING', ('parse.extreme', 2))

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='64-bit Val reads a number of thousands of digits with a negative exponent as zero; the emulator as an infinity',
    )
    def test_parsing_of_4951_digits_with_a_negative_exponent(self):
        self.assertCellsEmulatedAsLogged('ORACLEPARSINGPOWERS', ('parse.exponent_limit', 4))

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='the text of a subnormal Double from 64-bit Delphi differs in its last digits',
    )
    def test_text_of_subnormal_doubles(self):
        self.assertCellsEmulatedAsLogged('ORACLEFITTEXT', ('fit.text.52', 5), ('fit.tenths.15', 14))

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='64-bit Windows converts a Variant string of 309 digits to a Double that is one unit in the last place off',
    )
    def test_a_variant_string_of_309_digits_converted_to_a_double(self):
        self.assertCellsEmulatedAsLogged('ORACLEOLE7', ('ole7.double', 6))


class TestTheParserReadsWhatTheCompilerWrote(TestBase):
    """
    The parser reads the records of an installer as Setup reads them. The script of the host oracle
    sets the yes-or-no directives `Uninstallable`, `CreateUninstallRegKey`, `ChangesEnvironment`
    and `ChangesAssociations` to calls of its function `Directive`, and
    `ArchitecturesInstallIn64BitMode` to `x64compatible`.
    """

    def oracle(self) -> InnoArchive:
        return InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe'))

    def test_installers_of_inno_setup_5_5_install_in_64_bit_mode_on_x64_processors(self):
        """
        Before 6.3.0, Setup stores the directive as a set of processor architectures; these
        installers check `IsWin64` in their scripts and install 64-bit files.
        """
        for sample in (
            'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42',
            'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73',
        ):
            with self.subTest(sample=sample):
                header = InnoArchive(self.download_sample(sample)).setup_info.Header
                self.assertEqual(header.ArchitecturesInstallIn64BitMode, Architecture.X64)

    def test_an_installer_of_inno_setup_6_5_reads_its_architecture_directives_as_text(self):
        header = self.oracle().setup_info.Header
        self.assertEqual(header.ArchitecturesInstallIn64BitMode, 'x64compatible')
        self.assertEqual(header.ArchitecturesAllowed, '')

    def test_a_yes_or_no_directive_written_as_an_expression_is_read_as_its_text(self):
        header = self.oracle().setup_info.Header
        self.assertEqual(
            [header.directive(name) for name in YesNoDirective],
            [
                SetupDirective(None, 'Directive(\'Uninstallable\', True)'),
                SetupDirective(None, 'Directive(\'CreateUninstallRegKey\', True)'),
                SetupDirective(None, 'Directive(\'ChangesEnvironment\', False)'),
                SetupDirective(None, 'Directive(\'ChangesAssociations\', False)'),
            ],
        )

    def test_an_installer_of_inno_setup_5_2_has_no_texts_for_its_directives_but_flags(self):
        """
        Inno Setup 5.2.1 writes no text for these directives and fields; the header keeps the
        directives as flags.
        """
        info = InnoArchive(self.download_sample('0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642')).setup_info
        header = info.Header
        self.assertEqual(
            [header.Uninstallable, header.CreateUninstallRegistryKey, header.ChangesEnvironment, header.ChangesAssociations],
            [None, None, None, None],
        )
        self.assertEqual(
            [header.directive(name).answer for name in YesNoDirective],
            [
                bool(header.Flags & Flags.Uninstallable),
                bool(header.Flags & Flags.CreateUninstallRegKey),
                bool(header.Flags & Flags.ChangesEnvironment),
                bool(header.Flags & Flags.ChangesAssociations),
            ],
        )
        self.assertTrue(info.Icons)
        self.assertEqual({(icon.AppUserModelId, icon.AppUserModelToastActivatorCLSID) for icon in info.Icons}, {(None, None)})

    def test_the_value_of_an_ini_entry_and_the_text_of_registry_values(self):
        info = self.oracle().setup_info
        self.assertEqual([entry.Value for entry in info.IniEntries], ['v{code:Code|ini.a.string}', 'v'])
        self.assertEqual([entry.ValueText for entry in info.RegistryEntries], [
            'd{code:Code|registry.a.valuedata}',
            'd',
            'first{break}second{code:Code|registry.c.valuedata}',
            'd{code:Code|registry.d.valuedata}',
            'd{code:Code|registry.e.valuedata}',
        ])

    def test_a_file_entry_is_external_when_setup_does_not_take_its_data_from_the_installer(self):
        """
        The script installs five files of the installer, one that it never copies, two downloads,
        and three external files; the first entry is the uninstaller, which Setup writes from
        itself.
        """
        files = self.oracle().setup_info.Files
        self.assertEqual(
            [(file.Type, file.external) for file in files],
            [(SetupFileType.UninstExe, True)] + [(SetupFileType.UserFile, False)] * 6 + [(SetupFileType.UserFile, True)] * 5,
        )


class TestTheSetupAgreesWithTheScript(TestBase):
    """
    A script of Inno Setup 7 runs only under a Setup of Inno Setup 7, and an earlier script only
    under an earlier Setup. The host oracle was built by Inno Setup 6.5.0; its script is replaced
    by one of the value oracle and its header changed as Inno Setup 7 writes it.
    """

    def script(self, build: str) -> IFPSFile:
        return IFPSFile.Parse(_value_oracle_file(self, build, 'ifps'))

    def installer(self) -> InnoArchive:
        return InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe'))

    def test_a_setup_version_before_7_refuses_a_script_of_inno_setup_7(self):
        with self.assertRaises(ValueError):
            InnoSetupEmulator(self.script('x86'), IFPSEmulatorConfig(setup_version=(6, 5, 0)))

    def test_a_setup_version_of_7_refuses_a_script_of_inno_setup_6(self):
        with self.assertRaises(ValueError):
            InnoSetupEmulator(self.script('inno6'), IFPSEmulatorConfig(setup_version=(7, 1, 0)))

    def test_an_installer_of_inno_setup_6_refuses_a_script_of_inno_setup_7(self):
        installer = self.installer()
        installer.ifps = self.script('x86')
        with self.assertRaises(ValueError):
            InnoSetupEmulator(installer, IFPSEmulatorConfig())

    def test_an_installer_of_inno_setup_6_5_runs_its_script_by_the_rules_of_pascal_script_6(self):
        emulator = InnoSetupEmulator(self.installer(), IFPSEmulatorConfig())
        setup = emulator.setup
        self.assertEqual((setup.release.exact, emulator.dialect, setup.platform), ((6, 5, 0), Dialect.Inno6, Platform.Win32))

    def test_32_bit_windows_refuses_a_script_of_a_64_bit_setup(self):
        with self.assertRaises(ValueError):
            InnoSetupEmulator(self.script('x64'), IFPSEmulatorConfig(x64=False))

    def test_a_32_bit_installer_refuses_a_script_of_a_64_bit_setup(self):
        installer = self.installer()
        installer.setup_info.Header.CompiledCodeVersion = 0x07010000
        installer.ifps = self.script('x64')
        with self.assertRaises(ValueError):
            InnoSetupEmulator(installer, IFPSEmulatorConfig())

    def test_a_64_bit_installer_refuses_a_script_of_a_32_bit_setup(self):
        installer = self.installer()
        installer.setup_info.Header.CompiledCodeVersion = 0x87010000
        installer.ifps = self.script('x86')
        with self.assertRaises(ValueError):
            InnoSetupEmulator(installer, IFPSEmulatorConfig())

    def test_the_release_of_an_installer_of_inno_setup_7_is_the_version_of_its_compiled_code(self):
        """
        Inno Setup 7.1.0 wrote these versions of its compiled code into the headers of the 32-bit
        and the 64-bit Setup of the value oracle; the version of their data is 7.0.0.3. The highest
        bit marks a 64-bit Setup.
        """
        from refinery.lib.inno.release import SetupRelease
        self.assertEqual(SetupRelease.of_compiled_code(0x07010000).exact, (7, 1, 0))
        self.assertEqual(SetupRelease.of_compiled_code(0x87010000).exact, (7, 1, 0))


class TestTheEmulatorHandlesErrorsAsInnoSetupDid(_OracleTest):
    """
    The procedures of this script raise errors and log what the script sees of them: which blocks
    ran, in order, and the exception message.
    """
    script = _ERROR_SCRIPT
    log = _ERROR_LOG

    def test_an_error_in_a_called_function_runs_the_except_block_of_its_caller(self):
        self.assertEmulatedAsLogged('ORACLECALLERHANDLER')

    def test_an_error_in_an_except_block_leaves_the_block(self):
        self.assertEmulatedAsLogged('ORACLEEXCEPTBLOCKRAISES')

    def test_an_error_passes_through_a_finally_block(self):
        self.assertEmulatedAsLogged('ORACLEFINALLYPASSESON')

    def test_an_error_in_a_finally_block_replaces_the_error_that_passes_through(self):
        self.assertEmulatedAsLogged('ORACLEFINALLYRAISES')

    def test_an_exit_runs_the_finally_blocks_of_its_function(self):
        self.assertEmulatedAsLogged('ORACLEEXITS')

    def test_an_exit_through_finally_blocks_that_call_no_function_returns(self):
        self.assertEmulatedAsLogged('ORACLEQUIETEXITS')

    def test_an_exit_inside_a_finally_block_keeps_the_error_that_passes_through(self):
        self.assertEmulatedAsLogged('ORACLEEXITINSIDEFINALLY')

    def test_a_try_statement_with_an_except_block_and_a_finally_block(self):
        self.assertEmulatedAsLogged('ORACLECOMBINEDBLOCKS')

    def test_an_error_in_the_finally_block_after_an_except_block(self):
        self.assertEmulatedAsLogged('ORACLESECONDFINALLYRAISES')

    def test_break_and_continue_inside_a_try_block(self):
        self.assertEmulatedAsLogged('ORACLELOOPS')

    def test_runtime_errors_of_integers_and_arrays(self):
        self.assertEmulatedAsLogged(
            'ORACLERUNTIMEERRORS',
            'DynamicIndexMessage',
            'StaticIndexMessage',
            'NegativeIndexMessage',
            'DivisionMessage',
            'ModuloMessage',
            'OverflowMessage',
        )

    def test_float_errors_raise_nothing(self):
        self.assertEmulatedAsLogged(
            'ORACLERUNTIMEERRORS',
            'InvalidFloatTrace',
            'InvalidFloatMessage',
            'FloatDivisionTrace',
            'FloatDivisionMessage',
        )

    def test_the_exception_message(self):
        self.assertEmulatedAsLogged('ORACLEMESSAGES')

    def test_an_error_that_passes_through_a_finally_block_has_no_exception_message(self):
        self.assertEmulatedAsLogged('ORACLEMESSAGEINFINALLY')

    def test_a_code_constant_runs_a_function_of_the_script(self):
        self.assertEmulatedAsLogged('ORACLECODECONSTANTS')

    def test_a_code_constant_inside_a_finally_block_ends_the_error_that_passes_through(self):
        self.assertEmulatedAsLogged('ORACLECODEINFINALLY')

    def test_a_code_constant_reads_the_exception_message_of_the_function_that_expands_it(self):
        self.assertEmulatedAsLogged('ORACLECODEMESSAGE')

    def test_a_code_constant_that_logs_a_value_is_expanded_to_its_result(self):
        self.assertEmulatedAsLogged('ORACLECODELOGS', 'CodeLogsValue')

    def test_a_code_constant_logs_a_value(self):
        self.assertEmulatedAsLogged('ORACLECODELOGS', 'CodeLogged')

    def test_abort_raises_an_error_that_the_script_handles(self):
        self.assertEmulatedAsLogged('ORACLEABORT')

    def test_strtoint_of_text_that_is_no_number_raises_no_error(self):
        self.assertEmulatedAsLogged('ORACLECONVERSIONMESSAGE', 'StrToIntMessage')

    def test_an_error_left_by_an_exit_inside_a_finally_block_ends_the_run(self):
        """
        Setup logged that `DeinitializeSetup` raised an exception with this message.
        """
        emulator = self.emulator()
        logged = {}
        with self.assertRaises(IFPSException) as raised:
            _logged_values(emulator.emulate_function(emulator.symbols['DEINITIALIZESETUP']), logged)
        self.assertEqual(logged, {'DeinitializeSetup': self.log['DeinitializeSetup']})
        self.assertEqual(raised.exception.message, 'left in flight')

    def test_two_runs_advanced_alternately_log_what_each_logs_alone(self):
        self.assertRunsAdvancedAlternatelyLogWhatEachLogsAlone('ORACLEMESSAGES', 'ORACLECALLERHANDLER')

    def test_a_code_constant_in_a_description_that_the_script_reads_sees_the_error_of_the_reader(self):
        """
        Setup expands the descriptions of the selected components as `ExpandConstant` expands its
        text. Here `ExpandConstant` is replaced by a read of these descriptions; the wizard selects
        one component, whose description is the code constant that the procedure expands, and the
        read writes it as a list of names.
        """
        from refinery.lib.inno.emulator import IFPSEmulator
        from refinery.lib.inno.wizard import StandIns, WizardForm, comma_text
        emulator = self.emulator()
        form = emulator.wizard_form = WizardForm(StandIns.of(emulator.config), walked=True)
        form.created = True
        component = InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe')).setup_info.Components[0]
        component.Description = '{code:CodeMessage|m}'
        form.components.add_check_box(0, True, True, False, True, component)
        registry = IFPSEmulator.external_symbols['']
        read = registry['WizardSelectedComponents']

        def read_descriptions(emulator: IFPSEmulator, text: str, caller=None):
            return read.call(emulator, True, caller=caller)

        with mock.patch.dict(registry, {'ExpandConstant': registry['ExpandConstant']._replace(call=read_descriptions)}):
            logged = _logged_values(emulator.emulate_function(emulator.symbols['ORACLECODEMESSAGE']), {})
        self.assertEqual(logged['CodeSeesMessage'], comma_text([self.log['CodeSeesMessage']]))


class TestTheEmulatorComputesPathsAsInnoSetupDid(TestBase):
    """
    The procedures `OraclePaths`, `OracleSiblings` and `OracleCurrentDir` of the sixth host oracle
    pass paths to the path functions of Setup and log the results.
    """

    def assertEmulatedAsLogged(self, procedure: str, *arguments: str):
        archive = InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe'))
        emulator = InnoSetupEmulator(archive, IFPSEmulatorConfig(
            log_calls=True,
            executable=R'W:\HostOracle6\host-oracle-6.exe',
        ))
        emulated = _logged_values(emulator.emulate_function(emulator.symbols[procedure], *arguments), {})
        log = codecs.decode(_archived_file(self, _HOST_ORACLE, 'host-oracle-6-normal.log'), 'utf8')
        logged = dict(match.groups() for line in log.splitlines() if (match := _ORACLE_LINE.fullmatch(line)))
        self.assertTrue(emulated)
        self.assertEqual(emulated, {name: logged[name] for name in emulated})

    def test_full_paths_follow_windows(self):
        self.assertEmulatedAsLogged('ORACLEPATHS')

    def test_the_support_functions_for_paths_follow_the_path_functions_of_inno_setup(self):
        self.assertEmulatedAsLogged('ORACLESIBLINGS')

    def test_the_current_folder_of_setup_is_the_folder_that_it_started_from(self):
        self.assertEmulatedAsLogged('ORACLECURRENTDIR', 'Setup')


class TestSetupInstallsForAllUsersAsItsSourceSays(TestBase):
    """
    Setup installs for all users when the user is an administrator and the installer does not ask
    for the lowest privileges; the privileges that an installer asks for are changed in memory.
    """

    def test_the_folder_of_programs_of_inno_setup_6_is_that_of_all_users_or_that_of_the_user(self):
        for privileges in PrivilegesRequired:
            for admin in (False, True):
                archive = InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe'))
                archive.setup_info.Header.PrivilegesRequired = privileges
                emulator = InnoSetupEmulator(archive, IFPSEmulatorConfig(admin=admin))
                for_all_users = admin and privileges is not PrivilegesRequired.Lowest
                with self.subTest(privileges=privileges.name, admin=admin):
                    self.assertEqual(emulator.setup.admin_install_mode, for_all_users)
                    self.assertEqual(
                        emulator.expand_constant('{autopf}'),
                        R'C:\Program Files' if for_all_users else R'C:\Users\Frank\AppData\Local\Programs',
                    )

    def test_inno_setup_5_takes_the_shell_folders_of_the_user_unless_it_installs_for_all_users(self):
        """
        The common folders of application data and of documents stay; cdbc92e0 is an installer of
        Inno Setup 5.5.3.
        """
        common = R'C:\Users\Public\Desktop|C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
        personal = R'C:\Users\Frank\Desktop|C:\Users\Frank\Start Menu\Programs'
        for privileges in (PrivilegesRequired.Admin, PrivilegesRequired.Lowest):
            for admin in (False, True):
                archive = InnoArchive(self.download_sample('cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c'))
                archive.setup_info.Header.PrivilegesRequired = privileges
                emulator = InnoSetupEmulator(archive, IFPSEmulatorConfig(admin=admin))
                for_all_users = admin and privileges is not PrivilegesRequired.Lowest
                with self.subTest(privileges=privileges.name, admin=admin):
                    self.assertEqual(
                        emulator.expand_constant('{commondesktop}|{commonprograms}'),
                        common if for_all_users else personal,
                    )
                    self.assertEqual(
                        emulator.expand_constant('{commonappdata}|{commondocs}'),
                        R'C:\ProgramData|C:\Users\Public\Documents',
                    )


class _HostOracleTest(TestBase):
    """
    Inno Setup 6.5.0 built the host oracle, an installer whose script logs the events that Setup
    sends, how Setup expands constants, the calls of the script that Setup makes for its entries,
    and Setup's texts, paths and wizard. It ran from a folder on the drive `W:` of 64-bit Windows
    with a log file, installing for the current user, once with the wizard and once silently; a
    check and a `BeforeInstall` function of its directories raise an error on purpose. The emulated
    machine has the variables `WINDIR` and `USERPROFILE` set, as every Windows has, and Setup starts
    from the drive `W:`.
    """

    def host_oracle(self) -> InnoArchive:
        return InnoArchive(_archived_file(self, _HOST_ORACLE, 'host-oracle-6.exe'))

    def emulator(self, archive: InnoArchive | IFPSFile | None = None, **config) -> InnoSetupEmulator:
        if archive is None:
            archive = self.host_oracle()
        return InnoSetupEmulator(archive, IFPSEmulatorConfig(
            log_calls=True,
            admin=False,
            executable=R'W:\HostOracle6\host-oracle-6.exe',
            environment={'WINDIR': R'C:\WINDOWS', 'USERPROFILE': R'C:\Users\Frank'},
            **config,
        ))

    def installation(self, archive: InnoArchive | IFPSFile | None = None, silent: bool = False) -> list[object]:
        return list(self.emulator(archive, wizard_silent=silent).emulate_installation())

    def events(self, archive: InnoArchive | IFPSFile | None = None, silent: bool = False) -> list[str]:
        """
        The events that the script logs in an emulated installation, in order.
        """
        return [value for name, value in _logged_lines(self.installation(archive, silent)) if _HOST_EVENT.fullmatch(name)]

    def errors(self, archive: InnoArchive | IFPSFile | None = None, silent: bool = False) -> list[object]:
        return [event for event in self.installation(archive, silent) if isinstance(event, (NewScriptError, NewEmulationError))]

    def assertLinesAsLogged(self, *names: str):
        """
        The lines with the given names that an emulated installation with the wizard logs are, in
        order, those that the run with the wizard logged.
        """
        def selected(lines: Iterable[tuple[str, str]]):
            return [line for line in lines if line[0] in names]
        logged = selected(_host_oracle_lines(self, 'normal'))
        self.assertTrue(logged)
        self.assertEqual(selected(_logged_lines(self.installation())), logged)


class TestTheEmulatorGivesTheScriptTheWizardAsInnoSetupDid(_HostOracleTest):

    def test_the_variables_of_setups_forms_stay_empty_until_setup_creates_each_form(self):
        """
        The oracle probes the variables and the functions of the wizard in `InitializeSetup`, in
        `InitializeWizard` and on the page of the user information.
        """
        self.assertLinesAsLogged(*(
            F'{when}{what}'
            for when in ('Setup', 'Wizard', 'UserInfoPage')
            for what in (
                'WizardFormVariable',
                'UninstallProgressFormVariable',
                'GetWizardForm',
                'PageIndexFromID',
                'PageFromID',
            )
        ))

    def test_a_property_of_the_empty_wizard_form_fails_past_the_innermost_except_block(self):
        self.assertLinesAsLogged('NilFormProperty')

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='an object that the emulator does not model is nil, like an empty variable',
    )
    def test_a_method_that_the_wizard_form_inherits_fails_past_the_innermost_except_block_on_the_empty_form(self):
        self.assertLinesAsLogged('NilFormMethod')

    def test_each_page_of_the_wizard_is_one_object_with_its_id(self):
        self.assertLinesAsLogged(
            'ProgressID',
            'Page1ID',
            'Page2ID',
            'PageAfterMissing',
            'Page3ID',
            'PageIndexes',
            'PageFromIDs',
            'PageFromIDMissing',
            'PageIndexFromIDMissing',
            'PageSame',
        )

    def test_setup_runs_the_handlers_that_the_script_sets_on_a_standard_page(self):
        self.assertLinesAsLogged('DirActivate', 'DirNextClick')

    def test_the_selection_of_a_text_box_follows_the_edit_control_of_windows(self):
        """
        The script sets a handler of its own on the box of the organization, which logs its text
        whenever it changes.
        """
        self.assertLinesAsLogged(
            'OrgChange',
            'SelectAfterText',
            'SelectText',
            'SelectAfterSelText',
            'SelectAll',
            'SelectCleared',
            'SelectClamped',
        )

    def test_setup_message_gives_the_message_of_the_active_language(self):
        """
        Inno Setup 6.5 removes the arrows from the texts of Back and Next.
        """
        self.assertLinesAsLogged(
            'MessageButtonBack',
            'MessageButtonNext',
            'MessageReadyMemoDir',
            'MessageFullInstallation',
            'MessageCustomInstallation',
            'MessageErrorInternal2',
        )

    def test_a_new_machine_has_no_previous_installation(self):
        self.assertLinesAsLogged('PrevAppDir', 'PreviousData')

    def test_the_function_main_form_of_inno_setup_5_fails_until_setup_created_its_main_form(self):
        """
        Scripts of Inno Setup 5 find the main form through the function `MainForm`, whose
        `GetMainForm` raises an internal error while Setup has not created the form; Setup creates
        it after `InitializeSetup`.
        """
        main_form = IFPSEmulator.external_symbols['']['MainForm'].call
        emulator = self.emulator()
        self.assertIs(main_form(emulator), emulator.wizard_form.main)
        self.assertIsNotNone(emulator.wizard_form.main)
        emulator.reset(walked=True)
        with self.assertRaisesRegex(InternalError, 'MainForm before it has been created'):
            main_form(emulator)


class TestTheTextBoxesOfTheWizardFollowTheEditControlOfWindows(_HostOracleTest):
    """
    The members of a text box as Delphi implements them with the edit control of Windows; the
    selections, texts and changes that the tests expect were measured with an edit control of
    Windows 11. The box of the program group is given the script's handler `OrgChange`, which logs
    the text of the box whenever the box notifies a change.
    """

    def box(self) -> tuple[InnoSetupEmulator, TextBox]:
        emulator = self.emulator()
        box = emulator.wizard_form.group_edit
        box.on_change = emulator.symbols['ORGCHANGE']
        return emulator, box

    def write(self, emulator: InnoSetupEmulator, box: TextBox, member: str, *arguments) -> list[str]:
        """
        Runs a member of the box that the script writes, and gives the texts that `OrgChange`
        logged.
        """
        namespace, _, name = member.partition('.')
        events = IFPSEmulator.external_symbols[namespace][name].call(emulator, box, *arguments)
        return [value for key, value in _logged_lines(events or ()) if key == 'OrgChange']

    def read(self, emulator: InnoSetupEmulator, box: TextBox, member: str):
        namespace, _, name = member.partition('.')
        return IFPSEmulator.external_symbols[namespace][name].call(emulator, box)

    def selection(self, emulator: InnoSetupEmulator, box: TextBox) -> tuple[int, int]:
        return self.read(emulator, box, 'TCustomEdit.GetSelStart'), self.read(emulator, box, 'TCustomEdit.GetSelLength')

    def test_a_negative_length_selects_the_characters_before_the_start(self):
        """
        Delphi's `SelLength` sends `EM_SETSEL` from the start to the start plus the length.
        """
        emulator, box = self.box()
        self.write(emulator, box, 'TCustomEdit.SetText', 'abcdef')
        self.write(emulator, box, 'TCustomEdit.SetSelStart', 3)
        self.write(emulator, box, 'TCustomEdit.SetSelLength', -1)
        self.assertEqual(self.selection(emulator, box), (2, 1))
        self.assertEqual(self.read(emulator, box, 'TCustomEdit.GetSelText'), 'c')

    def test_a_negative_start_other_than_minus_one_puts_the_caret_at_the_end(self):
        emulator, box = self.box()
        self.write(emulator, box, 'TCustomEdit.SetText', 'abcdef')
        self.write(emulator, box, 'TCustomEdit.SetSelStart', -5)
        self.assertEqual(self.selection(emulator, box), (6, 0))

    def test_a_box_in_upper_case_converts_every_text_that_it_receives_one_character_at_a_time(self):
        """
        The edit control keeps a character whose capital has more than one character, such as the
        German sharp s.
        """
        emulator, box = self.box()
        self.write(emulator, box, 'TEdit.SetCharCase', 1)
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.SetText', 'stra\u00dfe'), ['[STRA\u00dfE]'])
        self.write(emulator, box, 'TCustomEdit.SetSelStart', 0)
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.SetSelText', 'x'), ['[XSTRA\u00dfE]'])

    def test_clearing_a_box_notifies_a_change_also_when_the_box_is_empty(self):
        """
        Delphi's `Text` sends `WM_SETTEXT` only when the text differs; its `Clear` sends it always.
        """
        emulator, box = self.box()
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.SetText', ''), ['[]'])
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.SetText', ''), [])
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.Clear'), ['[]'])

    def test_replacing_an_empty_selection_notifies_a_change_but_clearing_it_does_not(self):
        """
        `SelText` sends `EM_REPLACESEL` and `ClearSelection` sends `WM_CLEAR`.
        """
        emulator, box = self.box()
        self.write(emulator, box, 'TCustomEdit.SetText', 'abc')
        self.write(emulator, box, 'TCustomEdit.SetSelStart', 1)
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.ClearSelection'), [])
        self.assertEqual(self.write(emulator, box, 'TCustomEdit.SetSelText', ''), ['[abc]'])


class TestTheEmulatorHostsTheScriptAsInnoSetupDid(_HostOracleTest):

    def test_initialize_setup_expands_constants_as_setup_did(self):
        """
        Right after `InitializeSetup`, Setup expands the code constant of the directive `AppName`;
        the lines before it are those of `InitializeSetup`. The values of `{app}`, `{group}`,
        `{uninstallexe}` and of the user information, and whether the wizard exists, depend on how
        far the installation got, which a run of `InitializeSetup` alone does not show; with the
        wizard, the probes of the empty wizard form also log the lines of their inner blocks.
        """
        log = _host_oracle_lines(self, 'normal')
        end = log.index(next(line for line in log if line[1] == 'code:AppName'))
        logged = dict(log[:end])
        emulator = self.emulator()
        emulated = _logged_values(emulator.emulate_function(emulator.symbols['INITIALIZESETUP']), {})
        progress = {
            'ConstAppEarly',
            'ConstGroupEarly',
            'ConstUninstallExeEarly',
            'WizardSetupTypeBeforeWizard',
            'SetupWizardFormVariable',
            'SetupGetWizardForm',
            'SetupWizardDirValue',
            'SetupWizardGroupValue',
            'SetupPageIndexFromID',
            'SetupPageFromID',
            'SetupUserInfo',
            'SetupGroupName',
            'NilFormProperty',
            'NilFormMethod',
        }
        compared = logged.keys() - progress - {'RegKeyExistsMissing', *_HOST_VALUES_THAT_ARE_NOT_EMULATED}
        inner = {'NilFormPropertyInner', 'NilFormMethodInner'}
        self.assertEqual(emulated.keys() - _HOST_VALUES_LEFT_OUT_OF_THE_LOGS - inner, logged.keys())
        self.assertEqual({name: emulated[name] for name in compared}, {name: logged[name] for name in compared})

    def test_an_installation_with_the_wizard_runs_the_script_as_setup_did(self):
        emulated = _comparable(_logged_lines(self.installation(silent=False)))
        self.assertEqual(emulated, _comparable(_host_oracle_lines(self, 'normal')))

    def test_a_silent_installation_runs_the_script_as_setup_did(self):
        """
        The silent run followed the run with the wizard, which left `file.a.txt` in the folder of
        the application. In its scan for the restart manager, Setup found that file as the source
        of the external file `file.copy` and expanded its destination; the emulated machine starts
        without it.
        """
        emulated = _comparable(_logged_lines(self.installation(silent=True)))
        logged = _comparable(_host_oracle_lines(self, 'silent'))
        logged.remove('Event = code:file.copy.destdir')
        self.assertEqual(emulated, logged)

    def test_each_installation_reports_the_two_script_errors_that_setup_showed(self):
        for silent in (False, True):
            with self.subTest(silent=silent):
                self.assertEqual([str(error) for error in self.errors(silent=silent)], [
                    'script error in Check of [Dirs] entry 10: Error calling RaiseException: oracle check error dir.k',
                    'script error in BeforeInstall of [Dirs] entry 11: Error calling RaiseException: oracle install error dir.l',
                ])

    def test_setup_expands_the_code_constants_of_its_directives_as_setup_did(self):
        """
        The code constants of the directives of `[Setup]` pass the name of the directive.
        """
        def code_constants(lines: Iterable[tuple[str, str]]):
            return [value for name, value in lines if _HOST_EVENT.fullmatch(name) and re.fullmatch(r'code:[A-Za-z]+', value)]
        self.assertEqual(
            code_constants(_logged_lines(self.installation())),
            code_constants(_host_oracle_lines(self, 'normal')),
        )

    def test_setup_passes_the_texts_of_the_ready_memo_as_setup_did(self):
        def memo(values: dict[str, str]):
            return {name: value for name, value in values.items() if name.startswith('ReadyMemo')}
        self.assertEqual(memo(_logged_values(self.installation(), {})), memo(_host_oracle_log(self, 'normal')))

    def test_check_serial_receives_the_default_serial_number(self):
        self.assertIn('CheckSerial(1)', self.events())

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='the emulated RegKeyExists finds every key')
    def test_a_key_that_windows_does_not_have_does_not_exist(self):
        emulated = _logged_values(self.installation(), {})
        self.assertEqual(emulated['RegKeyExistsMissing'], _host_oracle_log(self, 'normal')['RegKeyExistsMissing'])

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='the emulated registry has none of the keys that every Windows has')
    def test_a_registry_value_that_does_not_create_its_key_is_written_into_a_key_that_windows_has(self):
        """
        The entry writes a value under `HKCU\\Software` with the flag `dontcreatekey`; Setup
        expands its data only when the key exists.
        """
        self.assertIn('code:registry.d.valuedata', self.events())

    def test_setup_does_not_ask_the_script_for_the_ready_memo_when_the_header_disables_the_memo(self):
        """
        The parsed header of the installer is changed as the directive `DisableReadyMemo` changes
        it.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.Flags |= Flags.DisableReadyMemo
        events = self.events(archive)
        self.assertIn('CurPageChanged(10)', events)
        self.assertNotIn('UpdateReadyMemo', events)

    def test_a_silent_installation_of_the_script_alone_never_shows_the_license_page(self):
        """
        Without its installer, the script runs as if every page were shown; a silent Setup still
        skips the license page on its own.
        """
        script = self.host_oracle().ifps
        assert script is not None
        normal = self.events(script, silent=False)
        silent = self.events(script, silent=True)
        self.assertIn('ShouldSkipPage(2)', normal)
        self.assertNotIn('ShouldSkipPage(2)', silent)
        self.assertNotIn('CurPageChanged(2)', silent)

    def test_each_release_of_setup_behaves_as_its_source_says(self):
        """
        The behavior of Setup that changed between releases, by the release that changed it.
        """
        changes = {
            'prepares_with_selection'                : ((5, 5, 1), None),
            'registers_close_applications_resources' : ((5, 5, 2), None),
            'evaluates_change_directives'            : ((6, 0, 0), None),
            'downloads_archives'                     : ((6, 5, 0), None),
            'page_changes_only'                      : ((6, 5, 0), (6, 6, 0)),
            'download_tests_components_as_tasks'     : ((6, 5, 0), (6, 5, 2)),
            'run_working_dir_always'                 : ((7, 0, 0), None),
        }
        for release in ((5, 5, 0), (5, 5, 1), (5, 5, 2), (6, 0, 0), (6, 5, 0), (6, 5, 1), (6, 5, 2), (6, 6, 0), (7, 0, 0)):
            build = 'x86' if release >= (7, 0, 0) else 'inno6'
            script = IFPSFile.Parse(_value_oracle_file(self, build, 'ifps'))
            setup = InnoSetupEmulator(script, IFPSEmulatorConfig(setup_version=release)).setup
            with self.subTest(release=release):
                self.assertEqual(
                    {name: getattr(setup, name) for name in changes},
                    {name: first <= release and (last is None or release < last) for name, (first, last) in changes.items()},
                )

    def install_mode_values(self, archive: InnoArchive) -> dict[str, str]:
        emulator = self.emulator(archive)
        logged = _logged_values(emulator.emulate_function(emulator.symbols['INITIALIZESETUP']), {})
        return {name: logged[name] for name in _HOST_VALUES_OF_THE_INSTALL_MODE}

    def test_a_setup_in_64_bit_install_mode_gives_the_values_that_setup_gave(self):
        log = _host_oracle_log(self, 'normal')
        self.assertEqual(
            self.install_mode_values(self.host_oracle()),
            {name: log[name] for name in _HOST_VALUES_OF_THE_INSTALL_MODE},
        )

    def test_a_setup_in_64_bit_install_mode_reads_the_folder_of_the_64_bit_dotnet_framework(self):
        emulator = self.emulator(self.host_oracle())
        logged = _logged_values(emulator.emulate_function(emulator.symbols['INITIALIZESETUP']), {})
        self.assertEqual(logged['ConstDotNet40Mode'], _host_oracle_log(self, 'normal')['ConstDotNet40Mode'])

    def test_a_setup_in_32_bit_install_mode_gives_the_values_that_setup_gave(self):
        """
        The parsed header of the installer is changed as a script without the directive
        `ArchitecturesInstallIn64BitMode` changes it.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.ArchitecturesInstallIn64BitMode = ''
        self.assertEqual(self.install_mode_values(archive), _HOST_LOG_OF_A_32_BIT_INSTALL_MODE)

    def test_a_script_of_a_64_bit_setup_installs_in_64_bit_mode_without_its_installer(self):
        """
        A 64-bit Setup installs in 64-bit mode unless its directive says otherwise.
        """
        script = IFPSFile.Parse(_value_oracle_file(self, 'x64', 'ifps'))
        emulator = InnoSetupEmulator(script, IFPSEmulatorConfig(setup_version=(7, 1, 0)))
        self.assertEqual(emulator.expand_constant('{commonpf}'), R'C:\Program Files')

    def test_a_script_of_a_32_bit_setup_installs_in_32_bit_mode_without_its_installer(self):
        """
        A 32-bit Setup installs in 32-bit mode unless its directive says otherwise.
        """
        script = IFPSFile.Parse(_value_oracle_file(self, 'inno6', 'ifps'))
        emulator = InnoSetupEmulator(script, IFPSEmulatorConfig(setup_version=(6, 5, 0)))
        self.assertEqual(emulator.expand_constant('{commonpf}'), R'C:\Program Files (x86)')

    def test_an_architecture_that_the_emulator_does_not_know_leaves_the_install_mode_undecided(self):
        """
        The parsed header of the installer is changed as a directive with an identifier of a later
        Setup would change it. Only the values that follow the install mode fail.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.ArchitecturesInstallIn64BitMode = 'nosucharchitecture or x64compatible'
        emulator = self.emulator(archive)
        self.assertEqual(
            emulator.setup.install_mode.reason,
            'Internal error: Expression error \'Unknown architecture \'nosucharchitecture\'\'',
        )
        with self.assertRaises(NotImplementedError):
            emulator.expand_constant('{commonpf}')
        self.assertEqual(emulator.expand_constant('{commonpf32}'), R'C:\Program Files (x86)')

    def test_an_architecture_directive_that_nests_deeper_than_python_follows_leaves_the_install_mode_undecided(self):
        depth = sys.getrecursionlimit()
        archive = self.host_oracle()
        opening = '(' * depth
        closing = ')' * depth
        archive.setup_info.Header.ArchitecturesInstallIn64BitMode = F'{opening}x64compatible{closing}'
        emulator = self.emulator(archive)
        self.assertIsNone(emulator.setup.install_mode.bits64)
        with self.assertRaises(NotImplementedError):
            emulator.expand_constant('{commonpf}')

    def test_a_method_of_a_class_receives_its_object_and_every_value(self):
        """
        On the tasks page, the script of the installer calls a method of the task list as
        `TasksList.CheckItem(I, coUncheck)`, first for the index 0; `coUncheck` is 0.
        """
        emulator = self.emulator()
        calls = [
            event.args for event in emulator.emulate_function(emulator.symbols['CurPageChanged'], PageID.wpSelectTasks)
            if isinstance(event, NewFunctionCall) and event.name == 'TNewCheckListBox.CheckItem'
        ]
        self.assertEqual(len(calls[0]), 3)
        self.assertEqual(calls[0][1:], (0, 0))

    def test_a_function_of_the_wizard_fails_before_setup_creates_the_wizard(self):
        """
        Setup sends `InitializeSetup` and runs the checks of the components before it creates the
        wizard.
        """
        emulated = _logged_values(self.installation(), {})
        log = _host_oracle_log(self, 'normal')
        for name in ('WizardSetupTypeBeforeWizard', 'WizardInComponentCheck'):
            with self.subTest(name=name):
                self.assertEqual(emulated[name], log[name])

    def test_the_current_file_is_known_only_in_a_function_of_a_file_entry(self):
        emulated = _logged_values(self.installation(), {})
        log = _host_oracle_log(self, 'normal')
        self.assertEqual(emulated['CurrentFilenameInEvent'], log['CurrentFilenameInEvent'])

    @wontfix('the progress of an installation counts the bytes that Setup installs, and the emulator installs none')
    def test_an_installation_reports_its_progress(self):
        emulated = _logged_values(self.installation(), {})
        log = _host_oracle_log(self, 'normal')
        self.assertEqual(
            (emulated['ProgressCalls'], emulated['ProgressLast']),
            (log['ProgressCalls'], log['ProgressLast']),
        )

    @wontfix('the emulator does not know the environment of the machine; a variable that the configuration does not name stays %NAME%')
    def test_an_environment_variable_that_is_not_set_expands_to_an_empty_text(self):
        expanded = self.emulator().expand_constant('{%NOSUCHORACLEVARIABLE}')
        self.assertEqual(F'[{expanded}]', _host_oracle_log(self, 'normal')['ConstEnvMissing'])


class TestTheEmulatorGivesSetupsTextsAsInnoSetupDid(_HostOracleTest):
    """
    The texts that Setup proposes, tidies and takes: the directives of `[Setup]`, the boxes of the
    wizard, the user information, the folder, the program group, the uninstaller and the memo of
    the ready page. Where a test changes the installer in memory, it says how.
    """

    def test_the_boxes_of_the_wizard_hold_setups_texts_wherever_the_script_reads_them(self):
        names = {
            name for name, _ in _host_oracle_lines(self, 'normal')
            if name.endswith(('Edit', 'WizardDirValue', 'WizardGroupValue'))
        }
        self.assertLinesAsLogged(*names)

    def test_check_serial_runs_whenever_a_box_of_the_user_information_changes_on_its_page(self):
        """
        The script writes the serial twice, then the name with spaces around it, and replaces the
        handler of the box of the organization with one of its own; Next trims the name.
        """
        def serial_checks(lines: Iterable[tuple[str, str]]):
            return [
                value for name, value in lines
                if _HOST_EVENT.fullmatch(name) and value.startswith('CheckSerial')
                or name in ('CheckSerialUserInfo', 'UserInfoAfterChanges', 'UserInfoOnNext')
            ]
        self.assertEqual(serial_checks(_logged_lines(self.installation())), serial_checks(_host_oracle_lines(self, 'normal')))

    def test_setup_tidies_the_folder_and_the_group_where_it_takes_them(self):
        """
        On the page of the folder, the script puts spaces and slashes around the folder and the
        group.
        """
        self.assertLinesAsLogged(
            'ConstAppInWizard',
            'ConstAppOnPasswordNext',
            'ConstAppOnDirNext',
            'GroupNameOnTasksPage',
            'GroupOnTasksPage',
            'ConstGroupOnReadyNext',
            'ConstGroupNameOnReadyNext',
            'ConstAppOnInstall',
            'ConstGroupOnInstall',
            'ConstGroupNameOnInstall',
        )

    def test_the_current_folder_becomes_the_system_folder_when_setup_installs(self):
        self.assertLinesAsLogged(*(
            F'{when}{what}'
            for when in ('Setup', 'Install', 'PostInstall')
            for what in ('CurrentDirIsSrc', 'CurrentDirIsSys', 'RelativeExpand')
        ))

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='SetCurrentDir does not change the current folder')
    def test_set_current_dir_changes_the_folder_that_get_current_dir_gives(self):
        """
        Setup's `SetCurrentDir` makes an existing folder the current folder of the process; the
        installation created the folder of the application.
        """
        emulator = self.emulator()
        list(emulator.emulate_installation())
        app = emulator.expand_constant('{app}')
        handlers = IFPSEmulator.external_symbols['']
        self.assertIn('SetCurrentDir', handlers)
        self.assertTrue(handlers['SetCurrentDir'].call(emulator, app))
        self.assertEqual(handlers['GetCurrentDir'].call(emulator), app)

    def test_the_uninstaller_is_named_in_the_folder_of_the_uninstall_files(self):
        self.assertLinesAsLogged('ConstUninstallExeEarly', 'ConstUninstallExeOnInstall', 'ConstUninstallExeAfterInstall')

    def test_the_installation_creates_the_folder_of_the_application_and_no_stand_in(self):
        emulator = self.emulator()
        list(emulator.emulate_installation())
        self.assertEqual(emulator.expand_constant('{app}'), R'C:\Users\Frank\AppData\Roaming\HostOracle6\sub\x')
        self.assertTrue(emulator.DirExists(emulator.expand_constant('{app}')))
        self.assertFalse(emulator.DirExists('I:\\'))

    def test_a_default_type_takes_its_description_from_the_messages(self):
        """
        The first type of the installer is changed in memory to the default type of a full
        installation, whose description Setup takes from its message `FullInstallation`.
        """
        archive = self.host_oracle()
        archive.setup_info.Types[0].SetupType = SetupTypeEnum.DefaultFull
        emulated = _logged_values(self.installation(archive), {})
        self.assertEqual(emulated['InstallSetupTypeDescription'], 'Full installation')
        self.assertEqual(emulated['ReadyMemoType'], 'Setup type:|      Full installation')

    def test_an_error_in_the_default_folder_is_reported_and_setup_refuses_the_empty_folder(self):
        """
        The default folder of the installer is changed in memory to call a function that the script
        does not have, and the installer to refuse a folder on a network share. The box of the
        folder stays empty; the script then puts spaces and slashes around it, which makes it the
        path of a share, and Setup refuses it.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.DefaultDirName = '{code:NoSuchOracleFunction}'
        archive.setup_info.Header.Flags &= ~Flags.AllowUNCPath
        installation = self.installation(archive)
        errors = [error.name for error in installation if isinstance(error, NewScriptError)]
        self.assertIn(TextDirective.DefaultDirName, errors)
        emulated = _logged_values(installation, {})
        self.assertEqual(emulated['WizardDirEdit'], '[]')
        self.assertEqual(emulated['ConstAppOnInstall'], R'[I:\]')

    def test_setup_does_not_tidy_the_folder_that_the_user_entered_after_a_refusal_when_it_installs(self):
        """
        The installer is changed in memory as in the test above, so that Setup refuses the folder;
        the box of the folder is given the script's handler `OrgChange`, which logs the text of the
        box whenever the box notifies a change. The emulated user then enters a folder that Setup
        accepts, and tidying it when Setup installs leaves it as it is.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.DefaultDirName = '{code:NoSuchOracleFunction}'
        archive.setup_info.Header.Flags &= ~Flags.AllowUNCPath
        emulator = self.emulator(archive)
        reset = emulator.reset

        def reset_with_a_handler_on_the_folder_box(walked: bool = False):
            reset(walked)
            emulator.wizard_form.dir_edit.on_change = emulator.symbols['ORGCHANGE']
            return emulator

        with mock.patch.object(emulator, 'reset', reset_with_a_handler_on_the_folder_box):
            changes = [value for name, value in _logged_lines(emulator.emulate_installation()) if name == 'OrgChange']
        self.assertEqual(emulator.expand_constant('{app}'), 'I:\\')
        self.assertNotIn('[I:\\]', changes)

    def test_a_default_folder_that_the_emulator_cannot_make_a_full_path_is_reported_and_setup_goes_on(self):
        """
        The default folder of the installer is changed in memory to end in the name of a device,
        which the emulator does not model.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.DefaultDirName = 'C:\\Apps\\CON'
        installation = self.installation(archive)
        failures = [error.name for error in installation if isinstance(error, NewEmulationError)]
        self.assertIn(TextDirective.DefaultDirName, failures)
        self.assertIn('DeinitializeSetup', self.events(archive))

    def test_the_uninstaller_of_a_script_without_its_installer_is_in_the_folder_of_the_application(self):
        """
        Setup's default folder of the uninstall files is `{app}`; the compiled script of the second
        build of the host oracle runs without its installer.
        """
        emulator = self.emulator(IFPSFile.Parse(_archived_file(self, _HOST_ORACLE, 'host-oracle-6-run2.ifps')))
        list(emulator.emulate_installation())
        self.assertEqual(emulator.expand_constant('{uninstallexe}'), emulator.expand_constant('{app}\\unins000.exe'))

    def test_the_ready_memo_has_no_text_of_the_type_when_every_type_fails_its_check(self):
        """
        Every type of the installer is changed in memory to a check that fails. Setup then has no
        type, for which its `UpdateReadyPage` gives no text.
        """
        archive = self.host_oracle()
        for setup_type in archive.setup_info.Types:
            setup_type.Check = 'Chk(\'-type.none\')'
        emulated = _logged_values(self.installation(archive), {})
        self.assertEqual(emulated['ReadyMemoType'], '')

    def test_a_check_of_the_serial_that_fails_while_setup_trims_the_name_is_reported_and_refuses_the_serial(self):
        """
        The default name of the installer is changed in memory to have spaces around it, and the
        function `ChkRaises`, which raises an error, is made the script's `CheckSerial`. Setup
        disables Next when the check fails; the emulated user enters a serial that the emulator
        does not know.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.DefaultUsername = ' Oracle '
        emulator = self.emulator(archive)
        emulator.symbols['CheckSerial'] = emulator.symbols['CHKRAISES']
        installation = list(emulator.emulate_installation())
        errors = [str(error) for error in installation if isinstance(error, NewScriptError)]
        self.assertIn('script error in OnChange(UserInfoNameEdit,): Error calling RaiseException: oracle check error 2', errors)
        self.assertEqual(emulator.expand_constant('{userinfoname}|{userinfoserial}'), 'Oracle|{userinfoserial}')

    def test_setup_keeps_the_arrows_of_back_and_next_before_inno_setup_6_1_1(self):
        """
        Inno Setup 6.1.1 removed them; cdbc92e0 is an installer of Inno Setup 5.5.3.
        """
        archive = InnoArchive(self.download_sample('cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c'))
        setup = InnoSetupEmulator(archive, IFPSEmulatorConfig()).setup
        self.assertEqual(setup.named_message(SetupMessageName.ButtonBack), '< &Back')
        self.assertEqual(setup.named_message(SetupMessageName.ButtonNext), '&Next >')

    def test_an_internal_error_of_setup_has_the_frame_of_the_active_language(self):
        """
        The installer has a Dutch language, whose message `ErrorInternal2` is `Interne fout: %1`.
        """
        frame = 'raised: Internal error: '
        logged = {name: value for name, value in _host_oracle_lines(self, 'normal') if value.startswith(frame)}
        dutch = _logged_values(list(self.emulator(language='nl').emulate_installation()), {})
        self.assertTrue(logged)
        self.assertEqual(
            {name: dutch.get(name) for name in logged},
            {name: value.replace(frame, 'raised: Interne fout: ') for name, value in logged.items()},
        )

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='an error of a check is reported as the error of the script')
    def test_setup_reports_an_error_of_a_check_as_an_internal_error_of_its_expression(self):
        """
        Setup's `EvalCheck` raises every error of a check as an internal error of the expression,
        and an error of the script has the place in the script where it happened.
        """
        errors = [error for error in self.installation() if isinstance(error, NewScriptError) and error.name == EntryParameter.Check]
        self.assertTrue(errors)
        for error in errors:
            self.assertTrue(error.message.startswith('Internal error: Expression error \'Runtime error (at '))


class TestTheSecondBuildOfTheHostOracleFailedAsInnoSetupDid(_HostOracleTest):
    """
    The second build of the host oracle has the same `[Setup]` as the first one; its compiled script
    is put into the installer in memory. Its `CheckSerial` raises an error for the serial `3`, which
    the script writes while the page of the user information is shown, inside a try block; it also
    changes the `CharCase` of the box of the organization. After the error, Pascal Script failed in
    the next event with an unrelated error, and Setup could not go on; the run ended there.
    """

    def installer(self) -> InnoArchive:
        archive = self.host_oracle()
        archive.ifps = IFPSFile.Parse(_archived_file(self, _HOST_ORACLE, 'host-oracle-6-run2.ifps'))
        return archive

    def logged(self) -> list[tuple[str, str]]:
        log = codecs.decode(_archived_file(self, _HOST_ORACLE, 'host-oracle-6-run2-normal.log'), 'utf8')
        return [(match[1], match[2]) for line in log.splitlines() if (match := _ORACLE_LINE.fullmatch(line))]

    def test_an_error_of_check_serial_reaches_the_script_that_wrote_the_serial(self):
        logged = self.logged()
        end = logged.index(next(line for line in logged if line[0] == 'UserInfoAfterChanges')) + 1
        expected = _comparable(logged[:end])
        emulated = _comparable(_logged_lines(self.installation(self.installer())))
        self.assertEqual(emulated[:len(expected)], expected)

    @wontfix('a script that raises an error in its own check of the serial while it writes the serial is made up for the oracle')
    def test_pascal_script_fails_after_an_error_of_check_serial_inside_a_change_of_the_serial(self):
        logged = _comparable(self.logged())
        emulated = _comparable(_logged_lines(self.installation(self.installer())))
        self.assertEqual(emulated, logged)


class TestTheEmulatorRunsTheEntriesAsInnoSetupDid(_HostOracleTest):
    """
    The entries of the host oracle name the functions of its script as their checks and as their
    `BeforeInstall` and `AfterInstall` functions, and have code constants in their fields; each of
    these functions logs its name, the name of the entry and, for a file, the names of the current
    file. A check fails when the name of the entry starts with a minus. The tests compare what
    the run with the wizard logged, or change the installer in memory for what no run shows.
    """

    def assertLinesAsLogged(self, *names: str):
        emulated = _logged_values(self.installation(), {})
        log = _host_oracle_log(self, 'normal')
        self.assertEqual({name: emulated.get(name) for name in names}, {name: log[name] for name in names})

    def assertEventsAsLogged(self, *entries: str):
        def events(lines: Iterable[tuple[str, str]]):
            return [value for name, value in lines if _HOST_EVENT.fullmatch(name) and any(entry in value for entry in entries)]
        self.assertEqual(events(_logged_lines(self.installation())), events(_host_oracle_lines(self, 'normal')))

    def test_a_component_or_task_for_another_windows_hides_the_entries_below_it(self):
        """
        The component `older` and the task `oldtask` are only for Windows before 6.0, their children
        are for every Windows.
        """
        self.assertLinesAsLogged('WizardComponents', 'TasksPageTasks')
        self.assertEventsAsLogged('older', 'oldtask')

    def test_a_component_that_repeats_the_name_of_the_one_before_it_lets_the_children_of_that_one_follow(self):
        """
        The second component `dup` fails its check; the child `dup\\child` follows the first one.
        """
        self.assertLinesAsLogged('WizardComponents')
        self.assertEventsAsLogged('component.dup')

    def test_the_lists_of_the_wizard_hold_the_choices_that_setup_made_and_change_as_in_setup(self):
        self.assertLinesAsLogged(
            'ComponentsList',
            'ComponentsListOutOfRange',
            'TasksList',
            'TasksListCheckItem0',
            'TasksListCheckItem3',
            'TasksListCheckItem6',
            'TasksListCheckItem9',
            'TasksListCheckItem12',
            'TasksListChanged',
            'TasksListChangedTasks',
            'RunList',
            'RunListChanged',
        )

    def test_a_list_of_tasks_ends_at_its_first_nul_character(self):
        self.assertLinesAsLogged('AfterSelectTasksWithNulTasks')

    def test_the_scan_of_the_preparing_page_keeps_the_selection_from_before_prepare_to_install(self):
        """
        `PrepareToInstall` unchecks the task `unchecked`, which the file `file.d` is for: the scan
        of the restart manager runs its check, the installation does not.
        """
        self.assertLinesAsLogged('PrepareTasks', 'InstallTasks')
        self.assertEventsAsLogged('(file.d)')

    def test_a_download_expands_its_source_destination_and_credentials_around_its_functions(self):
        self.assertEventsAsLogged('file.dl')

    def test_an_external_file_whose_source_the_installation_created_expands_its_destination(self):
        self.assertEventsAsLogged('file.copy')

    def test_an_icon_or_a_run_entry_that_needs_its_file_expands_its_fields_only_when_the_file_exists(self):
        self.assertEventsAsLogged('icon.c', 'icon.d', 'run.c', 'run.d')

    def test_a_break_in_a_registry_value_of_several_strings_is_a_constant(self):
        self.assertEventsAsLogged('registry.c')

    def test_a_downloaded_archive_expands_its_source_when_setup_prepares_and_its_password_when_it_installs(self):
        """
        The download of the installer is changed in memory into a download of an archive whose check
        passes and whose password is a code constant. Setup downloads the archive when it prepares;
        the restart manager's scan and the installation then find the archive in the temporary
        folder and expand its folder and its password.
        """
        archive = self.host_oracle()
        entry = archive.setup_info.Files[7]
        entry.Condition.Check = 'Chk(\'file.download\')'
        entry.Flags |= SetupFileFlags.ExtractArchive
        entry.ExtractArchivePassword = '{code:Code|file.download.archivepassword}'
        events = [event for event in self.events(archive) if event.startswith('code:file.download')]
        self.assertEqual(events, [
            'code:file.download.source',
            'code:file.download.destdir',
            'code:file.download.archivepassword',
            'code:file.download.destdir',
            'code:file.download.archivepassword',
        ])

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='the emulator does not show the page on which Setup downloads archives')
    def test_setup_shows_its_download_page_when_it_downloads_an_archive(self):
        """
        Setup adds its download page after the four pages that the script creates.
        """
        archive = self.host_oracle()
        entry = archive.setup_info.Files[7]
        entry.Condition.Check = 'Chk(\'file.download\')'
        entry.Flags |= SetupFileFlags.ExtractArchive
        self.assertIn('CurPageChanged(104)', self.events(archive))

    def test_a_run_entry_of_a_setup_before_5_1_13_runs_without_a_verb(self):
        """
        Setup before 5.1.13 has no verb for its run entries; the parsed entries are changed in
        memory as the parser reads such an entry.
        """
        archive = self.host_oracle()
        for entry in archive.setup_info.RunEntries:
            entry.Verb = None
            entry.Flags |= SetupRunFlags.ShellExec
        self.assertEqual(self.events(archive)[-3:], ['CurStepChanged(3)', 'GetCustomSetupExitCode', 'DeinitializeSetup'])

    def test_an_error_in_a_field_of_a_component_or_a_task_names_its_entry(self):
        """
        The descriptions of the component `optional` and of the task `radio2` are changed in memory
        to call a function that the script does not have.
        """
        archive = self.host_oracle()
        archive.setup_info.Components[6].Description = '{code:NoSuchOracleFunction}'
        archive.setup_info.Tasks[7].Description = '{code:NoSuchOracleFunction}'
        lists = (EntrySection.Components, EntrySection.Tasks)
        located = {
            error.entry for error in self.errors(archive)
            if isinstance(error, NewScriptError) and error.entry is not None and error.entry.section in lists
        }
        self.assertEqual(located, {
            EntryLocation(EntrySection.Components, 6, EntryField.Description),
            EntryLocation(EntrySection.Tasks, 7, EntryField.Description),
        })

    def test_setup_skips_the_page_of_the_program_group_without_an_icon_for_the_emulated_windows(self):
        """
        The page is changed in memory to be shown; then each icon is changed to be only for Windows
        before 6.0, as the component `old` is.
        """
        archive = self.host_oracle()
        archive.setup_info.Header.DisableProgramGroupPage = AutoBool.No
        self.assertIn('ShouldSkipPage(8)', self.events(archive))
        old = archive.setup_info.Components[8]
        for icon in archive.setup_info.Icons:
            icon.WindowsVersion = old.WindowsVersion
        self.assertNotIn('ShouldSkipPage(8)', self.events(archive))

    def test_a_call_from_setup_that_the_function_of_the_script_cannot_take_ends_the_emulation(self):
        """
        The check of the directory `dir.i` is changed in memory to calls that the declarations of
        the functions of the script do not take, and the function `NeedRestart` gets a parameter
        that the event does not pass.
        """
        for check in (
            'ChkArgs(\'dir.i\', \'abc\', true, \'x\')',
            'ChkArgs(42, 42, true, \'x\')',
            'PrepareToInstall(true)',
            'Code(\'dir.i\')',
        ):
            archive = self.host_oracle()
            archive.setup_info.Directories[8].Condition.Check = check
            with self.subTest(check=check), self.assertRaises(EmulatorUndefined):
                self.installation(archive)
        emulator = self.emulator()
        decl = emulator.symbols['NeedRestart'].decl
        assert decl is not None
        decl.parameters.append(DeclSpecParam(True, None, 'Extra'))
        with self.assertRaises(EmulatorUndefined):
            list(emulator.emulate_installation())

    def test_a_check_that_nests_deeper_than_python_follows_ends_the_emulation(self):
        archive = self.host_oracle()
        negations = 'not ' * sys.getrecursionlimit()
        archive.setup_info.Directories[8].Condition.Check = F'{negations}Chk(\'dir.i\')'
        with self.assertRaises(EmulatorMaxCalls):
            self.installation(archive)

    def test_a_check_that_names_a_support_function_without_a_recorded_result_runs_it(self):
        """
        Pascal Script records no result type for some imported functions, such as the DLL imports
        and `FileCopy` of the stored scripts; Setup takes the result of a check as a Boolean of its
        own. The check of the directory `dir.i` is changed in memory to `IsWin64`, whose recorded
        result type is removed; the emulated Windows is 64-bit.
        """
        archive = self.host_oracle()
        archive.setup_info.Directories[8].Condition.Check = 'IsWin64'
        emulator = self.emulator(archive)
        decl = emulator.symbols['IsWin64'].decl
        assert decl is not None
        decl.return_type = None
        list(emulator.emulate_installation())
        self.assertTrue(emulator.DirExists(emulator.expand_constant('{app}\\dir.i')))

    def test_a_downloaded_archive_names_its_folder_with_a_backslash_at_the_end(self):
        """
        Setup sets the destination of a downloaded archive to `PathExtractPath` of its file name,
        which keeps the backslash at the end. The download of the installer is changed in memory
        into a download of an archive whose check passes.
        """
        archive = self.host_oracle()
        entry = archive.setup_info.Files[7]
        entry.Condition.Check = 'Chk(\'file.download\')'
        entry.Flags |= SetupFileFlags.ExtractArchive
        names = {
            event.partition(' source=')[0] for event in self.events(archive)
            if event.startswith('BeforeInstall(file.download)')
        }
        self.assertEqual(names, {'BeforeInstall(file.download) name=[{app}{code:Code|file.download.destdir}\\]'})

    def test_an_error_in_the_fields_of_one_archive_to_download_downloads_no_archive(self):
        """
        Setup expands the fields of every archive to download before it downloads any. The download
        of the installer and the download `file.dl` are changed in memory into downloads of archives
        whose checks pass; the password of the second one calls a function that the script does not
        have.
        """
        archive = self.host_oracle()
        for number, name in ((7, 'file.download'), (10, 'file.dl')):
            entry = archive.setup_info.Files[number]
            entry.Condition.Check = F'Chk(\'{name}\')'
            entry.Flags |= SetupFileFlags.ExtractArchive
        archive.setup_info.Files[10].DownloadPassword = '{code:NoSuchOracleFunction}'
        sources = [event for event in self.events(archive) if '_isetup' in event]
        self.assertEqual(sources, [])

    def test_the_installation_creates_the_files_of_its_ini_entries_and_its_shortcuts(self):
        """
        The installer writes `oracle.ini` into the folder of the application and two shortcuts into
        the program group, `Oracle` and `Oracle C`; the shortcut `Oracle D` is only created when
        its file exists, and it does not.
        """
        emulator = self.emulator()
        list(emulator.emulate_installation())
        created = {
            name: emulator.FileExists(emulator.expand_constant(name)) for name in (
                '{app}\\oracle.ini',
                '{group}\\Oracle.lnk',
                '{group}\\Oracle C.lnk',
                '{group}\\Oracle D.lnk',
            )
        }
        self.assertEqual(created, {
            '{app}\\oracle.ini': True,
            '{group}\\Oracle.lnk': True,
            '{group}\\Oracle C.lnk': True,
            '{group}\\Oracle D.lnk': False,
        })

    def test_an_error_in_the_tasks_of_an_entry_is_reported_when_its_components_are_not_selected(self):
        """
        Setup tests the components, the tasks and the languages of an entry each in full. The
        directory `dir.d` is changed in memory to be for a component that does not exist and for a
        broken expression of tasks.
        """
        archive = self.host_oracle()
        condition = archive.setup_info.Directories[3].Condition
        condition.Components = 'nosuchcomponent'
        condition.Tasks = 'a)'
        errors = [
            error for error in self.errors(archive)
            if isinstance(error, NewScriptError) and error.entry == EntryLocation(EntrySection.Dirs, 3)
        ]
        self.assertEqual(errors, [NewScriptError(
            EntryParameter.Tasks,
            (),
            'Internal error: Expression error \'Invalid token \')\' found\'',
            EntryLocation(EntrySection.Dirs, 3),
        )])
