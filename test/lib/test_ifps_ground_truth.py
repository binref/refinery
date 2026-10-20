import codecs
import pytest
import re
import tracemalloc

from itertools import zip_longest
from typing import Iterable

from fractions import Fraction

from refinery.lib.inno.archive import Flags, InnoArchive
from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
from refinery.lib.inno.emulation import EmulatorMaxArray, EmulatorMaxString, EmulatorUndefined, NewFunctionCall
from refinery.lib.inno.pascal import IFPSException
from refinery.lib.inno.ifps import TC, AOp, Dialect, Function, IFPSFile, Op, Operand, Value
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


def _value_oracle_file(test: TestBase, build: str, extension: str) -> buf:
    name = F'value-oracle-7c-{build}.{extension}'
    for file in SzArchive(test.download_sample(_VALUE_ORACLE)).files:
        if file.name == name:
            return file.extractor(None)()
    raise LookupError(name)


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

_HOST_INSTALLER = '6b237b785ae7f7d5fae8d87d7b3015a2fdf296d1b74286a85c1906c141edae22'
_HOST_LOG_OF_INITIALIZE_SETUP = {
    'Event001'               : 'InitializeSetup',
    'ConstLoneBrace'         : '[a}b]',
    'ConstEscapedBrace'      : '[{tmp}]',
    'ConstBackslash'         : R'[\x]',
    'ConstBackslashTwice'    : R'[\\x]',
    'ConstNested'            : R'[\]',
    'ConstCodeNested'        : '[z]',
    'ConstPercent'           : '[a}b]',
    'ConstPercentBrace'      : R'[\]',
    'ConstPercentBad'        : 'raised: Internal error: Failed to parse "code" constant',
    'ConstDoubleInside'      : '[a{b]',
    'ConstUnknown'           : 'raised: Internal error: Unknown constant "nosuchconstant"',
    'ConstEmpty'             : 'raised: Internal error: Unknown constant ""',
    'ConstUnclosed'          : 'raised: Internal error: Unclosed constant',
    'ConstLastBrace'         : 'raised: Internal error: Unclosed constant',
    'ConstCase'              : 'raised: Internal error: Unknown constant "Tmp"',
    'ConstMissingCode'       : 'raised: Script error: Could not call proc',
    'ConstCustomMessage'     : '[Hello a and b,c]',
    'ConstEnvDefault'        : '[dflt]',
    'ConstEnvMissing'        : '[]',
    'ConstRegBadRoot'        : 'raised: Internal error: Failed to parse "reg" constant',
    'ConstRegDefault'        : '[dflt]',
    'ConstIniDefault'        : '[dflt]',
    'ConstParamDefault'      : '[dflt]',
    'ConstDrive'             : '[C:]',
    'ConstCustom'            : R'[value\x]',
    'ConstCustomBuiltin'     : R'[\]',
    'ConstRenamed'           : 'equal',
    'ConstHwnd'              : 'raised: Internal error: Unknown constant "hwnd"',
    'ConstUserFavorites'     : 'expands',
    'ConstCommonFavorites'   : 'equal',
    'ConstAutoFavorites'     : 'equal',
    'ConstUserPf'            : 'expands',
    'ConstUserFonts'         : 'expands',
    'ConstUserFavourites'    : 'raised: Internal error: Unknown constant "userfavourites"',
    'ConstAppEarly'          : 'raised: Internal error: An attempt was made to expand the "app" constant before it was initialized',
    'ConstGroupEarly'        : 'raised: Internal error: An attempt was made to expand the "group" constant before it was initialized',
    'ConstUninstallExeEarly' : '[]',
    'ConstCmUnknown'         : 'raised: Internal error: Unknown custom message name "NoSuchMessage" in "cm" constant',
    'ConstCmCase'            : '[Hello x and y]',
    'CustomMessageUnknown'   : 'raised: Internal error: Unknown custom message name "NoSuchMessage"',
    'ActiveLanguage'         : 'default',
    'ConstLanguage'          : '[default]',
    'ConstEnvLazy'           : 'expands',
    'LazyAfterEnv'           : '0',
    'ConstEnvEmpty'          : '[dflt]',
    'ConstRegLazy'           : '[dflt]',
    'Event002'               : 'Lazy(default)',
    'Event003'               : 'Lazy(key)',
    'ConstRegOrder'          : '[default]',
    'Event004'               : R'Lazy(C:\nosuch\oracle.ini)',
    'Event005'               : 'Lazy(section)',
    'Event006'               : 'Lazy(key)',
    'Event007'               : 'Lazy(default)',
    'ConstIniOrder'          : '[default]',
    'Event008'               : 'Lazy(nosuchparam)',
    'Event009'               : 'Lazy(default)',
    'ConstParamOrder'        : '[default]',
    'LazyCount'              : '8',
}

_HOST_LOG_OF_INITIALIZE_WIZARD = {
    'Event010'         : 'InitializeWizard:first',
    'Event011'         : 'InitializeWizard:second',
    'Event012'         : 'InitializeWizard:main',
    'ProgressID'       : '100',
    'Page1ID'          : '101',
    'Page2ID'          : '102',
    'PageAfterMissing' : 'raised: Internal error: Could not find page with ID 9999',
    'Page3ID'          : '103',
}
_HOST_LOG_OF_AN_INSTALLATION_WITH_THE_WIZARD = {
    **_HOST_LOG_OF_INITIALIZE_SETUP,
    **_HOST_LOG_OF_INITIALIZE_WIZARD,
    'Event013'                      : 'CurPageChanged(1)',
    'Event014'                      : 'ShouldSkipPage:first(1)',
    'Event015'                      : 'ShouldSkipPage(1)',
    'Event016'                      : 'NextButtonClick:first(1)',
    'Event017'                      : 'NextButtonClick(1)',
    'Event018'                      : 'OnShouldSkipPage(102)',
    'Event019'                      : 'OnShouldSkipPage(101)',
    'Event020'                      : 'ShouldSkipPage:first(101)',
    'Event021'                      : 'ShouldSkipPage(101)',
    'Event022'                      : 'OnShouldSkipPage(102)',
    'Event023'                      : 'ShouldSkipPage:first(1)',
    'Event024'                      : 'ShouldSkipPage(1)',
    'Event025'                      : 'OnActivate(101)',
    'Event026'                      : 'CurPageChanged(101)',
    'Event027'                      : 'OnNextButtonClick(101)',
    'Event028'                      : 'NextButtonClick:first(101)',
    'Event029'                      : 'NextButtonClick(101)',
    'Event030'                      : 'ShouldSkipPage:first(3)',
    'Event031'                      : 'ShouldSkipPage(3)',
    'Event032'                      : 'OnShouldSkipPage(101)',
    'Event033'                      : 'ShouldSkipPage:first(101)',
    'Event034'                      : 'ShouldSkipPage(101)',
    'Event035'                      : 'CurPageChanged(3)',
    'Event036'                      : 'CheckPassword(Wrong)',
    'Event037'                      : 'NextButtonClick:first(3)',
    'Event038'                      : 'NextButtonClick(3)',
    'ConstAppOnPasswordNext'        : 'raised: Internal error: An attempt was made to expand the "app" constant before it was initialized',
    'Event039'                      : 'ShouldSkipPage:first(5)',
    'Event040'                      : 'ShouldSkipPage(5)',
    'Event041'                      : 'OnShouldSkipPage(101)',
    'Event042'                      : 'ShouldSkipPage:first(101)',
    'Event043'                      : 'ShouldSkipPage(101)',
    'Event044'                      : 'CheckSerial()',
    'Event045'                      : 'CurPageChanged(5)',
    'Event046'                      : 'NextButtonClick:first(5)',
    'Event047'                      : 'NextButtonClick(5)',
    'Event048'                      : 'ShouldSkipPage:first(6)',
    'Event049'                      : 'ShouldSkipPage(6)',
    'Event050'                      : 'ShouldSkipPage:first(5)',
    'Event051'                      : 'ShouldSkipPage(5)',
    'Event052'                      : 'CurPageChanged(6)',
    'Event053'                      : 'NextButtonClick:first(6)',
    'Event054'                      : 'NextButtonClick(6)',
    'ConstAppOnDirNext'             : 'expands',
    'Event055'                      : 'ShouldSkipPage:first(103)',
    'Event056'                      : 'ShouldSkipPage(103)',
    'Event057'                      : 'ShouldSkipPage:first(6)',
    'Event058'                      : 'ShouldSkipPage(6)',
    'Event059'                      : 'CurPageChanged(103)',
    'Event060'                      : 'NextButtonClick:first(103)',
    'Event061'                      : 'NextButtonClick(103)',
    'Event062'                      : 'ShouldSkipPage:first(9)',
    'Event063'                      : 'ShouldSkipPage(9)',
    'Event064'                      : 'ShouldSkipPage:first(103)',
    'Event065'                      : 'ShouldSkipPage(103)',
    'Event066'                      : 'CurPageChanged(9)',
    'Event067'                      : 'NextButtonClick:first(9)',
    'Event068'                      : 'NextButtonClick(9)',
    'Event069'                      : 'UpdateReadyMemo',
    'Event070'                      : 'ShouldSkipPage:first(10)',
    'Event071'                      : 'ShouldSkipPage(10)',
    'Event072'                      : 'ShouldSkipPage:first(9)',
    'Event073'                      : 'ShouldSkipPage(9)',
    'Event074'                      : 'CurPageChanged(10)',
    'Event075'                      : 'NextButtonClick:first(10)',
    'Event076'                      : 'NextButtonClick(10)',
    'ConstGroupOnReadyNext'         : 'expands',
    'Event077'                      : 'ShouldSkipPage:first(10)',
    'Event078'                      : 'ShouldSkipPage(10)',
    'Event079'                      : 'CurPageChanged(11)',
    'Event080'                      : 'PrepareToInstall',
    'Event081'                      : 'ShouldSkipPage:first(10)',
    'Event082'                      : 'ShouldSkipPage(10)',
    'Event083'                      : 'ShouldSkipPage:first(10)',
    'Event084'                      : 'ShouldSkipPage(10)',
    'Event085'                      : 'ShouldSkipPage:first(10)',
    'Event086'                      : 'ShouldSkipPage(10)',
    'Event087'                      : 'CurPageChanged(12)',
    'Event088'                      : 'CurStepChanged(1)',
    'ConstUninstallExeOnInstall'    : '[]',
    'Event089'                      : 'NeedRestart',
    'Event090'                      : 'RegisterPreviousData',
    'Event091'                      : 'CurStepChanged(2)',
    'ConstUninstallExeAfterInstall' : 'expands',
    'Event092'                      : 'ShouldSkipPage:first(14)',
    'Event093'                      : 'ShouldSkipPage(14)',
    'Event094'                      : 'CurPageChanged(14)',
    'Event095'                      : 'NextButtonClick:first(14)',
    'Event096'                      : 'NextButtonClick(14)',
    'Event097'                      : 'CurStepChanged(3)',
    'Event098'                      : 'GetCustomSetupExitCode',
    'Event099'                      : 'DeinitializeSetup',
    'ProgressCalls'                 : '227',
    'ProgressLast'                  : '894/894',
}
_HOST_LOG_OF_A_SILENT_INSTALLATION = {
    **_HOST_LOG_OF_INITIALIZE_SETUP,
    **_HOST_LOG_OF_INITIALIZE_WIZARD,
    'Event013'                      : 'CurPageChanged(1)',
    'Event014'                      : 'NextButtonClick:first(1)',
    'Event015'                      : 'NextButtonClick(1)',
    'Event016'                      : 'OnShouldSkipPage(102)',
    'Event017'                      : 'OnShouldSkipPage(101)',
    'Event018'                      : 'ShouldSkipPage:first(101)',
    'Event019'                      : 'ShouldSkipPage(101)',
    'Event020'                      : 'OnShouldSkipPage(102)',
    'Event021'                      : 'ShouldSkipPage:first(1)',
    'Event022'                      : 'ShouldSkipPage(1)',
    'Event023'                      : 'OnActivate(101)',
    'Event024'                      : 'CurPageChanged(101)',
    'Event025'                      : 'OnNextButtonClick(101)',
    'Event026'                      : 'NextButtonClick:first(101)',
    'Event027'                      : 'NextButtonClick(101)',
    'Event028'                      : 'ShouldSkipPage:first(3)',
    'Event029'                      : 'ShouldSkipPage(3)',
    'Event030'                      : 'OnShouldSkipPage(101)',
    'Event031'                      : 'ShouldSkipPage:first(101)',
    'Event032'                      : 'ShouldSkipPage(101)',
    'Event033'                      : 'CurPageChanged(3)',
    'Event034'                      : 'CheckPassword(Wrong)',
    'Event035'                      : 'NextButtonClick:first(3)',
    'Event036'                      : 'NextButtonClick(3)',
    'ConstAppOnPasswordNext'        : 'raised: Internal error: An attempt was made to expand the "app" constant before it was initialized',
    'Event037'                      : 'ShouldSkipPage:first(5)',
    'Event038'                      : 'ShouldSkipPage(5)',
    'Event039'                      : 'OnShouldSkipPage(101)',
    'Event040'                      : 'ShouldSkipPage:first(101)',
    'Event041'                      : 'ShouldSkipPage(101)',
    'Event042'                      : 'CheckSerial()',
    'Event043'                      : 'CurPageChanged(5)',
    'Event044'                      : 'NextButtonClick:first(5)',
    'Event045'                      : 'NextButtonClick(5)',
    'Event046'                      : 'ShouldSkipPage:first(6)',
    'Event047'                      : 'ShouldSkipPage(6)',
    'Event048'                      : 'ShouldSkipPage:first(5)',
    'Event049'                      : 'ShouldSkipPage(5)',
    'Event050'                      : 'CurPageChanged(6)',
    'Event051'                      : 'NextButtonClick:first(6)',
    'Event052'                      : 'NextButtonClick(6)',
    'ConstAppOnDirNext'             : 'expands',
    'Event053'                      : 'ShouldSkipPage:first(103)',
    'Event054'                      : 'ShouldSkipPage(103)',
    'Event055'                      : 'ShouldSkipPage:first(6)',
    'Event056'                      : 'ShouldSkipPage(6)',
    'Event057'                      : 'CurPageChanged(103)',
    'Event058'                      : 'NextButtonClick:first(103)',
    'Event059'                      : 'NextButtonClick(103)',
    'Event060'                      : 'ShouldSkipPage:first(9)',
    'Event061'                      : 'ShouldSkipPage(9)',
    'Event062'                      : 'ShouldSkipPage:first(103)',
    'Event063'                      : 'ShouldSkipPage(103)',
    'Event064'                      : 'CurPageChanged(9)',
    'Event065'                      : 'NextButtonClick:first(9)',
    'Event066'                      : 'NextButtonClick(9)',
    'Event067'                      : 'UpdateReadyMemo',
    'Event068'                      : 'ShouldSkipPage:first(9)',
    'Event069'                      : 'ShouldSkipPage(9)',
    'Event070'                      : 'CurPageChanged(10)',
    'Event071'                      : 'NextButtonClick:first(10)',
    'Event072'                      : 'NextButtonClick(10)',
    'ConstGroupOnReadyNext'         : 'expands',
    'Event073'                      : 'CurPageChanged(11)',
    'Event074'                      : 'PrepareToInstall',
    'Event075'                      : 'ShouldSkipPage:first(10)',
    'Event076'                      : 'ShouldSkipPage(10)',
    'Event077'                      : 'ShouldSkipPage:first(10)',
    'Event078'                      : 'ShouldSkipPage(10)',
    'Event079'                      : 'ShouldSkipPage:first(10)',
    'Event080'                      : 'ShouldSkipPage(10)',
    'Event081'                      : 'CurPageChanged(12)',
    'Event082'                      : 'CurStepChanged(1)',
    'ConstUninstallExeOnInstall'    : '[]',
    'Event083'                      : 'NeedRestart',
    'Event084'                      : 'RegisterPreviousData',
    'Event085'                      : 'CurStepChanged(2)',
    'ConstUninstallExeAfterInstall' : 'expands',
    'Event086'                      : 'ShouldSkipPage:first(14)',
    'Event087'                      : 'ShouldSkipPage(14)',
    'Event088'                      : 'CurPageChanged(14)',
    'Event089'                      : 'NextButtonClick:first(14)',
    'Event090'                      : 'NextButtonClick(14)',
    'Event091'                      : 'CurStepChanged(3)',
    'Event092'                      : 'GetCustomSetupExitCode',
    'Event093'                      : 'DeinitializeSetup',
    'ProgressCalls'                 : '227',
    'ProgressLast'                  : '894/894',
}
_HOST_VALUES_THAT_ARE_NOT_EMULATED = ('ConstEnvMissing', 'ProgressCalls', 'ProgressLast')


def _logged_values(events: Iterable[object], values: dict[str, str]) -> dict[str, str]:
    """
    Adds the name and value of each oracle line that the events log to the given values.
    """
    for event in events:
        if (
            isinstance(event, NewFunctionCall)
            and event.name == 'Log'
            and (match := _ORACLE_LINE.fullmatch(event.args[0]))
        ):
            values[match[1]] = match[2]
    return values


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


class TestTheSetupAgreesWithTheScript(TestBase):
    """
    A script of Inno Setup 7 runs only under a Setup of Inno Setup 7, and an earlier script only
    under an earlier Setup. The stored installer was built by Inno Setup 6.5.0; its script is
    replaced by one of the value oracle and its header changed as Inno Setup 7 writes it.
    """

    def script(self, build: str) -> IFPSFile:
        return IFPSFile.Parse(_value_oracle_file(self, build, 'ifps'))

    def installer(self) -> InnoArchive:
        return InnoArchive(self.download_sample(_HOST_INSTALLER))

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
        setup = InnoSetupEmulator(self.installer(), IFPSEmulatorConfig()).setup
        self.assertEqual((setup.release, setup.dialect, setup.platform), ((6, 5, 0, 0), Dialect.Inno6, Platform.Win32))

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
        from refinery.lib.inno.emulator import _release
        self.assertEqual(_release(0x07010000, None), (7, 1, 0))
        self.assertEqual(_release(0x87010000, None), (7, 1, 0))


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


class TestTheEmulatorHostsTheScriptAsInnoSetupDid(TestBase):
    """
    Inno Setup 6.5.0 built an installer whose script logs the events that Setup sends and how Setup
    expands constants. The installer ran on Windows with a log file, installing for the current
    user. The emulated machine has `WINDIR` set, as every Windows has.
    """

    def emulator(self, archive: InnoArchive | IFPSFile | None = None, **config):
        if archive is None:
            archive = InnoArchive(self.download_sample(_HOST_INSTALLER))
        return InnoSetupEmulator(archive, IFPSEmulatorConfig(
            log_calls=True,
            admin=False,
            environment={'WINDIR': R'C:\WINDOWS'},
            **config,
        ))

    def test_initialize_setup_expands_constants_as_setup_did(self):
        """
        The values of `{app}`, `{group}` and `{uninstallexe}` depend on how far the installation
        got, which a run of `InitializeSetup` alone does not show.
        """
        emulator = self.emulator()
        emulated = _logged_values(emulator.emulate_function(emulator.symbols['INITIALIZESETUP']), {})
        compared = _HOST_LOG_OF_INITIALIZE_SETUP.keys() - {
            'ConstAppEarly',
            'ConstGroupEarly',
            'ConstUninstallExeEarly',
            *_HOST_VALUES_THAT_ARE_NOT_EMULATED,
        }
        self.assertEqual(emulated.keys(), _HOST_LOG_OF_INITIALIZE_SETUP.keys())
        self.assertEqual(
            {name: emulated[name] for name in compared},
            {name: _HOST_LOG_OF_INITIALIZE_SETUP[name] for name in compared},
        )

    def assertInstallationLogsAsSetupDid(self, log: dict[str, str], **config):
        emulated = _logged_values(self.emulator(**config).emulate_installation(), {})
        compared = log.keys() - set(_HOST_VALUES_THAT_ARE_NOT_EMULATED)
        self.assertEqual(emulated.keys(), log.keys())
        self.assertEqual({name: emulated[name] for name in compared}, {name: log[name] for name in compared})

    def test_an_installation_with_the_wizard_runs_the_script_as_setup_did(self):
        self.assertInstallationLogsAsSetupDid(_HOST_LOG_OF_AN_INSTALLATION_WITH_THE_WIZARD, wizard_silent=False)

    def test_a_silent_installation_runs_the_script_as_setup_did(self):
        self.assertInstallationLogsAsSetupDid(_HOST_LOG_OF_A_SILENT_INSTALLATION, wizard_silent=True)

    def test_setup_does_not_ask_the_script_for_the_ready_memo_when_the_header_disables_the_memo(self):
        """
        The parsed header of the installer is changed as the directive `DisableReadyMemo` changes
        it.
        """
        archive = InnoArchive(self.download_sample(_HOST_INSTALLER))
        archive.setup_info.Header.Flags |= Flags.DisableReadyMemo
        events = _logged_values(self.emulator(archive, wizard_silent=False).emulate_installation(), {}).values()
        self.assertIn('CurPageChanged(10)', events)
        self.assertNotIn('UpdateReadyMemo', events)

    def test_a_silent_installation_of_the_script_alone_never_shows_the_license_page(self):
        """
        Without its installer, the script runs as if every page were shown; a silent Setup still
        skips the license page on its own.
        """
        script = InnoArchive(self.download_sample(_HOST_INSTALLER)).ifps
        assert script is not None
        silent = _logged_values(self.emulator(script, wizard_silent=True).emulate_installation(), {}).values()
        normal = _logged_values(self.emulator(script, wizard_silent=False).emulate_installation(), {}).values()
        self.assertIn('ShouldSkipPage(2)', normal)
        self.assertNotIn('ShouldSkipPage(2)', silent)
        self.assertNotIn('CurPageChanged(2)', silent)

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='the program files folders do not follow the 32-bit install mode of the setup',
    )
    def test_a_setup_in_32_bit_install_mode_puts_the_program_files_folders_under_program_files_x86(self):
        """
        The installer sets no `ArchitecturesInstallIn64BitMode`, so it installs in 32-bit mode;
        the emulated Windows is 64-bit.
        """
        emulator = self.emulator(x64=True)
        self.assertEqual(
            [emulator.expand_constant(constant) for constant in ('{commonpf}', '{commoncf}', '{dao}')],
            [
                R'C:\Program Files (x86)',
                R'C:\Program Files (x86)\Common Files',
                R'C:\Program Files (x86)\Common Files\Microsoft Shared\DAO',
            ],
        )

    @wontfix('the progress of an installation counts the bytes that Setup installs, and the emulator installs none')
    def test_an_installation_reports_its_progress(self):
        emulated = _logged_values(self.emulator(wizard_silent=False).emulate_installation(), {})
        log = _HOST_LOG_OF_AN_INSTALLATION_WITH_THE_WIZARD
        self.assertEqual(
            (emulated['ProgressCalls'], emulated['ProgressLast']),
            (log['ProgressCalls'], log['ProgressLast']),
        )

    @wontfix('the emulator does not know the environment of the machine; a variable that the configuration does not name stays %NAME%')
    def test_an_environment_variable_that_is_not_set_expands_to_an_empty_text(self):
        expanded = self.emulator().expand_constant('{%NOSUCHORACLEVARIABLE}')
        self.assertEqual(F'[{expanded}]', _HOST_LOG_OF_INITIALIZE_SETUP['ConstEnvMissing'])
