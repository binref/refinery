import pytest
import re

from itertools import zip_longest
from typing import Iterable

from refinery.lib.inno.archive import Flags, InnoArchive
from refinery.lib.inno.emulator import (
    EmulatorException,
    IFPSEmulatorConfig,
    IFPSException,
    InnoSetupEmulator,
    NewFunctionCall,
)
from refinery.lib.inno.ifps import Function, IFPSFile, Op, Operand

from .. import TestBase, wontfix

_ORACLE_LINE = re.compile(r'ORACLE (\S+) = (.*)')
_INTEGER_SCRIPT = '8ca8a9c7454b8aab50c461b543098450f2f7ea277b67fc7614c2fe5f58d2c3a8'
_INTEGER_LOG = {
    'store.s32_to_u32'                      : '4294967295',
    'store.u32_to_s32'                      : '-1',
    'store.s32_to_u8'                       : '200',
    'store.u8_to_s8'                        : '-56',
    'store.s32_to_u16'                      : '65535',
    'store.u16_to_s16'                      : '-1',
    'store.s64_to_s32'                      : '5',
    'store.s64_to_u32'                      : '4294967295',
    'store.u32_to_s64'                      : '4294967295',
    'store.s32_to_s64'                      : '-1',
    'store.s32_to_u8_truncated'             : '44',
    'store.s32_to_s16_truncated'            : '-25536',
    'store.inttostr_u32'                    : '4294967295',
    'store.inttostr_s32'                    : '-7',
    'add.s32_overflow'                      : '-2147483648',
    'sub.u32_underflow'                     : '4294967295',
    'add.u8_overflow'                       : '44',
    'add.s8_overflow'                       : '-128',
    'sub.u16_underflow'                     : '65535',
    'mul.s32_overflow_to_zero'              : '0',
    'mul.s32_overflow_to_minus_one'         : '-1',
    'add.s64_overflow'                      : '-9223372036854775808',
    'add.u32_plus_s32'                      : '4294967294',
    'add.s32_plus_u32'                      : '4',
    'mul.u32_times_s32'                     : '4294966996',
    'inc.s32_overflow'                      : '-2147483648',
    'inc.u8_overflow'                       : '0',
    'dec.u32_underflow'                     : '4294967295',
    'neg.s32_minimum'                       : '-2147483648',
    'neg.u32'                               : '4294967291',
    'not.u8'                                : '250',
    'not.u32'                               : '4294967290',
    'not.s32'                               : '-6',
    'not.s64'                               : '-6',
    'and.u32_with_s32'                      : '4294967294',
    'or.s32_with_u32'                       : '-1',
    'div.s32_negative_by_positive'          : '-3',
    'mod.s32_negative_by_positive'          : '-1',
    'div.s32_positive_by_negative'          : '-3',
    'mod.s32_positive_by_negative'          : '1',
    'div.s32_negative_by_negative'          : '3',
    'mod.s32_negative_by_negative'          : '-1',
    'div.u32_by_s32'                        : '1',
    'mod.u32_by_s32'                        : '0',
    'div.u32_by_negative_s32'               : '0',
    'mod.u32_by_negative_s32'               : '7',
    'div.s32_by_u32'                        : '-1',
    'mod.s32_by_u32'                        : '-1',
    'div.s32_by_large_u32'                  : '1',
    'mod.s32_by_large_u32'                  : '-1',
    'div.s32_by_large_s64'                  : '0',
    'mod.s32_by_large_s64'                  : '-100',
    'div.s32_by_s64'                        : '-3',
    'mod.s32_by_s64'                        : '-1',
    'div.u32_by_negative_s64'               : '4294967263',
    'mod.u32_by_negative_s64'               : '1',
    'div.u8_by_negative_s32'                : '0',
    'mod.u8_by_negative_s32'                : '200',
    'div.s8_by_s32'                         : '-33',
    'mod.s8_by_s32'                         : '-1',
    'div.u16_by_negative_s32'               : '0',
    'div.s64_by_s32'                        : '-3',
    'mod.s64_by_s32'                        : '-1',
    'div.s64_by_u32'                        : '0',
    'mod.s64_by_u32'                        : '-7',
    'div.by_zero'                           : 'raised',
    'mod.by_zero'                           : 'raised',
    'div.s32_minimum_by_minus_one'          : 'raised',
    'mod.s32_minimum_by_minus_one'          : 'raised',
    'div.s64_minimum_by_minus_one'          : '-9223372036854775808',
    'div.s8_minimum_by_minus_one'           : '-128',
    'shr.s32_negative_by_4'                 : '268435455',
    'shr.s32_negative_by_0'                 : '-16',
    'shr.s32_negative_by_32'                : '-16',
    'shr.s32_negative_by_33'                : '2147483640',
    'shr.s32_negative_by_minus_1'           : '1',
    'shl.s32_by_31'                         : '-2147483648',
    'shl.s32_by_32'                         : '1',
    'shl.u32_by_33'                         : '2',
    'shr.u32_by_4'                          : '268435455',
    'shl.u8_by_1'                           : '144',
    'shl.u8_by_8'                           : '0',
    'shl.u8_by_32'                          : '200',
    'shr.u8_by_1'                           : '100',
    'shr.u8_by_9'                           : '0',
    'shr.s8_negative_by_2'                  : '-4',
    'shr.s16_negative_by_2'                 : '-4',
    'shr.u16_by_4'                          : '4095',
    'shr.s64_negative_by_4'                 : '1152921504606846975',
    'shl.s64_by_63'                         : '-9223372036854775808',
    'shl.s64_by_64'                         : '1',
    'shl.s64_by_65'                         : '2',
    'shl.s64_by_128'                        : '1',
    'shl.s64_by_200'                        : '256',
    'shl.s64_by_256'                        : '1',
    'shr.s64_negative_by_64'                : '-16',
    'shr.s64_negative_by_36'                : '268435455',
    'shr.hex_digits_of_minus_16'            : 'FFFFFFF0',
    'cmp.u32_equals_s32'                    : 'true',
    'cmp.s32_equals_u32'                    : 'true',
    'cmp.u32_greater_than_negative_s32'     : 'false',
    'cmp.negative_s32_less_than_u32'        : 'true',
    'cmp.s32_less_than_large_u32'           : 'false',
    'cmp.large_u32_greater_than_s32'        : 'true',
    'cmp.u8_equals_s32'                     : 'false',
    'cmp.s8_equals_u8'                      : 'false',
    'cmp.u16_equals_s32'                    : 'false',
    'cmp.s64_equals_u32'                    : 'true',
    'cmp.negative_s64_equals_u32'           : 'false',
    'cmp.u32_equals_large_s64'              : 'true',
    'cmp.s32_equals_large_s64'              : 'false',
    'cmp.s32_less_than_double'              : 'true',
    'cmp.u32_less_equal_double'             : 'raised',
    'cmp.case_label_of_a_cardinal_constant' : 'matched',
    'cmp.s32_equals_cardinal_constant'      : 'true',
    'cmp.s32_less_than_currency'            : 'raised',
    'cmp.s32_less_than_variant_float'       : 'true',
    'const.extended_above_integer'          : 'true',
    'const.extended_doubled'                : 'true',
    'const.currency_negative'               : 'true',
    'const.currency_doubled'                : 'true',
    'const.extended_beyond_double'          : 'true',
    'fmt.x_of_negative_s32'                 : 'FFFFFFF0',
    'fmt.d_of_large_u32'                    : '-1',
    'fmt.u_of_negative_s32'                 : '4294967295',
    'fmt.x_of_negative_s64'                 : 'FFFFFFFFFFFFFFF0',
    'fmt.u_of_negative_s64'                 : '18446744073709551615',
    'fmt.d_of_large_s64'                    : '4294967301',
    'fmt.x_with_precision'                  : '00FF',
    'fmt.d_with_precision_of_negative'      : '-0005',
    'fmt.width_right_and_left'              : '[   42|42   ]',
    'fmt.index'                             : 'b a b',
    'fmt.star_width'                        : '[   42]',
    'fmt.star_precision'                    : '[0042]',
    'fmt.s_with_precision'                  : 'abc',
    'fmt.s_with_width'                      : '[    ab|ab    ]',
    'fmt.percent'                           : '100%',
    'fmt.upper_case_types'                  : '2A|42|z',
    'fmt.d_of_u8'                           : '200',
    'fmt.x_of_u16'                          : 'FFFF',
    'fmt.x_of_negative_s8'                  : 'FFFFFFFF',
    'fmt.s_of_char'                         : 'A',
    'fmt.error_code'                        : 'failed with code -2147012889 (0x80072EE7)',
    'fmt.precision_dates'                   : '20260109',
    'fmt.s_of_integer'                      : 'raised',
    'fmt.d_of_string'                       : 'raised',
    'fmt.d_of_char'                         : 'raised',
    'fmt.missing_argument'                  : 'raised',
    'fmt.unknown_type'                      : 'raised',
    'fmt.d_of_double'                       : 'raised',
    'fmt.x_of_double'                       : 'raised',
    'fmt.d_of_currency'                     : '0',
    'fmt.d_of_boolean'                      : '1',
    'fmt.d_of_variant'                      : 'raised',
    'fmt.x_of_variant'                      : 'raised',
    'fmt.s_of_variant'                      : '-16',
    'float.float_to_str'                    : '1.500000000000',
    'float.float_to_str_of_sum'             : '0.300000000000',
    'float.g_large'                         : '1234567',
    'float.g'                               : 'x: 1,5',
    'float.g_small'                         : '1E-006',
    'float.g_long'                          : '1,23456789012346',
    'float.f'                               : '2,50',
    'float.f_tie'                           : '0,13',
    'float.n'                               : '1.234.567,89',
    'float.e'                               : '1,23456789100000E+006',
    'float.m'                               : '1.234.567,89 €',
    'float.m_negative'                      : '-1.234,50 €',
    'float.single_widened'                  : '0.100000001490',
    'float.extended_third'                  : '0.333333333333',
    'float.currency'                        : '-1.500000000000',
    'set.union'                             : '[ABC]',
    'set.difference'                        : '[AC]',
    'set.intersection'                      : '[B]',
    'set.in'                                : 'true',
    'set.not_in'                            : 'false',
    'set.subset'                            : 'true',
    'set.not_subset'                        : 'false',
    'set.superset'                          : 'true',
    'set.equal'                             : 'true',
    'set.in_out_of_range'                   : 'raised',
    'bool.integer_of_true'                  : '1',
    'bool.integer_of_false'                 : '0',
    'bool.two_is_true'                      : 'true',
    'bool.two_equals_true'                  : 'false',
    'bool.not_two'                          : 'false',
    'variant.div_of_integers'               : '-3',
    'variant.mod_of_integers'               : '-1',
    'variant.div_of_float_is_real_division' : 'true',
    'variant.integer_overflow'              : '2147483648',
    'variant.int64_overflow'                : '-9223372036854775808',
    'variant.integer_square_overflow'       : '4294967296',
    'variant.shl_40'                        : '256',
    'variant.integer_plus_variant_float'    : '2',
    'variant.integer_plus_variant_string'   : '17',
    'pointer.format_of_var_parameter'       : '42',
    'pointer.format_of_computed_element'    : '3',
    'pointer.format_of_nested_field'        : '7',
    'fmt.percent_before_text'               : '[Downloaded 50]',
    'fmt.percent_at_end'                    : '[100]',
    'fmt.percent_before_space'              : '[50]',
    'fmt.width_at_end'                      : '[[]',
    'fmt.colon_without_index'               : '[a a]',
    'fmt.asterisk_index'                    : '[a]',
    'fmt.negative_asterisk_width'           : '[7    ]',
    'fmt.negative_asterisk_width_left'      : '[    7]',
    'fmt.negative_asterisk_precision'       : '[abc]',
    'fmt.int64_asterisk_width'              : '[   42]',
    'fmt.large_int64_asterisk_width'        : 'raised',
    'fmt.width_beyond_integer'              : 'raised',
    'fmt.empty_precision'                   : '[abc]',
    'bool.variant_of_boolean_variable'      : 'True',
    'bool.variant_of_true'                  : 'True',
    'bool.variant_of_comparison'            : 'True',
    'variant.u32_equals_minus_one'          : 'true',
    'variant.u16_greater_than_minus_one'    : 'false',
    'variant.s64_equals_minus_one'          : 'true',
    'variant.text_of_whole_float'           : '100',
    'variant.text_of_large_float'           : '1E16',
    'variant.for_counter'                   : 'raised after 1',
    'fmt.array_of_strings'                  : 'raised',
    'const.extended_infinity'               : 'true',
}


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


class _OracleTest(TestBase):
    """
    Inno Setup 6.5.0 built an installer from a script whose procedures log values that Pascal Script
    computes, one procedure per area. The installer ran on Windows with a log file: `log` holds
    every value of that log and `script` is the compiled script taken from that installer.
    """
    script: str
    log: dict[str, str]

    def emulator(self, **config):
        script = IFPSFile.Parse(self.download_sample(self.script))
        return InnoSetupEmulator(script, IFPSEmulatorConfig(log_calls=True, **config))

    def assertEmulatedAsLogged(self, procedure: str, *names: str):
        """
        Emulates one procedure and compares what it logs with the log: the values of the given
        names, or else every value that it logs with the logged values whose names are string
        constants of the procedure and of the script functions it calls.
        """
        emulator = self.emulator()
        function = emulator.symbols[procedure]
        emulated = _logged_values(emulator.emulate_function(function), {})
        if names:
            self.assertLessEqual(set(names), _string_constants(emulator.ifps.functions))
            emulated = {name: value for name, value in emulated.items() if name in names}
        else:
            reached: list[Function] = [function]
            for caller in reached:
                for instruction in caller.body or ():
                    if instruction.opcode is Op.Call:
                        reached.extend(
                            callee for callee in instruction.operands
                            if isinstance(callee, Function) and callee.body is not None and callee not in reached
                        )
            names = tuple(_string_constants(reached))
            self.assertTrue(self.log.keys() & names)
        real = {name: value for name, value in self.log.items() if name in names}
        self.assertEqual(emulated, real)

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


class TestTheEmulatorLogsWhatInnoSetupLogged(_OracleTest):
    """
    The procedures of this script compute with integers, floats, sets, Variants and `Format`.
    """
    script = _INTEGER_SCRIPT
    log = _INTEGER_LOG

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

    @pytest.mark.xfail(strict=True, raises=IFPSException, reason='floats are not converted to text as Delphi converts them')
    def test_floats(self):
        self.assertEmulatedAsLogged('ORACLEFLOATS')

    def test_sets(self):
        self.assertEmulatedAsLogged('ORACLESETS')

    def test_booleans(self):
        self.assertEmulatedAsLogged('ORACLEBOOLEANS')

    @pytest.mark.xfail(strict=True, raises=EmulatorException, reason='Variant operators follow Python instead of Delphi')
    def test_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTS')

    def test_format_of_values_reached_through_pointers(self):
        self.assertEmulatedAsLogged('ORACLEPOINTERS')

    def test_format_of_unusual_specifiers(self):
        self.assertEmulatedAsLogged('ORACLEFORMATEDGES')

    def test_booleans_in_variants(self):
        self.assertEmulatedAsLogged('ORACLEBOOLEANVARIANTS')

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='a Variant compared with a Cardinal or Word is compared by its value, not read as a Cardinal',
    )
    def test_comparisons_of_integers_with_variants(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOMPARISONS')

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='a Variant holding a float is converted to text by Python, not as Delphi converts it',
    )
    def test_variants_holding_floats_as_text(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTTEXT')

    def test_a_loop_with_a_variant_counter(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOUNTER')

    def test_format_of_an_array_of_strings(self):
        self.assertEmulatedAsLogged('ORACLEARRAYOFSTRINGS')

    def test_an_infinite_float_constant(self):
        self.assertEmulatedAsLogged('ORACLEINFINITY')

    def test_two_runs_advanced_alternately_by_instruction_log_what_each_logs_alone(self):
        self.assertRunsAdvancedAlternatelyLogWhatEachLogsAlone('ORACLECOMPARISONS', 'ORACLESETS', log_opcodes=True)


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

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason='float errors are raised although Delphi 12 masks them')
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

    @pytest.mark.xfail(
        strict=True,
        raises=AssertionError,
        reason='StrToInt raises an error for text that is no number instead of returning -1',
    )
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
