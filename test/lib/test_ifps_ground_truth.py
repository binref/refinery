import pytest
import re
import tracemalloc

from itertools import zip_longest
from typing import Iterable

from fractions import Fraction

from refinery.lib.inno.archive import Flags, InnoArchive
from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.emulator import (
    EmulatorMaxArray,
    EmulatorMaxString,
    EmulatorUndefined,
    IFPSEmulatorConfig,
    IFPSException,
    InnoSetupEmulator,
    NewFunctionCall,
)
from refinery.lib.inno.ifps import TC, AOp, Dialect, Function, IFPSFile, Op, Operand, Value
from refinery.lib.types import buf
from refinery.lib.un7z import SzArchive

from .. import TestBase, wontfix

_ORACLE_LINE = re.compile(r'ORACLE (\S+) = (.*)')
_MESSAGE_REFERENCE = re.compile(r'!(\d+)')
_VALUE_SCRIPT = 'ddff7277b0ecf390016c2200d91b671ab0f5f6f63edb29a6948010ba5ff19d51'
_VALUE_LOG = {
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
    'vstore.byte'                           : '17:200',
    'vstore.boolean'                        : '11:True',
    'vstore.shortint'                       : '16:-100',
    'vstore.word'                           : '18:60000',
    'vstore.smallint'                       : '2:-30000',
    'vstore.cardinal'                       : '19:4000000000',
    'vstore.integer'                        : '3:-7',
    'vstore.int64'                          : '20:-1099511627776',
    'vstore.single'                         : '5:0,100000001490116',
    'vstore.double'                         : '5:0,1',
    'vstore.extended'                       : '5:0,1',
    'vstore.currency'                       : '6:0,1',
    'vstore.ansistring'                     : '256:ab',
    'vstore.char'                           : '8:c',
    'vstore.string'                         : '258:de',
    'vstore.widestring'                     : '8:fg',
    'vstore.integer_constant'               : '3:5',
    'vstore.int64_constant'                 : '20:5000000000',
    'vstore.float_constant'                 : '5:1,5',
    'vstore.char_constant'                  : '8:h',
    'vstore.string_constant'                : '258:ij',
    'vstore.true_constant'                  : '11:True',
    'vstore.unassigned'                     : '0:',
    'msg.0'                                 : 'Could not convert variant of type (Null) into type (OleStr)',
    'vstore.null'                           : '1:!0',
    'vconv.empty'                           : '0|0|0|0|0.000000000000|0.000000000000|[]|0|0',
    'msg.1'                                 : 'Could not convert variant of type (Null) into type (Integer)',
    'msg.2'                                 : 'Could not convert variant of type (Null) into type (Int64)',
    'msg.3'                                 : 'Could not convert variant of type (Null) into type (Double)',
    'msg.4'                                 : 'Could not convert variant of type (Null) into type (Currency)',
    'vconv.null'                            : '!1|!2|!2|!2|!3|!4|!0|!2|!2',
    'vconv.int'                             : '7|7|7|7|7.000000000000|7.000000000000|[7]|7|7',
    'vconv.minus_one'                       : '-1|4294967295|255|-1|-1.000000000000|-1.000000000000|[-1]|65535|255',
    'msg.5'                                 : 'Overflow while converting variant of type (Int64) into type (Integer)',
    'vconv.int64'                           : (
        '!5|7|7|1099511627783|1099511627783.000000000000|1099511627783.000000000000|[1099511627783]|'
        '7|7'
    ),
    'vconv.int64_minus_one'                 : '-1|4294967295|255|-1|-1.000000000000|-1.000000000000|[-1]|65535|255',
    'vconv.double_half'                     : '0|0|0|0|0.500000000000|0.500000000000|[0,5]|0|0',
    'vconv.double_two_and_a_half'           : '2|2|2|2|2.500000000000|2.500000000000|[2,5]|2|2',
    'vconv.double_three_and_a_half'         : '4|4|4|4|3.500000000000|3.500000000000|[3,5]|4|4',
    'vconv.double_negative_two_and_a_half'  : '-2|4294967294|254|-2|-2.500000000000|-2.500000000000|[-2,5]|65534|254',
    'msg.6'                                 : 'Overflow while converting variant of type (Double) into type (Integer)',
    'vconv.double_large'                    : (
        '!6|1410065408|0|10000000000|10000000000.000000000000|10000000000.000000000000|'
        '[10000000000]|58368|0'
    ),
    'vconv.currency'                        : '2|2|2|2|2.500000000000|2.500000000000|[2,5]|2|2',
    'vconv.text_number'                     : '12|12|12|12|12.000000000000|12.000000000000|[12]|12|12',
    'vconv.text_padded'                     : '12|12|12|12|12.000000000000|12.000000000000|[ 12 ]|12|12',
    'msg.7'                                 : 'Could not convert variant of type (UnicodeString) into type (Double)',
    'msg.8'                                 : 'Could not convert variant of type (UnicodeString) into type (Currency)',
    'vconv.text_dollar_hex'                 : '31|31|31|31|!7|!8|[$1F]|31|31',
    'vconv.text_zero_x_hex'                 : '31|31|31|31|!7|!8|[0x1F]|31|31',
    'vconv.text_point'                      : '15|15|15|15|15.000000000000|15.000000000000|[1.5]|15|15',
    'vconv.text_comma'                      : '2|2|2|2|1.500000000000|1.500000000000|[1,5]|2|2',
    'vconv.text_comma_half'                 : '2|2|2|2|2.500000000000|2.500000000000|[2,5]|2|2',
    'vconv.text_exponent'                   : '1000|1000|232|1000|1000.000000000000|1000.000000000000|[1e3]|1000|232',
    'msg.9'                                 : 'Could not convert variant of type (UnicodeString) into type (Integer)',
    'msg.10'                                : 'Could not convert variant of type (UnicodeString) into type (Int64)',
    'vconv.text_empty'                      : '!9|!10|!10|!10|!7|!8|[]|!10|!10',
    'vconv.text_letters'                    : '!9|!10|!10|!10|!7|!8|[ab]|!10|!10',
    'vconv.text_true'                       : '1|1|1|1|!7|!8|[True]|1|1',
    'vconv.text_char'                       : '!9|!10|!10|!10|!7|!8|[c]|!10|!10',
    'msg.11'                                : 'Overflow while converting variant of type (UnicodeString) into type (Integer)',
    'vconv.text_large'                      : (
        '!11|3000000000|0|3000000000|3000000000.000000000000|3000000000.000000000000|[3000000000]|'
        '24064|0'
    ),
    'vconv.true'                            : '-1|4294967295|255|-1|-1.000000000000|-1.000000000000|[True]|65535|255',
    'vconv.false'                           : '0|0|0|0|0.000000000000|0.000000000000|[False]|0|0',
    'vop.add.empty'                         : '0:|1:!0|3:7|20:1099511627776|5:2,5|6:2,5|8:12|8:ab|5:-1',
    'vop.add.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.add.int'                           : '3:7|1:!0|3:14|20:1099511627783|5:9,5|6:9,5|5:19|!7|3:6',
    'vop.add.int64'                         : (
        '20:1099511627776|1:!0|20:1099511627783|20:2199023255552|5:1099511627778,5|'
        '6:1099511627778,5|5:1099511627788|!7|20:1099511627775'
    ),
    'vop.add.double'                        : '5:2,5|1:!0|5:9,5|5:1099511627778,5|5:5|6:5|5:14,5|!7|5:1,5',
    'vop.add.currency'                      : '6:2,5|1:!0|6:9,5|6:1099511627778,5|6:5|6:5|6:14,5|!8|6:1,5',
    'vop.add.numtext'                       : '258:12|1:!0|5:19|5:1099511627788|5:14,5|6:14,5|258:1212|258:12ab|5:11',
    'vop.add.text'                          : '258:ab|1:!0|!7|!7|!7|!8|258:ab12|258:abab|!7',
    'vop.add.true'                          : '5:-1|1:!0|3:6|20:1099511627775|5:1,5|6:1,5|5:11|!7|5:-2',
    'vop.sub.empty'                         : '0:|1:!0|3:-7|20:-1099511627776|5:-2,5|6:-2,5|5:-12|!7|5:1',
    'vop.sub.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.sub.int'                           : '3:7|1:!0|3:0|20:-1099511627769|5:4,5|6:4,5|5:-5|!7|3:8',
    'vop.sub.int64'                         : (
        '20:1099511627776|1:!0|20:1099511627769|20:0|5:1099511627773,5|6:1099511627773,5|'
        '5:1099511627764|!7|20:1099511627777'
    ),
    'vop.sub.double'                        : '5:2,5|1:!0|5:-4,5|5:-1099511627773,5|5:0|6:0|5:-9,5|!7|5:3,5',
    'vop.sub.currency'                      : '6:2,5|1:!0|6:-4,5|6:-1099511627773,5|6:0|6:0|6:-9,5|!8|6:3,5',
    'vop.sub.numtext'                       : '5:12|1:!0|5:5|5:-1099511627764|5:9,5|6:9,5|5:0|!7|5:13',
    'vop.sub.text'                          : '!7|1:!0|!7|!7|!7|!8|!7|!7|!7',
    'vop.sub.true'                          : '5:-1|1:!0|3:-8|20:-1099511627777|5:-3,5|6:-3,5|5:-13|!7|5:0',
    'vop.mul.empty'                         : '0:|1:!0|3:0|20:0|5:0|6:0|5:0|!7|5:0',
    'vop.mul.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.mul.int'                           : '3:0|1:!0|3:49|20:7696581394432|5:17,5|6:17,5|5:84|!7|3:-7',
    'vop.mul.int64'                         : (
        '20:0|1:!0|20:7696581394432|20:0|5:2748779069440|6:2748779069440|5:13194139533312|!7|'
        '20:-1099511627776'
    ),
    'vop.mul.double'                        : '5:0|1:!0|5:17,5|5:2748779069440|5:6,25|6:6,25|5:30|!7|5:-2,5',
    'vop.mul.currency'                      : '6:0|1:!0|6:17,5|6:2748779069440|6:6,25|6:6,25|6:30|!7|6:-2,5',
    'vop.mul.numtext'                       : '5:0|1:!0|5:84|5:13194139533312|5:30|6:30|5:144|!7|5:-12',
    'vop.mul.text'                          : '!7|1:!0|!7|!7|!7|!7|!7|!7|!7',
    'vop.mul.true'                          : '5:0|1:!0|3:-7|20:-1099511627776|5:-2,5|6:-2,5|5:-12|!7|5:1',
    'msg.12'                                : 'Division by zero',
    'vop.slash.empty'                       : '!12|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:0',
    'vop.slash.null'                        : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.slash.int'                         : '!12|1:!0|3:1|20:0|3:3|3:3|3:0|!9|3:-7',
    'vop.slash.int64'                       : '!12|1:!0|20:157073089682|20:1|!5|!5|!5|!5|20:-1099511627776',
    'vop.slash.double'                      : '5:INF|1:!0|5:0,357142857142857|5:2,27373675443232E-12|5:1|5:1|5:0,208333333333333|!7|5:-2,5',
    'vop.slash.currency'                    : '6:-922337203685477,5808|1:!0|6:0,3571|6:0|6:1|6:1|6:0,2083|!7|6:-2,5',
    'vop.slash.numtext'                     : '!12|1:!0|3:1|!5|3:6|3:6|3:1|!9|3:-12',
    'vop.slash.text'                        : '!9|1:!0|!9|!9|!9|!9|!9|!9|!9',
    'vop.slash.true'                        : '!12|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:1',
    'vop.div.empty'                         : '!12|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:0',
    'vop.div.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.div.int'                           : '!12|1:!0|3:1|20:0|3:3|3:3|3:0|!9|3:-7',
    'vop.div.int64'                         : '!12|1:!0|20:157073089682|20:1|!5|!5|!5|!5|20:-1099511627776',
    'vop.div.double'                        : '5:INF|1:!0|5:0,357142857142857|5:2,27373675443232E-12|5:1|5:1|5:0,208333333333333|!7|5:-2,5',
    'vop.div.currency'                      : '6:-922337203685477,5808|1:!0|6:0,3571|6:0|6:1|6:1|6:0,2083|!7|6:-2,5',
    'vop.div.numtext'                       : '!12|1:!0|3:1|!5|3:6|3:6|3:1|!9|3:-12',
    'vop.div.text'                          : '!9|1:!0|!9|!9|!9|!9|!9|!9|!9',
    'vop.div.true'                          : '!12|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:1',
    'vop.mod.empty'                         : '!12|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:0',
    'vop.mod.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.mod.int'                           : '!12|1:!0|3:0|20:7|3:1|3:1|3:7|!9|3:0',
    'vop.mod.int64'                         : '!12|1:!0|20:2|20:0|!5|!5|!5|!5|20:0',
    'vop.mod.double'                        : '!12|1:!0|3:2|!5|3:0|3:0|3:2|!9|3:0',
    'vop.mod.currency'                      : '!12|1:!0|3:2|!5|3:0|3:0|3:2|!9|3:0',
    'vop.mod.numtext'                       : '!12|1:!0|3:5|!5|3:0|3:0|3:0|!9|3:0',
    'vop.mod.text'                          : '!9|1:!0|!9|!9|!9|!9|!9|!9|!9',
    'vop.mod.true'                          : '!12|1:!0|3:-1|20:-1|3:-1|3:-1|3:-1|!9|3:0',
    'vop.shl.empty'                         : '0:|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:0',
    'vop.shl.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.shl.int'                           : '3:7|1:!0|3:896|20:7|3:28|3:28|3:28672|!9|3:-2147483648',
    'vop.shl.int64'                         : '20:1099511627776|1:!0|20:140737488355328|20:1099511627776|!5|!5|!5|!5|20:0',
    'vop.shl.double'                        : '3:2|1:!0|3:256|!5|3:8|3:8|3:8192|!9|3:0',
    'vop.shl.currency'                      : '3:2|1:!0|3:256|!5|3:8|3:8|3:8192|!9|3:0',
    'vop.shl.numtext'                       : '3:12|1:!0|3:1536|!5|3:48|3:48|3:49152|!9|3:0',
    'vop.shl.text'                          : '!9|1:!0|!9|!9|!9|!9|!9|!9|!9',
    'vop.shl.true'                          : '3:-1|1:!0|3:-128|20:-1|3:-4|3:-4|3:-4096|!9|3:-2147483648',
    'vop.shr.empty'                         : '0:|1:!0|3:0|20:0|3:0|3:0|3:0|!9|3:0',
    'vop.shr.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.shr.int'                           : '3:7|1:!0|3:0|20:7|3:1|3:1|3:0|!9|3:0',
    'vop.shr.int64'                         : '20:1099511627776|1:!0|20:8589934592|20:1099511627776|!5|!5|!5|!5|20:0',
    'vop.shr.double'                        : '3:2|1:!0|3:0|!5|3:0|3:0|3:0|!9|3:0',
    'vop.shr.currency'                      : '3:2|1:!0|3:0|!5|3:0|3:0|3:0|!9|3:0',
    'vop.shr.numtext'                       : '3:12|1:!0|3:0|!5|3:3|3:3|3:0|!9|3:0',
    'vop.shr.text'                          : '!9|1:!0|!9|!9|!9|!9|!9|!9|!9',
    'vop.shr.true'                          : '3:-1|1:!0|3:33554431|20:-1|3:1073741823|3:1073741823|3:1048575|!9|3:1',
    'vop.and.empty'                         : '0:|0:|3:0|20:0|3:0|3:0|3:0|!9|11:False',
    'msg.13'                                : 'Could not convert variant of type (UnicodeString) into type (Boolean)',
    'vop.and.null'                          : '0:|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|!13|1:!0',
    'vop.and.int'                           : '3:0|1:!0|3:7|20:0|3:2|3:2|3:4|!9|3:7',
    'vop.and.int64'                         : '20:0|1:!0|20:0|20:1099511627776|!5|!5|!5|!5|20:1099511627776',
    'vop.and.double'                        : '3:0|1:!0|3:2|!5|3:2|3:2|3:0|!9|3:2',
    'vop.and.currency'                      : '3:0|1:!0|3:2|!5|3:2|3:2|3:0|!9|3:2',
    'vop.and.numtext'                       : '3:0|1:!0|3:4|!5|3:0|3:0|3:12|!9|11:True',
    'vop.and.text'                          : '!9|!13|!9|!9|!9|!9|!9|!9|!13',
    'vop.and.true'                          : '11:False|1:!0|3:7|20:1099511627776|3:2|3:2|11:True|!13|11:True',
    'vop.or.empty'                          : '0:|1:!0|3:7|20:1099511627776|3:2|3:2|3:12|!9|11:True',
    'vop.or.null'                           : '1:!0|1:!0|3:7|20:1099511627776|5:2,5|6:2,5|258:12|!13|11:True',
    'vop.or.int'                            : '3:7|3:7|3:7|20:1099511627783|3:7|3:7|3:15|!9|3:-1',
    'vop.or.int64'                          : '20:1099511627776|20:1099511627776|20:1099511627783|20:1099511627776|!5|!5|!5|!5|20:-1',
    'vop.or.double'                         : '3:2|5:2,5|3:7|!5|3:2|3:2|3:14|!9|3:-1',
    'vop.or.currency'                       : '3:2|6:2,5|3:7|!5|3:2|3:2|3:14|!9|3:-1',
    'vop.or.numtext'                        : '3:12|258:12|3:15|!5|3:14|3:14|3:12|!9|11:True',
    'vop.or.text'                           : '!9|!13|!9|!9|!9|!9|!9|!9|!13',
    'vop.or.true'                           : '11:True|11:True|3:-1|20:-1|3:-1|3:-1|11:True|11:True|11:True',
    'vop.xor.empty'                         : '0:|1:!0|3:7|20:1099511627776|3:2|3:2|3:12|!9|11:True',
    'vop.xor.null'                          : '1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0|1:!0',
    'vop.xor.int'                           : '3:7|1:!0|3:0|20:1099511627783|3:5|3:5|3:11|!9|3:-8',
    'vop.xor.int64'                         : '20:1099511627776|1:!0|20:1099511627783|20:0|!5|!5|!5|!5|20:-1099511627777',
    'vop.xor.double'                        : '3:2|1:!0|3:5|!5|3:0|3:0|3:14|!9|3:-3',
    'vop.xor.currency'                      : '3:2|1:!0|3:5|!5|3:0|3:0|3:14|!9|3:-3',
    'vop.xor.numtext'                       : '3:12|1:!0|3:11|!5|3:14|3:14|3:0|!9|11:False',
    'vop.xor.text'                          : '!9|1:!0|!9|!9|!9|!9|!9|!9|!13',
    'vop.xor.true'                          : '11:True|1:!0|3:-8|20:-1099511627777|3:-3|3:-3|11:False|!13|11:False',
    'vcmp.eq.empty'                         : 't|f|f|f|f|f|f|f|f|f|f',
    'vcmp.eq.null'                          : 'f|t|f|f|f|f|f|f|f|f|f',
    'vcmp.eq.int'                           : 'f|f|t|t|t|f|t|t|!7|!7|f',
    'vcmp.eq.int64'                         : 'f|f|t|t|t|f|t|t|!7|!7|f',
    'vcmp.eq.double'                        : 'f|f|t|t|t|f|t|t|!7|!7|f',
    'vcmp.eq.fraction'                      : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vcmp.eq.currency'                      : 'f|f|t|t|t|f|t|t|!8|!8|f',
    'vcmp.eq.numtext'                       : 'f|f|t|t|t|f|t|t|f|f|t',
    'vcmp.eq.lower'                         : 'f|f|!7|!7|!7|!7|!8|f|t|f|!13',
    'vcmp.eq.upper'                         : 'f|f|!7|!7|!7|!7|!8|f|f|t|!13',
    'vcmp.eq.true'                          : 'f|f|f|f|f|f|f|t|!13|!13|t',
    'vcmp.ne.empty'                         : 'f|t|t|t|t|t|t|t|t|t|t',
    'vcmp.ne.null'                          : 't|f|t|t|t|t|t|t|t|t|t',
    'vcmp.ne.int'                           : 't|t|f|f|f|t|f|f|!7|!7|t',
    'vcmp.ne.int64'                         : 't|t|f|f|f|t|f|f|!7|!7|t',
    'vcmp.ne.double'                        : 't|t|f|f|f|t|f|f|!7|!7|t',
    'vcmp.ne.fraction'                      : 't|t|t|t|t|f|t|t|!7|!7|t',
    'vcmp.ne.currency'                      : 't|t|f|f|f|t|f|f|!8|!8|t',
    'vcmp.ne.numtext'                       : 't|t|f|f|f|t|f|f|t|t|f',
    'vcmp.ne.lower'                         : 't|t|!7|!7|!7|!7|!8|t|f|t|!13',
    'vcmp.ne.upper'                         : 't|t|!7|!7|!7|!7|!8|t|t|f|!13',
    'vcmp.ne.true'                          : 't|t|t|t|t|t|t|f|!13|!13|f',
    'vcmp.lt.empty'                         : 'f|f|t|t|t|t|t|t|t|t|t',
    'vcmp.lt.null'                          : 't|f|t|t|t|t|t|t|t|t|t',
    'vcmp.lt.int'                           : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vcmp.lt.int64'                         : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vcmp.lt.double'                        : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vcmp.lt.fraction'                      : 'f|f|f|f|f|f|f|f|!7|!7|f',
    'vcmp.lt.currency'                      : 'f|f|f|f|f|t|f|f|!8|!8|f',
    'vcmp.lt.numtext'                       : 'f|f|f|f|f|t|f|f|t|t|f',
    'vcmp.lt.lower'                         : 'f|f|!7|!7|!7|!7|!8|f|f|f|!13',
    'vcmp.lt.upper'                         : 'f|f|!7|!7|!7|!7|!8|f|t|f|!13',
    'vcmp.lt.true'                          : 'f|f|t|t|t|t|t|f|!13|!13|f',
    'vcmp.le.empty'                         : 't|f|t|t|t|t|t|t|t|t|t',
    'vcmp.le.null'                          : 't|t|t|t|t|t|t|t|t|t|t',
    'vcmp.le.int'                           : 'f|f|t|t|t|t|t|t|!7|!7|f',
    'vcmp.le.int64'                         : 'f|f|t|t|t|t|t|t|!7|!7|f',
    'vcmp.le.double'                        : 'f|f|t|t|t|t|t|t|!7|!7|f',
    'vcmp.le.fraction'                      : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vcmp.le.currency'                      : 'f|f|t|t|t|t|t|t|!8|!8|f',
    'vcmp.le.numtext'                       : 'f|f|t|t|t|t|t|t|t|t|t',
    'vcmp.le.lower'                         : 'f|f|!7|!7|!7|!7|!8|f|t|f|!13',
    'vcmp.le.upper'                         : 'f|f|!7|!7|!7|!7|!8|f|t|t|!13',
    'vcmp.le.true'                          : 'f|f|t|t|t|t|t|t|!13|!13|t',
    'vcmp.gt.empty'                         : 'f|t|f|f|f|f|f|f|f|f|f',
    'vcmp.gt.null'                          : 'f|f|f|f|f|f|f|f|f|f|f',
    'vcmp.gt.int'                           : 't|t|f|f|f|f|f|f|!7|!7|t',
    'vcmp.gt.int64'                         : 't|t|f|f|f|f|f|f|!7|!7|t',
    'vcmp.gt.double'                        : 't|t|f|f|f|f|f|f|!7|!7|t',
    'vcmp.gt.fraction'                      : 't|t|t|t|t|f|t|t|!7|!7|t',
    'vcmp.gt.currency'                      : 't|t|f|f|f|f|f|f|!8|!8|t',
    'vcmp.gt.numtext'                       : 't|t|f|f|f|f|f|f|f|f|f',
    'vcmp.gt.lower'                         : 't|t|!7|!7|!7|!7|!8|t|f|t|!13',
    'vcmp.gt.upper'                         : 't|t|!7|!7|!7|!7|!8|t|f|f|!13',
    'vcmp.gt.true'                          : 't|t|f|f|f|f|f|f|!13|!13|f',
    'vcmp.ge.empty'                         : 't|t|f|f|f|f|f|f|f|f|f',
    'vcmp.ge.null'                          : 'f|t|f|f|f|f|f|f|f|f|f',
    'vcmp.ge.int'                           : 't|t|t|t|t|f|t|t|!7|!7|t',
    'vcmp.ge.int64'                         : 't|t|t|t|t|f|t|t|!7|!7|t',
    'vcmp.ge.double'                        : 't|t|t|t|t|f|t|t|!7|!7|t',
    'vcmp.ge.fraction'                      : 't|t|t|t|t|t|t|t|!7|!7|t',
    'vcmp.ge.currency'                      : 't|t|t|t|t|f|t|t|!8|!8|t',
    'vcmp.ge.numtext'                       : 't|t|t|t|t|f|t|t|f|f|t',
    'vcmp.ge.lower'                         : 't|t|!7|!7|!7|!7|!8|t|t|t|!13',
    'vcmp.ge.upper'                         : 't|t|!7|!7|!7|!7|!8|t|f|t|!13',
    'vcmp.ge.true'                          : 't|t|f|f|f|f|f|t|!13|!13|t',
    'vint.byte_add'                         : '3:256',
    'vint.byte_sub'                         : '3:-1',
    'vint.byte_mul'                         : '3:40000',
    'vint.shortint_add'                     : '3:128',
    'vint.word_add'                         : '3:65536',
    'vint.smallint_add'                     : '3:32768',
    'vint.cardinal_add'                     : '20:4294967296',
    'vint.cardinal_sub'                     : '20:-1',
    'vint.integer_add'                      : '5:2147483648',
    'vint.integer_sub'                      : '5:-2147483649',
    'vint.integer_mul'                      : '5:4294967296',
    'vint.integer_neg'                      : '3:-2147483648',
    'msg.14'                                : 'Integer overflow',
    'vint.integer_div'                      : '!14',
    'vint.int64_add'                        : '20:-9223372036854775808',
    'vint.int64_mul'                        : '20:0',
    'vint.integer_shl'                      : '3:256',
    'vint.integer_shl_31'                   : '3:-2147483648',
    'vint.int64_shl'                        : '20:1099511627776',
    'vint.byte_shl'                         : '3:512',
    'vint.integer_shr'                      : '3:2147483644',
    'vint.cardinal_shr'                     : '20:2147483647',
    'vint.integer_not'                      : '3:-6',
    'vint.byte_not'                         : '17:250',
    'vint.integer_div_zero'                 : '!12',
    'vint.integer_mod_zero'                 : '!12',
    'vint.integer_mod_negative'             : '3:-1',
    'msg.15'                                : 'Type Mismatch',
    'vunary.neg'                            : '2:0|1:!0|3:-7|20:-1099511627776|5:-2,5|6:-2,5|5:-12|!15|2:-1',
    'vunary.not'                            : '16:-1|1:!0|3:-8|20:-1099511627777|3:-3|3:-3|3:-13|!15|11:False',
    'vcalc.integer_add'                     : '8|2|4|13|!7|0|1|!1|!5|4',
    'vcalc.integer_div'                     : '1|3|3|0|!9|-7|!12|!1|0|3',
    'vcalc.byte_add'                        : '8|2|4|13|!7|0|1|!2|1|4',
    'vcalc.cardinal_add'                    : '8|2|4|13|!7|0|1|!2|1|4',
    'vcalc.int64_add'                       : '8|2|4|13|!7|0|1|!2|1099511627777|4',
    'vcalc.double_add'                      : (
        '8.000000000000|2.500000000000|3.500000000000|13.000000000000|!7|0.000000000000|'
        '1.000000000000|!3|1099511627777.000000000000|3.500000000000'
    ),
    'vcalc.string_add'                      : '!7|!7|!7|[x12]|[xab]|!7|[x]|!0|!7|!8',
    'vtcmp.integer_eq'                      : 'f|f|t|t|t|f|t|t|!7|!7|f',
    'vtcmp.integer_lt'                      : 'f|f|f|f|f|t|f|f|!7|!7|f',
    'vtcmp.byte_eq'                         : 'f|!2|t|t|t|t|t|t|!10|!10|f',
    'vtcmp.cardinal_eq'                     : 'f|!2|t|t|t|t|t|t|!10|!10|f',
    'vtcmp.int64_eq'                        : 'f|!2|t|t|t|t|t|t|!10|!10|f',
    'vtcmp.double_eq'                       : 'f|!3|t|t|t|f|t|t|!7|!7|f',
    'vtcmp.string_eq'                       : 'f|!0|t|t|t|f|t|t|f|f|f',
    'vtcmp.string_lt'                       : 'f|!0|f|f|f|t|f|f|t|t|t',
    'vtext.double'                          : '2,5|2,5',
    'vtext.double_third'                    : '0,333333333333333|0,333333333333333',
    'vtext.double_small'                    : '1E-5|1E-5',
    'vtext.double_large'                    : '1,23456789012346E17|1,23456789012346E17',
    'vtext.double_e15'                      : '1E15|1E15',
    'vtext.double_negative'                 : '-0,5|-0,5',
    'vtext.single'                          : '0,100000001490116|0,100000001490116',
    'vtext.currency'                        : '2,5|2,5',
    'vtext.currency_negative'               : '-1,5|-1,5',
    'vtext.currency_third'                  : '0,3333|0,3333',
    'vtext.int64_minimum'                   : '-9223372036854775808|-9223372036854775808',
    'vtext.false'                           : 'False|False',
    'vtext.null'                            : '|!0',
    'vtext.empty'                           : '|',
    'msg.16'                                : 'Format \'%f\' invalid or incompatible with argument',
    'vtext.format_f'                        : '!16',
    'msg.17'                                : 'Format \'%g\' invalid or incompatible with argument',
    'vtext.format_g'                        : '!17',
    'fpu.control_word'                      : '895',
    'fpu.masked_division_by_zero'           : '+Inf;INF',
    'fpu.masked_zero_by_zero'               : 'Nan;NAN',
    'fpu.masked_negative_by_zero'           : '-Inf;-INF',
    'fpu.masked_overflow'                   : '+Inf;INF',
    'fpu.masked_underflow'                  : ' 1.0E-0318;9,999987484956E-319',
    'fpu.masked_nan_equals_nan'             : 'f',
    'fpu.masked_round_of_infinity'          : '0',
    'fpu.masked_round_beyond_int64'         : '0',
    'fpu.round_beyond_integer'              : '-1294967296',
    'fpu.masked_single_overflow'            : '+Inf',
    'fpu.masked_currency_overflow'          : '-922337203685477.581000000000',
    'msg.18'                                : 'Floating point division by zero',
    'fpu.unmasked_division_by_zero'         : '!18',
    'msg.19'                                : 'Invalid floating point operation',
    'fpu.unmasked_zero_by_zero'             : '!19',
    'msg.20'                                : 'Floating point overflow',
    'fpu.unmasked_overflow'                 : '!20',
    'fpu.unmasked_underflow'                : ' 1.0E-0318;9,999987484956E-319',
    'fpu.unmasked_round_beyond_int64'       : '!19',
    'fpu.unmasked_currency_overflow'        : '!19',
    'fpu.control_word_after_set'            : '4978',
    'float.round_and_trunc'                 : '0|2|2|0|-2|-2|3|2|-2|1',
    'float.float_to_str_row'                : (
        '100000000000000000000.000000000000|0.000000000000|123456789.123456791000|0.666666666667|'
        '0.000000000000|0.000000000002|0.000000000000|0.000000000000|+Inf|-Inf|Nan'
    ),
    'float.float_to_str_range'              : (
        '100000000000000000.000000000000|1000000000000000000.000000000000|'
        '10000000000000000000.000000000000|1000000000000000020000000000000.000000000000| 1.0E+0038|'
        ' 1.0E+0039| 1.0E+0100| 1.0E+0300|-1.0E+0300| 1.0E-0100| 1.0E-0300| 2.2E-0308| 1.0E-0309|'
        ' 1.0E+4000| 1.0E-4000'
    ),
    'prec.double_sum_equals_constant'       : 'f',
    'prec.double_sum_residue'               : '-1,11130722679764E-017',
    'prec.extended_sum_residue'             : '0,00000000000000E+000',
    'prec.double_equals_constant'           : 'f',
    'prec.extended_equals_constant'         : 't',
    'prec.extended_minus_double'            : '1,85127520951900E-017',
    'prec.double_third_times_three'         : 't',
    'prec.double_odd_beyond_53_bits'        : '9007199254740992',
    'prec.extended_odd_beyond_53_bits'      : '9007199254740993',
    'prec.single_odd_beyond_24_bits'        : '16777216',
    'prec.single_product'                   : '0.300000011921',
    'prec.currency_tie_even'                : '2.000000000000',
    'prec.currency_tie_odd'                 : '2.000200000000',
    'prec.currency_third'                   : '0.333300000000',
    'prec.currency_product'                 : '2.250200000000',
    'prec.currency_half_of_smallest'        : '0.000000000000',
    'ffmt.g_e15'                            : '[1E015]',
    'ffmt.g_e16'                            : '[1E016]',
    'ffmt.g_digits'                         : '[123456,789012345]',
    'ffmt.g_ten_thousandth'                 : '[0,0001]',
    'ffmt.g_hundred_thousandth'             : '[1E-005]',
    'ffmt.g_e100'                           : '[1E100]',
    'ffmt.g_precision'                      : '[1,23E003]',
    'ffmt.g_zero'                           : '[0]',
    'ffmt.e_precision'                      : '[1,23E+003]',
    'ffmt.e_zero'                           : '[0,00000000000000E+000]',
    'ffmt.e_tiny'                           : '[1,00000000000000E-300]',
    'ffmt.f_tie_even'                       : '[3]',
    'ffmt.f_tie_odd'                        : '[4]',
    'ffmt.f_one_decimal'                    : '[0,1]',
    'ffmt.f_two_decimals'                   : '[1,01]',
    'ffmt.f_width'                          : '[      3,14]',
    'ffmt.f_left'                           : '[3,14      ]',
    'ffmt.f_large'                          : '[1E20]',
    'ffmt.f_negative_zero'                  : '[0,0]',
    'ffmt.n_negative'                       : '[-1.234.567,89]',
    'ffmt.n_no_decimals'                    : '[1.235]',
    'ffmt.m_zero'                           : '[0,00 €]',
    'ffmt.m_no_decimals'                    : '[3 €]',
    'ffmt.m_large'                          : '[1E20]',
    'ffmt.g_infinity'                       : '[INF]',
    'ffmt.f_infinity'                       : '[INF]',
    'ffmt.g_nan'                            : '[NAN]',
    'ffmt.f_currency'                       : '!16',
    'msg.21'                                : 'Format \'%m\' invalid or incompatible with argument',
    'ffmt.m_currency'                       : '!21',
    'ffmt.g_single'                         : '[0,100000001490116]',
    'msg.22'                                : 'Format \'%s\' invalid or incompatible with argument',
    'ffmt.s_of_float'                       : '!22',
    'msg.23'                                : '\'12 \' is not a valid integer value',
    'msg.24'                                : '\'\' is not a valid integer value',
    'msg.25'                                : '\' \' is not a valid integer value',
    'msg.26'                                : '\'1e3\' is not a valid integer value',
    'msg.27'                                : '\'12a\' is not a valid integer value',
    'msg.28'                                : '\'$\' is not a valid integer value',
    'msg.29'                                : '\'- 12\' is not a valid integer value',
    'msg.30'                                : '\'\t12\' is not a valid integer value',
    'msg.31'                                : '\'9223372036854775808\' is not a valid integer value',
    'msg.32'                                : '\'1.0\' is not a valid integer value',
    'parse.strtoint'                        : (
        '12|12|-1|12|-12|31|31|31|31|-1|-1|2147483647|-1|-2147483648|-1|-1|-1|-1|-1|-1|12|-1|-31|-1|'
        '-1|-1|-1|-1|-1|31|-1'
    ),
    'parse.strtointdef'                     : (
        '12|12|99|12|-12|31|31|31|31|-1|99|2147483647|99|-2147483648|99|99|99|99|99|99|12|99|-31|99|'
        '99|99|99|99|99|31|99'
    ),
    'parse.strtoint64'                      : (
        '12|12|!23|12|-12|31|31|31|31|4294967295|4294967296|2147483647|2147483648|-2147483648|'
        '-2147483649|4294967295|!24|!25|!26|!27|12|!28|-31|!29|!30|9223372036854775807|!31|-1|'
        '-9223372036854775808|31|!32'
    ),
    'parse.strtoint64def'                   : (
        '12|12|99|12|-12|31|31|31|31|4294967295|4294967296|2147483647|2147483648|-2147483648|'
        '-2147483649|4294967295|99|99|99|99|12|99|-31|99|99|9223372036854775807|99|-1|'
        '-9223372036854775808|31|99'
    ),
    'msg.33'                                : 'Invalid float',
    'parse.strtofloat'                      : (
        '1.500000000000|1.500000000000|!33|!33|1000.000000000000|1000.000000000000|0.500000000000|'
        '5.000000000000|1.500000000000|-1.500000000000|!33|!33|!33|!33|!33| 1.0E+0400|!33|'
        ' 1.0E-0400|12.000000000000'
    ),
    'msg.34'                                : 'Could not call proc',
    'msg.35'                                : 'Out of string range',
    'sindex.string_read'                    : 'o!34|o!34|ra|rb|rc|o!34',
    'sindex.string_read_finally'            : 'fo!35|fo!35|raf|rbf|rcf|fo!35',
    'sindex.string_write'                   : 'e!35abc|e!35abc|wxbc|waxc|wabx|e!35abc',
    'sindex.ansistring_read'                : 'o!34|o!34|ra|rb|rc|o!34',
    'sindex.ansistring_write'               : 'e!35abc|e!35abc|wxbc|waxc|wabx|e!35abc',
    'sindex.empty_read'                     : 'o!34',
    'share.assigned'                        : 'x',
    'share.resized'                         : 'a',
    'share.resized_to_same_length'          : 'x',
    'share.assigned_other_way'              : 'y',
    'share.parameter_by_value'              : 'by value',
    'share.parameter_resized'               : 'a;2',
    'share.parameter_by_reference'          : 'by reference',
    'share.record_copy'                     : 'x;x',
    'share.nested'                          : 'x',
    'share.cleared_source'                  : 'a;2',
    'share.static_array'                    : 'a',
    'probe.str_large'                       : (
        '9999999999999999640000000000000.000000000000|99999999999999987400000000000000.000000000000|'
        '999999999999999946000000000000000.000000000000|'
        '9999999999999999460000000000000000.000000000000|'
        '99999999999999996900000000000000000.000000000000| 1.0E+0036| 1.0E+0037| 1.0E+0038|'
        ' 5.0E+0037| 9.0E+0037| 1.0E+0038| 1.0E+0038'
    ),
    'probe.str_small'                       : (
        '0.000000000000|0.000000000000|0.000000000000|0.000000000000|0.000000000000|0.000000000000|'
        '0.000000000000|0.000000000000|0.000000000000|0.000000000000|0.000000000000|0.000000000000|'
        '0.000000000000|0.000000000000| 1.0E-0035| 1.0E-0036| 1.0E-0037| 1.0E-0038| 1.0E-0039|'
        ' 1.0E-0040| 1.0E-0041| 1.0E-0042| 1.0E-0043| 1.0E-0044| 1.0E-0045| 1.0E-0038| 1.0E-0039'
    ),
    'probe.null_logic'                      : '11:False|11:False|1:!0|1:!0|3:0|3:0|1:!0|1:!0|1:!0|11:False',
    'probe.text_to_double'                  : (
        '1234.500000000000|-1.500000000000|3.000000000000|123.000000000000|-12.000000000000|'
        '-12.000000000000|31.000000000000|150.000000000000|12.000000000000|!7|12.500000000000|'
        '13.500000000000|!7|!7|!7|0.500000000000|1.000000000000|!7'
    ),
    'probe.text_to_integer'                 : '1234|-2|3|123|-12|-12|31|150|12|!9|12|14|0|1|!9|0|1|!9',
    'probe.strtofloat'                      : (
        '0.000000000000|0.000000000000|!33|!33|+Inf|-0.500000000000|5.000000000000|!33|'
        '0.000000000000|0.100000000000|!33|!33'
    ),
    'probe.variant_integers'                : (
        '20:4000000001|20:-2446744073709551616|20:-4000000000|19:294967295|18:65530|3:-5|2:-6|3:0|'
        '3:400'
    ),
    'probe.variant_strings'                 : '256:abcd|258:cdab|8:efcd|258:cdef|8:ef|8:gh',
    'msg.36'                                : 'Could not convert variant of type (Null) into type (String)',
    'probe.variant_reads'                   : '99|99|!15|!2|!36|!0|0',
    'builtin.str_bands'                     : (
        '99999999999999996900000000000000000.000000000000|'
        '199999999999999994000000000000000000.000000000000|'
        '500000000000000021000000000000000000.000000000000| 1.0E-0035|0.000000000000|0.000000000000'
    ),
    'builtin.math'                          : (
        '2.000000000000|-2.000000000000|2.500000000000|1.414213562373|Nan|3.141592653590|'
        '0.841470984808|0.540302305868|3,14159265358979324E+000|1,41421356237309505E+000|'
        '8,41470984807896507E-001|-4|1410065408'
    ),
    'builtin.text'                          : '[   ab]|[abcdef]|[ab  ]|[0]|[00-7]|[xxx]|[]|[-5]|[9223372036854775807]',
    'builtin.varisnull'                     : 'f|t|f|f|f|f|f|f|f',
    'builtin.varisempty'                    : 't|f|f|f|f|f|f|f|f',
    'builtin.varisclear'                    : 't|f|f|f|f|f|f|f|f',
    'msg.37'                                : 'Could not convert variant of type (Integer) into type (Dispatch)',
    'msg.38'                                : 'Could not convert variant of type (Null) into type (Dispatch)',
    'msg.39'                                : 'Could not convert variant of type (UnicodeString) into type (Dispatch)',
    'msg.40'                                : 'Could not convert variant of type (Dispatch) into type (OleStr)',
    'builtin.dispatch'                      : '!37|ok|!38|!39|9:!40|t',
    'split'                                 : '4[a]["b c"][d][e]|3[x]["y,z"][w]|2[p][q]',
    'zero.add.0'                            : '3:3|3:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|5:2|5:2',
    'zero.add.1'                            : '5:3|5:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|5:2|5:2',
    'zero.add.2'                            : '5:3|5:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|5:2|5:2',
    'zero.add.3'                            : '6:3|6:3|6:2,5|6:2,5|6:-2,5|6:-2,5|6:1,5|6:1,5|6:2|6:2',
    'zero.add.4'                            : '5:3|5:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|258:02|258:20',
    'zero.add.5'                            : '3:3|3:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|5:2|5:2',
    'zero.add.6'                            : '3:3|3:3|5:2,5|5:2,5|5:-2,5|5:-2,5|6:1,5|6:1,5|8:2|258:2',
    'zero.sub.0'                            : '3:-3|3:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.sub.1'                            : '5:-3|5:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.sub.2'                            : '5:-3|5:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.sub.3'                            : '6:-3|6:3|6:-2,5|6:2,5|6:2,5|6:-2,5|6:-1,5|6:1,5|6:-2|6:2',
    'zero.sub.4'                            : '5:-3|5:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.sub.5'                            : '3:-3|3:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.sub.6'                            : '3:-3|3:3|5:-2,5|5:2,5|5:2,5|5:-2,5|6:-1,5|6:1,5|5:-2|5:2',
    'zero.mul.0'                            : '3:0|3:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.mul.1'                            : '5:0|5:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.mul.2'                            : '5:0|5:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.mul.3'                            : '6:0|6:0|6:0|6:0|6:0|6:0|6:0|6:0|6:0|6:0',
    'zero.mul.4'                            : '5:0|5:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.mul.5'                            : '3:0|3:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.mul.6'                            : '3:0|3:0|5:0|5:0|5:0|5:0|6:0|6:0|5:0|5:0',
    'zero.slash.0'                          : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.slash.1'                          : '5:0|!12|5:0|5:INF|5:0|5:-INF|5:0|6:-922337203685477,5808|5:0|!12',
    'zero.slash.2'                          : '5:0|!12|5:0|5:-INF|5:0|5:INF|5:0|6:-922337203685477,5808|5:0|!12',
    'zero.slash.3'                          : '6:0|!12|6:0|5:INF|6:0|5:-INF|6:0|6:-922337203685477,5808|6:0|!12',
    'zero.slash.4'                          : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.slash.5'                          : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.slash.6'                          : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.div.0'                            : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.div.1'                            : '5:0|!12|5:0|5:INF|5:0|5:-INF|5:0|6:-922337203685477,5808|5:0|!12',
    'zero.div.2'                            : '5:0|!12|5:0|5:-INF|5:0|5:INF|5:0|6:-922337203685477,5808|5:0|!12',
    'zero.div.3'                            : '6:0|!12|6:0|5:INF|6:0|5:-INF|6:0|6:-922337203685477,5808|6:0|!12',
    'zero.div.4'                            : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.div.5'                            : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.div.6'                            : '3:0|!12|3:0|5:INF|3:0|5:-INF|3:0|6:-922337203685477,5808|3:0|!12',
    'zero.mod.0'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.1'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.2'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.3'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.4'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.5'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.mod.6'                            : '3:0|!12|3:0|!12|3:0|!12|3:0|!12|3:0|!12',
    'zero.typed'                            : (
        '0.000000000000|0.000000000000|0.000000000000|0.000000000000|0.000000000000 0 0,0|5:0|6:0|'
        '6:0|6:0'
    ),
    'unassigned'                            : '0:|true|false|false|true|false|true|0:|6:0|0.000000000000 0.000000000000|[]0 0|[]',
    'msg.41'                                : 'Variant is null, cannot invoke',
    'dispatch.nil'                          : '!41|!38|!37|!39',
    'currency.operands'                     : '6:2|6:-2|6:0|6:0|6:2|6:-2|6:0|6:0|6:3,5|6:3|6:-922337203685477,5808|6:0',
    'parse.long'                            : (
        'true 6,75399432318247178E-010|true 3,53295631822787147E+013|true 3,46975596141450231E+024|'
        'true 2,53171521814181526E+004|true 9,83905176009339721E+004|true 7,45969329741637866E+013'
    ),
    'parse.extreme'                         : (
        'INF|0,00000000000000000E+000|INF|1,00000000000000000E+001|INF|1,00000000000000000E+001|'
        '1,00000000000000000E+001|INF|0,00000000000000000E+000|INF|INF|1,00000000000000000E+000'
    ),
    'msg.42'                                : 'Overflow while converting variant of type (UnicodeString) into type (Double)',
    'msg.43'                                : 'Overflow while converting variant of type (UnicodeString) into type (Currency)',
    'msg.44'                                : 'Overflow while converting variant of type (UnicodeString) into type (Int64)',
    'ole.double'                            : (
        '!42|!42|0,0000000000000000E+000|4,9406564584124654E-323|2,4703282292062327E-323|'
        '1,0000000000000000E+030|9,2233720368547800E+014|9,2233720368547758E+018|'
        '-9,2233720368547758E+018|2,1474836475000000E+010|2,1474836465000000E+010|'
        '1,0000000000000002E+053|1,0000000000000001E+058|!42|!42|1,0000000000000000E+000'
    ),
    'ole.currency'                          : '!43|!43|0|0|0|!43|!43|!43|!43|21474836475|21474836465|!43|!43|!43|!43|1',
    'ole.integer'                           : '!11|!11|0|0|0|!11|!11|!11|!11|!11|!11|!11|!11|!11|!11|1',
    'ole.int64'                             : (
        '!44|!44|0|0|0|-9223372036854775808|922337203685478|-9223372036854775808|'
        '-9223372036854775808|21474836475|21474836465|-9223372036854775808|-9223372036854775808|!44|'
        '!44|1'
    ),
    'ole.boolean'                           : '!44|!44|false|false|false|false|true|false|false|true|true|false|false|!44|!44|true',
    'text.large'                            : (
        ' 1.0E+4900 1E4900| 1.0E-4900 1E-4900| 1.0E-4940 0| 1.0E+4901 1E4901|'
        '599999999999999981000000000000000000.000000000000| 7.0E+0035| 8.0E+0035| 9.0E+0035|'
        ' 1.0E+0036| 1.1E-0035|0.000000000000|0.000000000000'
    ),
    'parse.powers'                          : (
        'true 1,25167000000000000E-048|true 5,81000000000000000E+031|true 2,02796597296790000E+029|'
        'true 4,62086660000000000E-047|true 2,76410000000000000E+031|true 3,60000000000000000E-010'
    ),
    'parse.scales'                          : 'INF|INF|INF|1,00000000000000000E-4901',
    'parse.first_infinite_exponent'         : '4998',
    'parse.edge'                            : '1,00000000000000000E+4932|1,00000000000000000E+4932|1,00000000000000000E+4932',
    'parse.exponent_limit'                  : 'INF|INF|INF|0,00000000000000000E+000|INF',
    'strings.char_20m'                      : '20000000 [xxxxxxxxxxxxxxxxxxxx...xxxxxxxxxxxxxxxxxxxx]',
    'msg.45'                                : 'Format \'[%99999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_11'               : '!45',
    'msg.46'                                : 'Format \'[%999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_12'               : '!46',
    'msg.47'                                : 'Format \'[%9999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_13'               : '!47',
    'msg.48'                                : 'Format \'[%99999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_14'               : '!48',
    'msg.49'                                : 'Format \'[%999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_15'               : '!49',
    'msg.50'                                : 'Format \'[%9999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_16'               : '!50',
    'msg.51'                                : 'Format \'[%99999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_17'               : '!51',
    'msg.52'                                : 'Format \'[%999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_18'               : '!52',
    'msg.53'                                : 'Format \'[%9999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_19'               : '!53',
    'msg.54'                                : 'Format \'[%99999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_20'               : '!54',
    'msg.55'                                : 'Format \'[%999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_21'               : '!55',
    'msg.56'                                : 'Format \'[%9999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_22'               : '!56',
    'msg.57'                                : 'Format \'[%99999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_23'               : '!57',
    'msg.58'                                : 'Format \'[%999999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_24'               : '!58',
    'msg.59'                                : 'Format \'[%9999999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_25'               : '!59',
    'msg.60'                                : 'Format \'[%99999999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_26'               : '!60',
    'msg.61'                                : 'Format \'[%999999999999999999999999999d]\' invalid or incompatible with argument',
    'strings.width_digits_27'               : '!61',
    'msg.62'                                : 'Format \'[%9999999999999999999999999999d\' invalid or incompatible with argument',
    'strings.width_digits_28'               : '!62',
    'msg.63'                                : 'Format \'[%99999999999999999999999999999\' invalid or incompatible with argument',
    'strings.width_digits_29'               : '!63',
    'strings.width_digits_30'               : '!63',
    'strings.width_digits_31'               : '!63',
    'strings.width_digits_32'               : '!63',
    'strings.width_digits_33'               : '!63',
    'strings.width_digits_34'               : '!63',
    'strings.width_digits_35'               : '!63',
    'strings.width_digits_36'               : '!63',
    'strings.width_digits_37'               : '!63',
    'strings.width_digits_38'               : '!63',
    'strings.width_digits_39'               : '!63',
    'strings.width_digits_40'               : '!63',
    'strings.width_2g'                      : '!14',
    'strings.setlength_2g'                  : '!14',
    'msg.64'                                : 'Out of memory',
    'strings.char_2g'                       : '!64',
    'strings.step'                          : 'end',
}


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


class _OracleTest(TestBase):
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

    def assertEmulatedAsLogged(self, procedure: str, *names: str, prefix: str | None = None):
        """
        Emulates one procedure and compares what it logs with the log: the values of the given
        names, the values whose names start with the given prefix, or else every value that it
        logs with the logged values whose names are string constants of the procedure and of the
        script functions it calls. Exception messages are compared by their text.
        """
        emulator = self.emulator()
        function = emulator.symbols[procedure]
        emulated = _resolved(_logged_values(emulator.emulate_function(function), {}))
        log = _resolved(self.log)
        if prefix is not None:
            names = tuple(name for name in log.keys() | emulated.keys() if name.startswith(prefix))
            self.assertTrue(names)
        elif names:
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
            self.assertTrue(log.keys() & names)
        real = {name: value for name, value in log.items() if name in names}
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
    The procedures of this script store, compute with, compare, convert, parse, and format values
    of every type: integers, floats, Currency, sets, strings, Variants, and dynamic arrays.
    """
    script = _VALUE_SCRIPT
    log = _VALUE_LOG

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
        self.assertEmulatedAsLogged('ORACLEVARIANTCONVERSIONS', prefix='vconv.')

    def test_operators_on_every_pair_of_variant_types(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTOPERATORS', prefix='vop.')

    def test_comparisons_of_every_pair_of_variant_types(self):
        self.assertEmulatedAsLogged('ORACLEVARIANTCOMPARISONMATRIX', prefix='vcmp.')

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

    def test_text_and_conversions_at_the_edges_of_their_ranges(self):
        self.assertEmulatedAsLogged('ORACLEPROBES')

    def test_built_in_functions_for_floats_and_variants(self):
        self.assertEmulatedAsLogged('ORACLEBUILTINS')

    def test_operations_on_the_zero_of_every_type(self):
        self.assertEmulatedAsLogged('ORACLEZEROS', prefix='zero.')

    def test_a_new_variant_and_an_unset_result_are_unassigned(self):
        self.assertEmulatedAsLogged('ORACLEUNASSIGNED')

    def test_a_call_on_a_nil_com_object_raises_an_error(self):
        self.assertEmulatedAsLogged('ORACLENILINVOKE')

    def test_parsing_of_numbers_with_many_digits(self):
        self.assertEmulatedAsLogged('ORACLELONGPARSING')

    def test_variant_strings_beyond_the_range_of_a_double(self):
        self.assertEmulatedAsLogged('ORACLEOLELIMITS')

    def test_text_of_floats_near_the_ends_of_their_range(self):
        self.assertEmulatedAsLogged('ORACLELARGETEXT')

    def test_parsing_scales_by_one_power_of_ten(self):
        self.assertEmulatedAsLogged('ORACLEPARSINGPOWERS')

    def test_a_dynamic_array_assigned_to_another_variable_is_shared(self):
        self.assertEmulatedAsLogged('ORACLESHAREDARRAYS')

    @wontfix('Inno Setup 5.5.3 and 5.5.4 copy a shared dynamic array that keeps its length; the emulator follows 5.5.5 and later')
    def test_inno_setup_5_5_4_copies_a_shared_dynamic_array_that_keeps_its_length(self):
        emulator = self.emulator(setup_version=(5, 5, 4))
        logged = _resolved(_logged_values(emulator.emulate_function(emulator.symbols['ORACLESHAREDARRAYS']), {}))
        self.assertEqual(logged['share.resized_to_same_length'], 'a')

    def test_a_currency_computed_with_a_cardinal_or_an_int64_is_read_as_a_double(self):
        self.assertEmulatedAsLogged('ORACLECURRENCYOPERANDS')

    def test_a_string_index_outside_of_the_string_raises_an_error(self):
        self.assertEmulatedAsLogged('ORACLESTRINGINDEX')

    def test_a_split_keeps_the_separators_between_quote_characters(self):
        self.assertEmulatedAsLogged('ORACLESPLIT')

    def test_a_split_into_more_parts_than_the_array_limit_ends_the_emulation(self):
        emulator = self.emulator(max_array_length=3)
        logged = {}
        with self.assertRaises(EmulatorMaxArray):
            _logged_values(emulator.emulate_function(emulator.symbols['ORACLESPLIT']), logged)
        self.assertEqual(logged, {})

    def test_long_strings_raise_the_errors_of_delphi_before_they_are_built(self):
        """
        The last probe asks for a string of 2,000,000,000 characters, for which Setup raised `Out of
        memory`; the emulation ends there, as the string exceeds the limit of the configuration.
        Every other probe that Setup refused is refused before the emulator builds its string.
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
        log = _resolved(self.log)
        logged = _resolved(logged)
        self.assertEqual(logged.pop('strings.step'), '4')
        self.assertEqual(logged, {name: log[name] for name in logged})
        self.assertEqual(logged.keys() | {'strings.step', 'strings.char_2g'}, {n for n in log if n.startswith('strings.')})

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
