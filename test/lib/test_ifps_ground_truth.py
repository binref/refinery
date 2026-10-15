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
from refinery.lib.inno.ifps import Function, Op, Operand

from .. import TestBase

_INSTALLER = '50ab31a850d3000006a1551c6c07aa470ee3ec65b95a3a521f95ac053a5441ea'
_ORACLE_LINE = re.compile(r'ORACLE (\S+) = (.*)')
_LOGGED = {
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


class TestTheEmulatorLogsWhatInnoSetupLogged(TestBase):
    """
    The installer was built with Inno Setup 6.5.0 from a script whose procedures log values that
    Pascal Script computes, one procedure per area. The installer ran on Windows with a log file,
    and `_LOGGED` holds every value of that log. Each test emulates one procedure and compares
    every value it logs with the logged value; the names of those values are the string constants
    of the procedure and of the script functions it calls.
    """

    def assertEmulatedAsLogged(self, procedure: str):
        emulator = InnoSetupEmulator(InnoArchive(self.download_sample(_INSTALLER)), IFPSEmulatorConfig(log_calls=True))
        function = emulator.symbols[procedure]
        reached: list[Function] = [function]
        for caller in reached:
            for instruction in caller.body or ():
                if instruction.opcode is Op.Call:
                    reached.extend(
                        callee for callee in instruction.operands
                        if isinstance(callee, Function) and callee.body is not None and callee not in reached
                    )
        constants = {
            value
            for caller in reached
            for instruction in caller.body or ()
            for operand in instruction.operands
            if isinstance(operand, Operand)
            and operand.value is not None
            and isinstance(value := operand.value.value, str)
        }
        real = {name: value for name, value in _LOGGED.items() if name in constants}
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
