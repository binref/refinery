import json

from .. import TestUnitBase


class TestCBORDecoder(TestUnitBase):
    """
    Tests based on all examples from RFC 8949, Appendix A:
    https://www.rfc-editor.org/rfc/rfc8949.html#appendix-A
    """

    def _decode(self, hex_input: str, **kwargs):
        data = bytes.fromhex(hex_input)
        return data | self.load(**kwargs) | json.loads

    def test_uint_0(self):
        self.assertEqual(self._decode('00'), 0)

    def test_uint_1(self):
        self.assertEqual(self._decode('01'), 1)

    def test_uint_10(self):
        self.assertEqual(self._decode('0a'), 10)

    def test_uint_23(self):
        self.assertEqual(self._decode('17'), 23)

    def test_uint_24(self):
        self.assertEqual(self._decode('1818'), 24)

    def test_uint_25(self):
        self.assertEqual(self._decode('1819'), 25)

    def test_uint_100(self):
        self.assertEqual(self._decode('1864'), 100)

    def test_uint_1000(self):
        self.assertEqual(self._decode('1903e8'), 1000)

    def test_uint_1000000(self):
        self.assertEqual(self._decode('1a000f4240'), 1000000)

    def test_uint_1000000000000(self):
        self.assertEqual(self._decode('1b000000e8d4a51000'), 1000000000000)

    def test_uint_max_u64(self):
        self.assertEqual(self._decode('1bffffffffffffffff'), 18446744073709551615)

    def test_bignum_positive(self):
        # 18446744073709551616 = 2^64, encoded as tag 2 bignum
        self.assertEqual(self._decode('c249010000000000000000'), '0x10000000000000000')

    def test_bignum_negative(self):
        # -18446744073709551617, encoded as tag 3 bignum
        self.assertEqual(self._decode('c349010000000000000000'), '-0x10000000000000001')

    def test_nint_minus_18446744073709551616(self):
        # -18446744073709551616 encoded directly as major type 1, exceeds 64 bits
        self.assertEqual(self._decode('3bffffffffffffffff'), '-0x10000000000000000')

    def test_nint_minus_1(self):
        self.assertEqual(self._decode('20'), -1)

    def test_nint_minus_10(self):
        self.assertEqual(self._decode('29'), -10)

    def test_nint_minus_100(self):
        self.assertEqual(self._decode('3863'), -100)

    def test_nint_minus_1000(self):
        self.assertEqual(self._decode('3903e7'), -1000)

    def test_float16_0_0(self):
        self.assertEqual(self._decode('f90000'), 0.0)

    def test_float16_neg_0_0(self):
        self.assertEqual(self._decode('f98000'), -0.0)

    def test_float16_1_0(self):
        self.assertEqual(self._decode('f93c00'), 1.0)

    def test_float16_1_5(self):
        self.assertEqual(self._decode('f93e00'), 1.5)

    def test_float16_65504_0(self):
        self.assertEqual(self._decode('f97bff'), 65504.0)

    def test_float16_subnormal(self):
        # 5.960464477539063e-8
        self.assertAlmostEqual(self._decode('f90001'), 5.960464477539063e-8, places=20)

    def test_float16_min_positive_normal(self):
        # 0.00006103515625
        self.assertAlmostEqual(self._decode('f90400'), 0.00006103515625, places=15)

    def test_float16_neg_4_0(self):
        self.assertEqual(self._decode('f9c400'), -4.0)

    def test_float16_infinity(self):
        self.assertEqual(self._decode('f97c00'), 'Infinity')

    def test_float16_nan(self):
        self.assertEqual(self._decode('f97e00'), 'NaN')

    def test_float16_neg_infinity(self):
        self.assertEqual(self._decode('f9fc00'), '-Infinity')

    def test_float32_100000_0(self):
        self.assertEqual(self._decode('fa47c35000'), 100000.0)

    def test_float32_max(self):
        # 3.4028234663852886e+38
        self.assertAlmostEqual(self._decode('fa7f7fffff'), 3.4028234663852886e+38, delta=1e+31)

    def test_float32_infinity(self):
        self.assertEqual(self._decode('fa7f800000'), 'Infinity')

    def test_float32_nan(self):
        self.assertEqual(self._decode('fa7fc00000'), 'NaN')

    def test_float32_neg_infinity(self):
        self.assertEqual(self._decode('faff800000'), '-Infinity')

    def test_float64_1_1(self):
        self.assertAlmostEqual(self._decode('fb3ff199999999999a'), 1.1)

    def test_float64_1e300(self):
        self.assertEqual(self._decode('fb7e37e43c8800759c'), 1.0e+300)

    def test_float64_neg_4_1(self):
        self.assertAlmostEqual(self._decode('fbc010666666666666'), -4.1)

    def test_float64_infinity(self):
        self.assertEqual(self._decode('fb7ff0000000000000'), 'Infinity')

    def test_float64_nan(self):
        self.assertEqual(self._decode('fb7ff8000000000000'), 'NaN')

    def test_float64_neg_infinity(self):
        self.assertEqual(self._decode('fbfff0000000000000'), '-Infinity')

    def test_false(self):
        self.assertIs(self._decode('f4'), False)

    def test_true(self):
        self.assertIs(self._decode('f5'), True)

    def test_null(self):
        self.assertIsNone(self._decode('f6'))

    def test_undefined(self):
        # undefined (simple value 23) maps to null in JSON
        self.assertIsNone(self._decode('f7'))

    def test_simple_16(self):
        self.assertEqual(self._decode('f0'), 'simple(16)')

    def test_simple_255(self):
        self.assertEqual(self._decode('f8ff'), 'simple(255)')

    def test_tag0_datetime_string(self):
        result = self._decode('c074323031332d30332d32315432303a30343a30305a')
        self.assertEqual(result, {'tag': 0, 'value': '2013-03-21T20:04:00Z'})

    def test_tag1_epoch_integer(self):
        result = self._decode('c11a514b67b0')
        self.assertEqual(result, {'tag': 1, 'value': 1363896240})

    def test_tag1_epoch_float(self):
        result = self._decode('c1fb41d452d9ec200000')
        self.assertEqual(result, {'tag': 1, 'value': 1363896240.5})

    def test_tag23_bytes(self):
        result = self._decode('d74401020304')
        self.assertEqual(result['tag'], 23)

    def test_tag24_bytes(self):
        result = self._decode('d818456449455446')
        self.assertEqual(result['tag'], 24)

    def test_tag32_uri(self):
        result = self._decode('d82076687474703a2f2f7777772e6578616d706c652e636f6d')
        self.assertEqual(result, {'tag': 32, 'value': 'http://www.example.com'})

    def test_bstr_empty(self):
        self.assertEqual(self._decode('40'), '')

    def test_bstr_01020304(self):
        self.assertEqual(self._decode('4401020304'), '\x01\x02\x03\x04')

    def test_tstr_empty(self):
        self.assertEqual(self._decode('60'), '')

    def test_tstr_a(self):
        self.assertEqual(self._decode('6161'), 'a')

    def test_tstr_ietf(self):
        self.assertEqual(self._decode('6449455446'), 'IETF')

    def test_tstr_quote_backslash(self):
        self.assertEqual(self._decode('62225c'), '"\\')

    def test_tstr_u00fc(self):
        self.assertEqual(self._decode('62c3bc'), '\u00fc')

    def test_tstr_u6c34(self):
        self.assertEqual(self._decode('63e6b0b4'), '\u6c34')

    def test_tstr_u10151(self):
        self.assertEqual(self._decode('64f0908591'), '\U00010151')

    def test_array_empty(self):
        self.assertEqual(self._decode('80'), [])

    def test_array_1_2_3(self):
        self.assertEqual(self._decode('83010203'), [1, 2, 3])

    def test_array_nested(self):
        self.assertEqual(self._decode('8301820203820405'), [1, [2, 3], [4, 5]])

    def test_array_25_items(self):
        result = self._decode(
            '98190102030405060708090a0b0c0d0e0f101112131415161718181819')
        self.assertEqual(result, list(range(1, 26)))

    def test_map_empty(self):
        self.assertEqual(self._decode('a0'), {})

    def test_map_int_keys(self):
        self.assertEqual(self._decode('a201020304'), {'1': 2, '3': 4})

    def test_map_string_keys(self):
        self.assertEqual(self._decode('a26161016162820203'), {'a': 1, 'b': [2, 3]})

    def test_array_with_map(self):
        self.assertEqual(self._decode('826161a161626163'), ['a', {'b': 'c'}])

    def test_map_five_pairs(self):
        result = self._decode('a56161614161626142616361436164614461656145')
        self.assertEqual(result, {'a': 'A', 'b': 'B', 'c': 'C', 'd': 'D', 'e': 'E'})

    def test_indef_bstr(self):
        # (_ h'0102', h'030405')
        self.assertEqual(self._decode('5f42010243030405ff'), '\x01\x02\x03\x04\x05')

    def test_indef_tstr(self):
        # (_ "strea", "ming")
        self.assertEqual(self._decode('7f657374726561646d696e67ff'), 'streaming')

    def test_indef_array_empty(self):
        # [_ ]
        self.assertEqual(self._decode('9fff'), [])

    def test_indef_array_nested_indef(self):
        self.assertEqual(self._decode('9f018202039f0405ffff'), [1, [2, 3], [4, 5]])

    def test_indef_array_nested_definite(self):
        self.assertEqual(self._decode('9f01820203820405ff'), [1, [2, 3], [4, 5]])

    def test_definite_array_inner_indef(self):
        self.assertEqual(self._decode('83018202039f0405ff'), [1, [2, 3], [4, 5]])

    def test_definite_array_middle_indef(self):
        self.assertEqual(self._decode('83019f0203ff820405'), [1, [2, 3], [4, 5]])

    def test_indef_array_25_items(self):
        result = self._decode(
            '9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff')
        self.assertEqual(result, list(range(1, 26)))

    def test_indef_map_string_keys(self):
        self.assertEqual(
            self._decode('bf61610161629f0203ffff'),
            {'a': 1, 'b': [2, 3]})

    def test_array_with_indef_map(self):
        self.assertEqual(
            self._decode('826161bf61626163ff'),
            ['a', {'b': 'c'}])

    def test_indef_map_fun_amt(self):
        self.assertEqual(
            self._decode('bf6346756ef563416d7421ff'),
            {'Fun': True, 'Amt': -2})
