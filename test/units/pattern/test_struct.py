from struct import pack
from zlib import crc32

from refinery.lib.loader import load_pipeline as L

from .. import TestUnitBase


class TestStructUnit(TestUnitBase):

    def test_structured_data_01(self):
        size = 456
        body = self.generate_random_buffer(size)
        crc = crc32(body)
        data = pack('=BBHL', 0x07, 0x34, size, crc)
        data += B'Binary Refinery\0'
        data += body
        data += B'\0\0\0\0\0\0\0\0'
        unit = self.load('=B{type:B}HLa{:{2}}')
        out = next(data | unit)
        self.assertEqual(out.meta['type'], 0x34)
        self.assertEqual(out, body)

    def test_variable_cleanup(self):
        data = B'\x05ABCDE' B'BINARY' B'REFINERY'
        unit = self.load('B{key:{0}}{_b:6}{_r:8}', '{_b}', '{_r}')
        b, r = data | unit
        self.assertNotIn('_b', b.meta)
        self.assertNotIn('_r', b.meta)
        self.assertNotIn('_b', r.meta)
        self.assertNotIn('_r', r.meta)
        self.assertEqual(b, B'BINARY')
        self.assertEqual(r, B'REFINERY')

    def test_no_last_field(self):
        unit = self.load('6sB6s')
        self.assertEqual(bytes(B'Binary Refinery' | unit), B'Binary Refine')

    def test_zero_length(self):
        unit = self.load('{s:H}{d:s}', multi=True)
        data = (
            B'\x00\x00'
            B'\x02\x00' b'ok'
            B'\x03\x00' b'foo'
            B'\x03\x00' b'bar'
        )
        self.assertListEqual([B'', b'ok', b'foo', b'bar'], list(data | unit))

    def test_read_all(self):
        unit = self.load('{s:B}{d:s}{x}')
        data = (
            B'\x02' b'ok'
            B'\x03' b'foo'
            B'\x03' b'bar'
        )
        self.assertListEqual([b'\x03foo\x03bar'], list(data | unit))

    def test_auto_batch(self):
        pl = L(R'emit ABCDEF | struct -m {k:B}{:1}{:1} {2} {3} [[| pop a | pf {a}{k} ]]')
        self.assertEqual(pl(), B'B65E68')

    def test_use_variables_in_output(self):
        data = self.download_sample('4537fab9de768a668ab4e72ae2cce3169b7af2dd36a1723ddab09c04d31d61a5')
        test = data | self.load_pipeline('vsect .bss | struct {n:L}{k:n}{c:} {c:rc4[var:k]:snip[::2]}') | bytes
        self.assertIn(B'165.22.5'B'.66', test)

    def test_until(self):
        data = B'1A92750293738'
        test = data | self.load('{k:B}', multi=True, until='k==0x30') | []
        self.assertEqual(len(test), 6)

    def test_argument_assignment_failure_regression_01(self):
        test = self.load_pipeline('emit rep[10]:5szz | struct -m {k:1}{d:3} {k}{d:xor[var:k]} []') | bytes
        self.assertEqual(test, 10 * B'5FOO')

    def test_argument_assignment_failure_regression_02(self):
        test = self.load_pipeline('emit rep[1000]:5szz | struct -m {k:1}{d:3} {k}{d:xor[var:k]} []') | bytes
        self.assertEqual(test, 1000 * B'5FOO')

    def test_correct_leftover_calculation(self):
        test = self.load_pipeline('emit ABCDE | struct -mM {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')
        test = self.load_pipeline('emit ABCDEF | struct -mM {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')
        test = self.load_pipeline('emit ABCDE | struct -m {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'AC')
        test = self.load_pipeline('emit ABCDEF | struct -m {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')

    def test_variables_available_in_pipeline(self):
        data = B'\x02xxREFINERY'
        unit = self.load(r'{k:B}{d}', r'{d:snip[k:]}')
        test = data | unit | bytes
        self.assertEqual(test, B'REFINERY')

    def test_bit_field_reads_the_least_significant_bits_first(self):
        unit = self.load('{a!0:4}{b!0:4}', '{a},{b}')
        self.assertEqual(bytes(b'\x21' | unit), b'1,2')

    def test_bit_field_follows_the_byte_order_of_the_spec(self):
        unit = self.load('>{a!0:4}{b!0:4}', '{a},{b}')
        self.assertEqual(bytes(b'\x21' | unit), b'2,1')

    def test_bit_field_follows_network_byte_order(self):
        unit = self.load('!{a!0:4}{b!0:4}', '{a},{b}')
        self.assertEqual(bytes(b'\x21' | unit), b'2,1')

    def test_bit_field_spans_byte_boundaries(self):
        unit = self.load('{a!0:12}{b!0:4}', '{a},{b}')
        self.assertEqual(bytes(b'\x34\x12' | unit), b'564,1')

    def test_bit_field_count_can_use_previous_fields(self):
        unit = self.load('{n:B}{a!0:{n}}', '{a}')
        self.assertEqual(bytes(b'\x04\xab' | unit), b'11')

    def test_byte_reads_continue_at_the_current_bit(self):
        unit = self.load('{n!0:11}{m!0:3}{a:n}{b:m}', '{n},{m},{a},{b}')
        self.assertEqual(bytes(b'\x02\x48\x90\xd0\x10' | unit), b'2,1,AB,C')

    def test_alignment_discards_partial_bits(self):
        unit = self.load('{a!0:4}{b!1:B}', '{a},{b}')
        self.assertEqual(bytes(b'\x21X' | unit), b'1,88')

    def test_bit_field_records_continue_at_the_current_bit(self):
        unit = self.load('{a!0:4}', '{a}', multi=True)
        self.assertEqual([bytes(chunk) for chunk in b'\x12\x34' | unit], [b'2', b'1', b'4', b'3'])

    def test_leftover_starts_at_the_byte_containing_the_current_bit(self):
        unit = self.load('{a!0:4}', '{a}', more=True)
        self.assertEqual([bytes(chunk) for chunk in b'\x12\x34\x56' | unit], [b'2', b'\x12\x34\x56'])

    def test_bit_field_can_be_peeked(self):
        unit = self.load(':{a!0:4}{b!0:4}', '{a},{b}')
        self.assertEqual(bytes(b'\x21' | unit), b'1,1')

    def test_bit_field_rejects_a_non_integer_format(self):
        unit = self.load('{a!0:B}')
        with self.assertRaises(ValueError):
            b'\x21' | unit | []

    def test_multi_mode_rejects_records_that_consume_nothing(self):
        unit = self.load('{a!0:0}', '{a}', multi=True)
        with self.assertRaises(ValueError):
            b'\x01' | unit | []

    def test_peek_marker_in_a_bare_prefix(self):
        unit = self.load(':B{v:B}', '{v}')
        self.assertEqual(bytes(b'AB' | unit), b'65')

    def test_peek_marker_applies_to_the_next_value_only(self):
        unit = self.load(':Bxx{v:B}', '{v}')
        self.assertEqual(bytes(b'ABCD' | unit), b'67')

    def test_peek_marker_before_a_custom_letter(self):
        unit = self.load(':a{v:a}', '{v}')
        self.assertEqual(bytes(b'foo\0bar\0' | unit), b'foo')

    def test_peek_marker_before_a_named_field(self):
        unit = self.load('H:{v:B}{w:B}', '{v},{w}')
        self.assertEqual(bytes(b'\x00\x01AB' | unit), b'65,65')

    def test_peek_marker_peeks_the_entire_named_field(self):
        unit = self.load(':{v:2s}{w:B}', '{v},{w}')
        self.assertEqual(bytes(b'ABX' | unit), b'AB,65')

    def test_peek_marker_composes_with_a_field_pipeline(self):
        unit = self.load(':{v:a:hex}', '{v}')
        self.assertEqual(bytes(b'4142\0' | unit), b'AB')

    def test_peek_marker_with_a_byte_count(self):
        unit = self.load(':{v:2}{r:}', '{v},{r}')
        self.assertEqual(bytes(b'ABXY' | unit), b'AB,ABXY')
