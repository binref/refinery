#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


class TestRex(TestUnitBase):

    def test_uniqueness(self):
        unit = self.load('.', unique=True)
        data = B'HELLO WORLD'
        self.assertEqual(B'HELO WRD', B''.join(unit.process(data)))

    def test_empty_groups_in_expression(self):
        unit = self.load(r'(?P<foo>x.*?)?bar', '{foo}')
        self.assertSetEqual(B'bar and xbazbar' | unit | {str}, {'', 'xbaz'})

    def test_nested_substitution_expressions(self):
        unit = self.load(
            R'((?:[A-F0-9]{2})+)-((?:[A-F0-9]{2})+)-(\d+)',
            R'{1:hex:aes[H:{2:h:xor[{3}]:h!}]:trim[-r,00]}'
        )
        msg = B'Too much technology, in too little time.'
        aeskey = self.generate_random_buffer(16)
        hex_op = self.ldu('hex')
        xor_op = self.ldu('xor', '0x4D')
        aes_op = self.ldu('aes', '-R', 'H:' + hex_op.reverse(aeskey).upper().decode('UTF8'))
        data = aes_op(msg)
        data = B'%s-%s-%d' % (hex_op.reverse(data), hex_op.reverse(xor_op(aeskey)), 0x4D)
        result = unit(data)
        self.assertEqual(msg, result)

    def test_real_world_01(self):
        data = (
            B'domain/www.google.com\n'
            B'domain/www.yahoo.com\n'
            B'domain/ns1.dns.com'
        )
        unit = self.load('-M', R'^domain\/(.*)$', '{1}')
        self.assertEqual(unit(data), data.replace(B'domain/', B''))

    def test_generic_parameters_01(self):
        unit = self.load('X+', take=2, longest=True)
        data = B'\n'.join(B'X' * k for k in [12, 1, 7, 17, 3])
        self.assertEqual(unit(data), B'\n'.join([
            B'X' * 12,
            B'X' * 17
        ]))

    def test_generic_parameters_02(self):
        unit = self.load('X+', take=2,)
        data = B'\n'.join(B'X' * k for k in [12, 1, 7, 17, 3])
        self.assertEqual(unit(data), B'\n'.join([
            B'X' * 12,
            B'X' * 1
        ]))

    def test_duplicate_by_default(self):
        unit = self.load('.', squeeze=True)
        tests = [
            B'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
            B'C\0R\0N\x0AC\0DE',
            self.generate_random_text(300),
            self.generate_random_buffer(300),
        ]
        for test in tests:
            result = unit(test)
            self.assertEqual(result, test)

    def test_multiple_outputs(self):
        data = b'AXBXC'
        unit = self.load('(.)X(.)X(.)', '1{1}', '2{2}', '3{3}', '[]')
        self.assertEqual(unit(data), B''.join((B'1A', B'2B', B'3C')))

    def test_auto_batch(self):
        pl = L(R'emit Foo12Bar336 | rex (\\w+?)(\\d+) {2} {1} [[| pop k:eval | cfmt {k:x}{} ]]')
        self.assertEqual(pl(), B'cFoo150Bar')

    def test_input_forward(self):
        data = B'HELLO WORLD'
        unit = self.load('L', '{.}')
        test = data | unit | [bytes]
        self.assertEqual(test, [data, data, data])
