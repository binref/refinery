from argparse import ArgumentTypeError

from refinery.lib import argformats
from refinery.lib.tools import entropy

from .. import TestBase


class TestArgumentFormats(TestBase):

    def test_hex_number_arg(self):
        self.assertEqual(argformats.number('045FAD'), 0x45FAD)
        self.assertEqual(argformats.number('45FADH'), 0x45FAD)

    def test_accu(self):
        self.assertEqual(
            argformats.multibin('itob[1]:take[:16]:accu:@msvc'),
            bytes.fromhex('26 27 F6 85 97 15 AD 1D D2 94 DD C4 76 19 39 31')
        )

    def test_empty_value_passed_to_itob(self):
        self.assertEqual(argformats.multibin('itob:take[:0]:foo'), b'')

    def test_itob_byte_width(self):
        self.assertEqual(argformats.multibin('itob[1]:eval:(0x00,0x12,0x3412)'), b'\0\x12\x12')

    def test_yara_regular_expression_lowercase(self):
        self.assertEqual(argformats.DelayedRegexpArgument('yara:deefaced')(), BR'\xde\xef\xac\xed')

    def test_no_yara_in_other_handlers(self):
        self.assertEqual(argformats.DelayedArgument('yara:??')(), B'yara:??')

    def test_accumulator(self):
        dm = argformats.DelayedArgument('take[:20]:accu[0x45]:(3*A+3)&0xFF')()
        self.assertEqual(dm, bytes.fromhex('D2796E4DEAC146D582899EDD9AD176653299CE6D'))

    def test_reduce_sum_of_odd_numbers(self):
        for k in range(1, 56):
            result = int(argformats.DelayedArgument(F'base[-R]:be:reduce[S+B]:take[:{k}]:accu[1,0]:A+2')(), 0)
            self.assertEqual(result, k ** 2, F'Failed for {k}.')

    def test_msvc(self):
        pl = self.load_pipeline('emit rep[32]:H:00 [| put s 0xF23CA2 | xor -B2 accu[s]:@msvc ]')
        self.assertEqual(pl(),
            bytes.fromhex('500BC53065647A48899EE4D7F07166A7643AB3EC9F4343A64DF5C45B4CC4D9B2'))

    def test_skip(self):
        data = argformats.DelayedArgument('take[:10]:accu[0,5]:A+1')()
        self.assertEqual(data, bytes(range(5, 15)))

    def test_skip_first_character_of_cyclic_key(self):
        key = argformats.DelayedArgument('take[1:16]:cycle:KITTY')()
        self.assertEqual(key, B'ITTYKITTYKITTYK')

    def test_with_seed(self):
        key = argformats.DelayedBinaryArgument('snip[:2]:snip[1:]', seed=B'FOO')()
        self.assertEqual(key, B'OO')

    def test_itob(self):
        data = argformats.DelayedArgument('itob:take[:4]:accu[0x1337]:A')()
        self.assertEqual(data, bytes.fromhex('3713371337133713'))

    def test_range_can_use_variables(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('xor', 'range:t:t+6') ] # noqa
        self.assertEqual(pipeline(bytearray(10)), B'0123450123')

    def test_take_can_use_variables(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('emit', 'take[:t]:cycle:A') ] # noqa
        self.assertEqual(pipeline(), B'A' * 0x30)

    def test_range_can_be_infinite(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('xor', 'range:t:') ] # noqa
        self.assertEqual(pipeline(bytearray(10)), B'0123456789')

    def test_slices_can_be_variables(self):
        pipeline = self.ldu('put', 'rg', '2:') [ self.ldu('snip', 'rg') ] # noqa
        self.assertEqual(pipeline(b'FOOBAR'), B'OBAR')

    def test_inc(self):
        result = argformats.DelayedArgument('take[:5]:inc[8]:e:0x30')(B'')
        self.assertEqual(result, b'01234')

    def test_le(self):
        with self.assertRaises(ArgumentTypeError):
            argformats.multibin('le:0x5D000111')
        self.assertEqual(
            argformats.multibin('le:e:0x5D000111'),
            b'\x11\x01\x00\x5D')

    def test_slice_objects_with_handlers(self):
        L = self.load_pipeline
        p = L('emit h:01000000 | put a [| snip le:var:a ]')
        self.assertEqual(p(), B'\0')

    def test_slice_objects_with_handlers_eat_regression(self):
        L = self.load_pipeline
        p = L('emit h:01000000 | put a [| snip le:eat:a ]')
        d = next(p)
        self.assertNotIn('a', d.meta)

    def test_variable_arg_regression_1(self):
        L = self.load_pipeline
        p = L('emit Helloooo | put s 4 [| terminate rep[var:s]:o ]')
        d = next(p)
        self.assertEqual(d, B'Hell')

    def test_variable_arg_regression_2(self):
        L = self.load_pipeline
        p = L('emit Helloooo | put s 4 [| terminate -Bs o ]')
        d = next(p)
        self.assertEqual(d, B'Hell')

    def test_eat_removes_variable(self):
        L = self.load_pipeline
        p = L('emit Bar [| put k Foo | cca eat:k | iff k | ccp var:k ]')
        with self.assertRaises(ArgumentTypeError):
            p()

    def test_environment_handler(self):
        import os
        os.environ['test'] = 'foo'
        L = self.load_pipeline
        pl = L('emit env:test')
        self.assertEqual(pl(), b'foo')

    def test_pos_01(self):
        L = self.load_pipeline
        pl = L('emit "Hello World" [| put k pos:or | pf {k} ]')
        self.assertEqual(pl(), b'7')

    def test_accu_zero_feed(self):
        t = argformats.multibin('take[:32]:accu[0xBA2,0,16]:A*0x5A7F+0x3079#(4*A)>>16')
        self.assertEqual(t, bytes.fromhex(
            '0003030100010303030302010301020003000202030202000300020203020200'))

    def test_integer_nonempty(self):
        self.assertEqual(argformats.multibin('le:e:0'), b'\0')
        self.assertEqual(argformats.multibin('be:e:0'), b'\0')

    def test_path_parts(self):
        self.assertEqual(argformats.multibin('pd[:3]:/a/very/deep/path/to/some/file.exe'), b'to/some/file.exe')
        self.assertEqual(argformats.multibin('pd[3:]:/a/very/deep/path/to/some/file.exe'), b'/a/very/deep/path')

    def test_path_name(self):
        self.assertEqual(argformats.multibin('pn:/a/very/deep/path/to/some/file.exe'), b'/a/very/deep/path/to/some/file')
        self.assertEqual(argformats.multibin('pb:pn:/a/very/deep/path/to/some/file.exe'), b'file')
        self.assertEqual(argformats.multibin('pb:/a/very/deep/path/to/some/file.exe'), b'file.exe')

    def test_path_extension(self):
        self.assertEqual(argformats.multibin('px:/a/very/deep/path/to/some/file.exe'), b'exe')

    def test_read_handler(self):
        import os
        import os.path
        import tempfile

        try:
            with tempfile.NamedTemporaryFile(delete=False) as ntf:
                name = os.path.abspath(ntf.name)
                ntf.write(B'binary refinery')
            self.assertEqual(argformats.multibin(F'read[6]:{name}'), b'binary')
            self.assertEqual(argformats.multibin(F'read[0:6]:{name}'), b'binary')
            self.assertEqual(argformats.multibin(F'read[7:]:{name}'), b'refinery')
            self.assertEqual(argformats.multibin(F'read[7:20]:{name}'), b'refinery')
            self.assertEqual(argformats.multibin(F'read[7:3]:{name}'), b'ref')
        finally:
            try:
                os.unlink(name)
            except Exception:
                pass

    def test_prng(self):
        import random

        try:
            randbytes = random.randbytes
        except AttributeError:
            def randbytes(n):
                return bytes(random.randint(0, 0xFF) for _ in range(n))
        finally:
            random.seed(0x1337)

        goal = randbytes(2000)
        test = argformats.multibin('prng[0x1337]:2000')
        self.assertEqual(goal, test)

    def test_rng(self):
        test = argformats.multibin('rng:200000')
        self.assertGreaterEqual(entropy(test), 0.99)

    def test_hex_handler(self):
        self.assertEqual(argformats.multibin('h:DEADBEEF'), bytes.fromhex('DEADBEEF'))

    def test_string_handler(self):
        self.assertEqual(argformats.multibin('s:hello'), b'hello')

    def test_unicode_handler(self):
        self.assertEqual(argformats.multibin('u:A'), b'A\x00')

    def test_cycle_handler(self):
        self.assertEqual(argformats.multibin('take[:8]:cycle:ABC'), b'ABCABCAB')

    def test_url_encode(self):
        self.assertEqual(argformats.multibin('q:hello%20world'), b'hello world')

    def test_base64_handler(self):
        self.assertEqual(argformats.multibin('b64:SGVsbG8='), b'Hello')

    def test_be_int_to_bytes(self):
        self.assertEqual(
            argformats.multibin('be:e:0x5D000111'),
            b'\x5D\x00\x01\x11')

    def test_be_bytes_to_int_via_reduce(self):
        result = argformats.DelayedArgument('be:h:DEADBEEF')()
        self.assertEqual(result, 0xDEADBEEF)

    def test_be_with_size(self):
        self.assertEqual(
            argformats.multibin('be[4]:e:0xFF'),
            b'\x00\x00\x00\xFF')

    def test_q_with_special_chars(self):
        self.assertEqual(
            argformats.multibin('q:foo%2Fbar%3Dbaz'),
            b'foo/bar=baz')

    def test_q_with_plus_not_decoded(self):
        self.assertEqual(
            argformats.multibin('q:foo+bar'),
            b'foo+bar')

    def test_q_with_percent_hex_bytes(self):
        self.assertEqual(
            argformats.multibin('q:%DE%AD%BE%EF'),
            bytes.fromhex('DEADBEEF'))

    def test_btoi_default_size(self):
        result = argformats.DelayedArgument('reduce[S+B]:btoi:h:01000000020000000300000004000000')()
        self.assertEqual(result, 1 + 2 + 3 + 4)

    def test_btoi_explicit_size(self):
        result = argformats.DelayedArgument('reduce[S+B]:btoi[2]:h:0100FF00')()
        self.assertEqual(result, 0x01 + 0xFF)

    def test_eval_tuple_expression(self):
        result = argformats.multibin('itob:eval:(1,2,3)')
        self.assertEqual(result, b'\x01\x02\x03')

    def test_eval_list_expression(self):
        result = argformats.multibin('itob:eval:[4,5,6]')
        self.assertEqual(result, b'\x04\x05\x06')

    def test_eval_arithmetic_expression(self):
        result = argformats.multibin('itob:eval:(0x10+1,0x20+2,0x30+3)')
        self.assertEqual(result, bytes([0x11, 0x22, 0x33]))

    def test_cycle_single_byte(self):
        self.assertEqual(
            argformats.multibin('take[:5]:cycle:X'),
            b'XXXXX')

    def test_cycle_longer_pattern(self):
        self.assertEqual(
            argformats.multibin('take[:10]:cycle:ABCD'),
            b'ABCDABCDAB')

    def test_cycle_with_hex_input(self):
        self.assertEqual(
            argformats.multibin('take[:6]:cycle:h:FF00'),
            bytes.fromhex('FF00FF00FF00'))

    def test_dec_handler(self):
        result = argformats.DelayedArgument('take[:5]:dec[8]:e:0x30')(B'')
        self.assertEqual(result, bytes([0x30, 0x2F, 0x2E, 0x2D, 0x2C]))

    def test_latin1_handler(self):
        self.assertEqual(argformats.multibin('a:caf\xe9'), b'caf\xe9')

    def test_bang_h_hex_encode(self):
        self.assertEqual(
            argformats.multibin('!h:h:DEADBEEF'),
            b'DEADBEEF')
